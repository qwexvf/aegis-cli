package usecase

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// Snapshot is the use case for project snapshots: save the current
// lockfile state to disk, show it back, enrich each dep with a
// fingerprint, and diff against either the last saved version or any
// explicit pair of files.
//
// The risk engine (domain.RiskScore / DriftScore / Verdict) runs inside
// Diff: each diff entry carries a Verdict that the presenter renders.
// "Enrich" is a separate operation because AST scanning is expensive
// and the user may want to opt in.
type Snapshot struct {
	store     SnapshotStore
	scanner   LockfileScanner
	presenter SnapshotPresenter

	// Optional. When all three are non-nil, Diff lazily enriches
	// missing fingerprints; Enrich operates explicitly. When any is
	// nil, Diff falls back to delta-only output (no Verdict).
	fetcher  PackageSourceFetcher
	analyzer ASTAnalyzer
	fpCache  FingerprintCache

	aegisVersion string
	now          func() time.Time // injectable for tests
}

// NewSnapshot wires the bare minimum (store + scanner + presenter).
// Risk-engine deps default to nil; use WithRiskEngine to enable.
func NewSnapshot(store SnapshotStore, scanner LockfileScanner, presenter SnapshotPresenter, aegisVersion string) *Snapshot {
	return &Snapshot{
		store:        store,
		scanner:      scanner,
		presenter:    presenter,
		aegisVersion: aegisVersion,
		now:          func() time.Time { return time.Now().UTC() },
	}
}

// WithRiskEngine attaches the optional fetcher / analyzer / cache.
// Returns the receiver for chaining at composition root.
func (s *Snapshot) WithRiskEngine(fetcher PackageSourceFetcher, analyzer ASTAnalyzer, fpCache FingerprintCache) *Snapshot {
	s.fetcher = fetcher
	s.analyzer = analyzer
	s.fpCache = fpCache
	return s
}

// riskEngineEnabled reports whether AST-based scanning is available.
func (s *Snapshot) riskEngineEnabled() bool {
	return s.fetcher != nil && s.analyzer != nil
}

// Save scans the project's lockfile(s) and writes a fresh snapshot to
// the canonical location (aegis.lock). Fingerprints are NOT computed
// here — Save is fast and side-effect-free against the network.
func (s *Snapshot) Save(projectDir string) error {
	deps, err := s.scanner.ScanProject(projectDir)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	if len(deps) == 0 {
		s.presenter.OnSnapshotEmpty("no lockfile found in " + projectDir)
		return nil
	}

	snap := domain.Snapshot{
		SchemaVersion: domain.SnapshotSchemaVersion,
		CreatedAt:     s.now(),
		AegisVersion:  s.aegisVersion,
		Project:       filepath.Base(projectDir),
		Deps:          deps,
	}
	if err := s.store.Save(projectDir, snap); err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	s.presenter.OnSnapshotSaved(s.store.Path(projectDir), len(deps))
	return nil
}

// Show loads the saved snapshot and renders it.
func (s *Snapshot) Show(projectDir string, directOnly bool) error {
	snap, ok, err := s.store.Load(projectDir)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	if !ok {
		s.presenter.OnSnapshotEmpty("no snapshot saved — run 'aegis snapshot save' first")
		return nil
	}
	s.presenter.OnSnapshotShow(snap, directOnly)
	return nil
}

// Enrich runs the AST scanner over every dep in the saved snapshot
// that doesn't yet have an Analyzed fingerprint, and writes the
// updated snapshot back. Idempotent — re-running enriches new entries
// only.
func (s *Snapshot) Enrich(ctx context.Context, projectDir string) error {
	if !s.riskEngineEnabled() {
		s.presenter.OnSnapshotEmpty("risk engine not configured (build with AST scanner)")
		return nil
	}
	snap, ok, err := s.store.Load(projectDir)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	if !ok {
		s.presenter.OnSnapshotEmpty("no snapshot saved — run 'aegis snapshot save' first")
		return nil
	}

	pending := make([]int, 0, len(snap.Deps))
	for i, d := range snap.Deps {
		if d.Fingerprint != nil && d.Fingerprint.Analyzed {
			continue
		}
		pending = append(pending, i)
	}
	if len(pending) == 0 {
		s.presenter.OnSnapshotInfo("all deps already enriched")
		return nil
	}

	for n, i := range pending {
		dep := snap.Deps[i]
		s.presenter.OnSnapshotEnrichProgress(n+1, len(pending), dep.Name)
		fp, err := s.analyzeOne(ctx, dep)
		if err != nil {
			// Best-effort: skip and continue. We log via presenter.
			s.presenter.OnSnapshotInfo(fmt.Sprintf("skip %s@%s: %v", dep.Name, dep.Version, err))
			continue
		}
		fp.Analyzed = true
		snap.Deps[i].Fingerprint = &fp
	}
	if err := s.store.Save(projectDir, snap); err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	s.presenter.OnSnapshotInfo(fmt.Sprintf("enriched %d deps", len(pending)))
	return nil
}

func (s *Snapshot) analyzeOne(ctx context.Context, dep domain.Dependency) (domain.Fingerprint, error) {
	if s.fpCache != nil {
		if fp, ok := s.fpCache.Get(dep.Ecosystem, dep.Name, dep.Version); ok {
			return fp, nil
		}
	}
	src, err := s.fetcher.Fetch(ctx, dep.Ecosystem, dep.Name, dep.Version)
	if err != nil {
		return domain.Fingerprint{}, fmt.Errorf("fetch: %w", err)
	}
	fp, err := s.analyzer.Analyze(ctx, dep.Ecosystem, src)
	if err != nil {
		return domain.Fingerprint{}, fmt.Errorf("analyze: %w", err)
	}
	if s.fpCache != nil {
		_ = s.fpCache.Put(dep.Ecosystem, dep.Name, dep.Version, fp)
	}
	return fp, nil
}

// Diff compares two snapshots and emits a DiffReport with per-entry
// Verdicts. Argument semantics:
//
//	()                — saved snapshot vs live re-scan of lockfile
//	(a.lock, b.lock)  — explicit two-file diff
func (s *Snapshot) Diff(projectDir, fileA, fileB string) error {
	a, b, err := s.loadDiffOperands(projectDir, fileA, fileB)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	delta := domain.DiffSnapshots(a, b)

	report := DiffReport{}
	for _, d := range delta.Added {
		dep := d
		entry := DiffEntry{Kind: DiffAdded, New: &dep}
		entry.Risk = domain.RiskScore(dep.Fingerprint)
		entry.Verdict = domain.Verdict(entry.Risk, entry.Drift)
		updateReportFlags(&report, entry.Verdict)
		report.Entries = append(report.Entries, entry)
	}
	for _, d := range delta.Removed {
		dep := d
		report.Entries = append(report.Entries, DiffEntry{
			Kind: DiffRemoved,
			Old:  &dep,
			// Removal is not a risk — verdict stays VerdictSafe (zero).
		})
	}
	for _, u := range delta.Upgraded {
		oldDep, newDep := u.Old, u.New
		entry := DiffEntry{Kind: DiffUpgraded, Old: &oldDep, New: &newDep}
		entry.Risk = domain.RiskScore(newDep.Fingerprint)
		entry.Drift = domain.DriftScore(oldDep.Fingerprint, newDep.Fingerprint)
		entry.Verdict = domain.Verdict(entry.Risk, entry.Drift)
		updateReportFlags(&report, entry.Verdict)
		report.Entries = append(report.Entries, entry)
	}

	s.presenter.OnSnapshotDiff(report)
	return nil
}

func updateReportFlags(r *DiffReport, v domain.VerdictKind) {
	switch v {
	case domain.VerdictBlock:
		r.AnyBlocked = true
	case domain.VerdictPrompt:
		r.AnyPrompt = true
	}
}

func (s *Snapshot) loadDiffOperands(projectDir, fileA, fileB string) (domain.Snapshot, domain.Snapshot, error) {
	switch {
	case fileA != "" && fileB != "":
		a, err := s.store.LoadFile(fileA)
		if err != nil {
			return domain.Snapshot{}, domain.Snapshot{}, fmt.Errorf("read %s: %w", fileA, err)
		}
		b, err := s.store.LoadFile(fileB)
		if err != nil {
			return domain.Snapshot{}, domain.Snapshot{}, fmt.Errorf("read %s: %w", fileB, err)
		}
		return a, b, nil

	case fileA == "" && fileB == "":
		saved, ok, err := s.store.Load(projectDir)
		if err != nil {
			return domain.Snapshot{}, domain.Snapshot{}, err
		}
		if !ok {
			return domain.Snapshot{}, domain.Snapshot{}, fmt.Errorf("no snapshot saved — run 'aegis snapshot save' first")
		}
		liveDeps, err := s.scanner.ScanProject(projectDir)
		if err != nil {
			return domain.Snapshot{}, domain.Snapshot{}, err
		}
		// Carry forward fingerprints from the saved snapshot for deps
		// whose version is unchanged. This avoids needing to re-enrich
		// the live scan: we want to know fingerprint-old vs
		// fingerprint-new, not "live has nothing".
		fpByVerKey := map[string]*domain.Fingerprint{}
		for _, d := range saved.Deps {
			if d.Fingerprint != nil && d.Fingerprint.Analyzed {
				fpByVerKey[d.VersionedKey()] = d.Fingerprint
			}
		}
		for i, d := range liveDeps {
			if fp, ok := fpByVerKey[d.VersionedKey()]; ok {
				liveDeps[i].Fingerprint = fp
			}
		}
		live := domain.Snapshot{
			SchemaVersion: domain.SnapshotSchemaVersion,
			CreatedAt:     s.now(),
			AegisVersion:  s.aegisVersion,
			Project:       saved.Project,
			Deps:          liveDeps,
		}
		return saved, live, nil

	default:
		return domain.Snapshot{}, domain.Snapshot{}, fmt.Errorf("diff requires either zero arguments (saved vs live) or two file paths")
	}
}

// Verify checks the saved snapshot is loadable and structurally valid.
func (s *Snapshot) Verify(projectDir string) error {
	snap, ok, err := s.store.Load(projectDir)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	if !ok {
		s.presenter.OnSnapshotEmpty("no snapshot to verify")
		return nil
	}
	if snap.SchemaVersion != domain.SnapshotSchemaVersion {
		s.presenter.OnSnapshotInfo(fmt.Sprintf(
			"schema mismatch: file=%d, current=%d (re-run 'aegis snapshot save')",
			snap.SchemaVersion, domain.SnapshotSchemaVersion))
		return nil
	}
	s.presenter.OnSnapshotInfo(fmt.Sprintf(
		"snapshot OK: %d deps, schema v%d, saved %s",
		len(snap.Deps), snap.SchemaVersion, snap.CreatedAt.Format(time.RFC3339)))
	return nil
}
