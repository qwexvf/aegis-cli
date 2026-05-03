package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// enrichWorkers is the cap on parallel AST scans during Enrich. AST
// parsing is CPU-bound; over-saturating with > NumCPU workers fights
// the GC. The cap also keeps memory predictable: each worker holds
// one in-flight tarball + parse buffer.
const enrichWorkers = 8

// submitWorkers is the cap on parallel /reports POSTs during Submit.
// Lower than enrichWorkers because submit is network-bound and we
// want to be polite to the API: a CI matrix of 50 jobs each making
// dozens of submits already produces fan-in we don't want to amplify.
const submitWorkers = 4

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

	// Optional submit pipeline. All three must be non-nil for Submit
	// to work. evidenceAnalyzer is typically the same concrete
	// dispatcher as analyzer, exposed under the EvidenceAnalyzer port.
	evidenceAnalyzer EvidenceAnalyzer
	submitter        ReportSubmitter
	reporter         ReporterIdentity

	// Optional provenance resolver — best-effort lookup of the
	// registry-reported publish time. Submit attaches an empty string
	// when nil or when the lookup fails.
	publishedAt PublishedAtResolver

	// Optional vulnerability lookup. When set, Enrich runs a single
	// batch query against the public OSV.dev (or equivalent) feed
	// after the AST workers drain, and writes the resulting
	// advisories onto each Dependency. nil disables — the snapshot
	// then carries no Advisories and CI won't fail on known
	// vulnerabilities, only on local AST findings.
	vulnLookup VulnLookup

	// allowlist is applied post-RiskScore/DriftScore in Diff so
	// known-benign capabilities (lodash dynamic-eval, build tools'
	// shell-spawn) don't manufacture false-positive verdicts.
	allowlist domain.AllowSet

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

// WithSubmitter attaches the cloud submit pipeline. All three deps
// are required; if any is nil, Submit reports the misconfiguration
// and returns nil error.
func (s *Snapshot) WithSubmitter(analyzer EvidenceAnalyzer, submitter ReportSubmitter, reporter ReporterIdentity) *Snapshot {
	s.evidenceAnalyzer = analyzer
	s.submitter = submitter
	s.reporter = reporter
	return s
}

// WithPublishedAtResolver attaches an optional registry lookup for the
// per-version publish time. Submit calls this once per dep before
// posting; failures are non-fatal (the report is still sent with
// PackagePublishedAt="").
func (s *Snapshot) WithPublishedAtResolver(r PublishedAtResolver) *Snapshot {
	s.publishedAt = r
	return s
}

// WithVulnLookup attaches a vulnerability database adapter (OSV.dev
// today). When set, every `aegis snapshot enrich` run batches the
// dep list against the feed and stamps any matching advisories onto
// the on-disk snapshot. Local AST findings still run regardless;
// vuln lookup is additive.
//
// nil is the safe no-op: no advisories are populated, CI scoring
// falls back to AST-only behaviour. Useful when running offline.
func (s *Snapshot) WithVulnLookup(v VulnLookup) *Snapshot {
	s.vulnLookup = v
	return s
}

// WithAllowlist attaches a precomputed AllowSet. Use cases without
// allowlist behave as if an empty AllowSet were attached.
func (s *Snapshot) WithAllowlist(set domain.AllowSet) *Snapshot {
	s.allowlist = set
	return s
}

// riskEngineEnabled reports whether AST-based scanning is available.
func (s *Snapshot) riskEngineEnabled() bool {
	return s.fetcher != nil && s.analyzer != nil
}

// RiskEngineEnabled is the public probe used by adjacent use cases
// (CI) that want to fail fast when AST scanning was requested but
// the binary was built with `nojsscan`.
func (s *Snapshot) RiskEngineEnabled() bool { return s.riskEngineEnabled() }

// Save scans the project's lockfile(s) and writes a fresh snapshot to
// the canonical location (aegis.lock). Fingerprints are NOT computed
// here — Save is fast and side-effect-free against the network.
//
// When an existing aegis.lock is present at the destination, an info
// line is emitted so the user knows hand-edits (rare but possible)
// will be replaced. We don't refuse — `save` is the explicit "rewrite
// from lockfile" verb.
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

	if _, existed, _ := s.store.Load(projectDir); existed {
		s.presenter.OnSnapshotInfo("overwriting existing " + s.store.Path(projectDir))
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
//
// Parallelism: up to enrichWorkers (or NumCPU, whichever is smaller)
// AST scans run concurrently. Progress messages stream in completion
// order, not input order — the user sees finished work as it arrives.
// Cancellation: ctx.Done is honored both inside the per-dep workers
// and between finished tasks; partial progress is persisted to disk
// before returning.
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

	s.presenter.OnEnrichBegin(len(pending))
	processed, succeeded := s.runEnrichWorkers(ctx, snap.Deps, pending)
	s.presenter.OnEnrichEnd()

	// After the AST workers drain, batch-query the public
	// vulnerability feed (OSV.dev) for every dep and stamp the
	// matching advisories back onto the snapshot. One round-trip
	// per Enrich call, no per-dep network cost. Best-effort: a
	// failed lookup logs an info line but doesn't fail Enrich —
	// the AST findings already on disk are the floor.
	s.lookupAdvisories(ctx, snap.Deps)

	if err := s.store.Save(projectDir, snap); err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		s.presenter.OnSnapshotInfo(fmt.Sprintf(
			"interrupted after %d/%d processed (%d enriched, saved partial)",
			processed, len(pending), succeeded))
		return ctxErr
	}
	if failed := processed - succeeded; failed > 0 {
		s.presenter.OnSnapshotInfo(fmt.Sprintf("enriched %d deps (%d failed)", succeeded, failed))
	} else {
		s.presenter.OnSnapshotInfo(fmt.Sprintf("enriched %d deps", succeeded))
	}
	return nil
}

// EnrichDeps runs the AST scanner over deps in place, using the same
// worker pool + presenter lifecycle as Snapshot.Enrich but without
// the load-from/save-to-disk steps. Used by adjacent use cases (CI
// --baseline) that hold an in-memory snapshot they don't want to
// persist.
//
// Caller is responsible for calling RiskEngineEnabled() first.
// Returns (processed, succeeded) per the same contract as the
// internal worker pool.
func (s *Snapshot) EnrichDeps(ctx context.Context, deps []domain.Dependency) (processed, succeeded int) {
	pending := make([]int, 0, len(deps))
	for i, d := range deps {
		if d.Fingerprint != nil && d.Fingerprint.Analyzed {
			continue
		}
		pending = append(pending, i)
	}
	if len(pending) == 0 {
		return 0, 0
	}
	s.presenter.OnEnrichBegin(len(pending))
	defer s.presenter.OnEnrichEnd()
	return s.runEnrichWorkers(ctx, deps, pending)
}

// runEnrichWorkers fans pending indices out to a worker pool, writes
// fingerprints back into deps[i] as results arrive, and returns
// (processed, succeeded). processed counts every result drained from
// the worker channel (including per-dep errors); succeeded counts only
// the results that produced an Analyzed fingerprint. Caller persists
// deps after we return so partial progress survives cancellation.
func (s *Snapshot) runEnrichWorkers(ctx context.Context, deps []domain.Dependency, pending []int) (processed, succeeded int) {
	workerCount := min(enrichWorkers, runtime.NumCPU(), len(pending))

	tasks := make(chan int, len(pending))
	for _, i := range pending {
		tasks <- i
	}
	close(tasks)

	type result struct {
		index int
		fp    domain.Fingerprint
		err   error
		dep   domain.Dependency
	}
	results := make(chan result, len(pending))

	var wg sync.WaitGroup
	for w := range workerCount {
		slot := w
		wg.Go(func() {
			for i := range tasks {
				if ctx.Err() != nil {
					return
				}
				dep := deps[i]
				fp, fromCache, err := s.analyzeOneSlot(ctx, dep, slot)
				if !fromCache {
					s.presenter.OnEnrichSlotDone(slot,
						string(dep.Ecosystem), dep.Name, dep.Version, err == nil)
				}
				results <- result{index: i, fp: fp, err: err, dep: dep}
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	total := len(pending)
	for r := range results {
		processed++
		s.presenter.OnSnapshotEnrichProgress(processed, total, r.dep.Name)
		if r.err != nil {
			s.presenter.OnSnapshotInfo(fmt.Sprintf("skip %s@%s: %v", r.dep.Name, r.dep.Version, r.err))
			continue
		}
		r.fp.Analyzed = true
		deps[r.index].Fingerprint = &r.fp
		succeeded++
	}
	return processed, succeeded
}

// analyzeOneSlot is the slot-aware variant used by Enrich workers. It
// emits SlotStart/Stage events around fetch + analyze. Cache hits skip
// slot events entirely (the live UI doesn't flash for instant returns)
// and signal that to the caller via fromCache=true so it can also skip
// the matching SlotDone.
func (s *Snapshot) analyzeOneSlot(ctx context.Context, dep domain.Dependency, slot int) (fp domain.Fingerprint, fromCache bool, err error) {
	if s.fpCache != nil {
		if cached, ok := s.fpCache.Get(dep.Ecosystem, dep.Name, dep.Version); ok {
			return cached, true, nil
		}
	}
	// Skip the AST scan entirely when no language scanner is
	// registered for this ecosystem (Python/Go/Rust/Ruby in
	// v0.3.0 — only the JS scanner ships in-tree). Mark the dep as
	// "analyzed" so re-runs don't keep retrying; OSV vulnerability
	// lookup happens in a separate pass after all workers drain
	// and applies to every ecosystem regardless of scanner support.
	if !s.analyzer.HasScanner(dep.Ecosystem) {
		fp := domain.Fingerprint{Analyzed: true}
		if s.fpCache != nil {
			_ = s.fpCache.Put(dep.Ecosystem, dep.Name, dep.Version, fp)
		}
		return fp, true, nil // fromCache=true suppresses SlotDone (cleaner UI for non-AST-scannable deps)
	}
	s.presenter.OnEnrichSlotStart(slot, string(dep.Ecosystem), dep.Name, dep.Version)
	s.presenter.OnEnrichSlotStage(slot, EnrichStageFetch)
	src, err := s.fetcher.Fetch(ctx, dep.Ecosystem, dep.Name, dep.Version)
	if err != nil {
		return domain.Fingerprint{}, false, fmt.Errorf("fetch: %w", err)
	}
	s.presenter.OnEnrichSlotStage(slot, EnrichStageScan)
	fp, err = s.analyzer.Analyze(ctx, dep.Ecosystem, src)
	if err != nil {
		return domain.Fingerprint{}, false, fmt.Errorf("analyze: %w", err)
	}
	if s.fpCache != nil {
		_ = s.fpCache.Put(dep.Ecosystem, dep.Name, dep.Version, fp)
	}
	return fp, false, nil
}

// Diff compares two snapshots and emits a DiffReport via the
// presenter. Argument semantics:
//
//	()                — saved snapshot vs live re-scan of lockfile
//	(a.lock, b.lock)  — explicit two-file diff
//
// Sister method BuildDiffReport returns the report without firing
// the presenter — used by adjacent use cases (CI --baseline) that
// render their own format.
func (s *Snapshot) Diff(projectDir, fileA, fileB string) error {
	report, err := s.BuildDiffReport(projectDir, fileA, fileB)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	s.presenter.OnSnapshotDiff(report)
	return nil
}

// BuildDiffReport produces the DiffReport without touching the
// presenter. Same operand semantics as Diff. Errors are returned
// raw — caller decides whether to surface them via its own
// presenter or wrap into a richer error.
func (s *Snapshot) BuildDiffReport(projectDir, fileA, fileB string) (DiffReport, error) {
	a, b, err := s.loadDiffOperands(projectDir, fileA, fileB)
	if err != nil {
		return DiffReport{}, err
	}
	return s.buildReportFromSnapshots(a, b), nil
}

// BuildDiffReportFromSnapshots is the in-memory variant: caller
// supplies both operands directly. Used by CI --baseline which
// constructs the live snapshot in memory rather than from disk.
func (s *Snapshot) BuildDiffReportFromSnapshots(baseline, live domain.Snapshot) DiffReport {
	return s.buildReportFromSnapshots(baseline, live)
}

// buildReportFromSnapshots is the shared core. Pure: same inputs →
// same output, no I/O, no presenter side-effects.
func (s *Snapshot) buildReportFromSnapshots(a, b domain.Snapshot) DiffReport {
	delta := domain.DiffSnapshots(a, b)

	report := DiffReport{}
	for _, d := range delta.Added {
		dep := d
		entry := DiffEntry{Kind: DiffAdded, New: &dep}
		entry.Risk = domain.RiskScore(dep.Fingerprint).
			ApplyAllowlist(dep.Ecosystem, dep.Name, dep.Version, s.allowlist)
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
		entry.Risk = domain.RiskScore(newDep.Fingerprint).
			ApplyAllowlist(newDep.Ecosystem, newDep.Name, newDep.Version, s.allowlist)
		entry.Drift = domain.DriftScore(oldDep.Fingerprint, newDep.Fingerprint).
			ApplyAllowlist(newDep.Ecosystem, newDep.Name, newDep.Version, s.allowlist)
		entry.Verdict = domain.Verdict(entry.Risk, entry.Drift)
		updateReportFlags(&report, entry.Verdict)
		report.Entries = append(report.Entries, entry)
	}
	return report
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

// Submit posts every analyzed dep in the saved snapshot to the Aegis
// API as a community report. Each dep is fetched, re-analyzed with
// evidence collection enabled, and POSTed as one PackageReportRequest.
//
// Idempotent in the API's sense: re-submitting the same (reporter,
// package, version) updates the existing row instead of creating
// duplicates. Re-fetching is unavoidable because evidence wasn't
// recorded during enrich (the hot path stays cheap).
func (s *Snapshot) Submit(ctx context.Context, projectDir string) error {
	if s.fetcher == nil || s.evidenceAnalyzer == nil || s.submitter == nil || s.reporter == nil {
		s.presenter.OnSnapshotEmpty("submit pipeline not configured")
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
	reporterID, err := s.reporter.ID()
	if err != nil {
		s.presenter.OnSnapshotError(fmt.Errorf("reporter id: %w", err))
		return err
	}

	// Only submit deps that have been analyzed — the user expects a
	// risk-engine-backed report, not a placeholder. Pre-filter so
	// progress counters reflect work actually done.
	pending := make([]int, 0, len(snap.Deps))
	for i, d := range snap.Deps {
		if d.Fingerprint == nil || !d.Fingerprint.Analyzed {
			continue
		}
		pending = append(pending, i)
	}
	if len(pending) == 0 {
		s.presenter.OnSnapshotEmpty("nothing to submit (run 'aegis snapshot enrich' first)")
		return nil
	}

	s.runSubmitWorkers(ctx, snap.Deps, pending, reporterID)
	return ctx.Err()
}

// runSubmitWorkers fans submit work out to submitWorkers goroutines.
// Each task fetches, analyzes-with-evidence, and POSTs one report.
// Errors are best-effort and surfaced through the presenter so a
// failing dep doesn't abort the batch.
func (s *Snapshot) runSubmitWorkers(ctx context.Context, deps []domain.Dependency, pending []int, reporterID string) {
	workerCount := min(submitWorkers, len(pending))

	tasks := make(chan int, len(pending))
	for _, i := range pending {
		tasks <- i
	}
	close(tasks)

	type result struct {
		dep    domain.Dependency
		ack    PackageReportAck
		err    error
		errMsg string
	}
	results := make(chan result, len(pending))

	var wg sync.WaitGroup
	for range workerCount {
		wg.Go(func() {
			for i := range tasks {
				if ctx.Err() != nil {
					return
				}
				dep := deps[i]
				ack, errMsg, err := s.submitOne(ctx, dep, reporterID)
				results <- result{dep: dep, ack: ack, errMsg: errMsg, err: err}
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	completed := 0
	total := len(pending)
	for r := range results {
		completed++
		s.presenter.OnSnapshotEnrichProgress(completed, total, r.dep.Name)
		if r.err != nil {
			s.presenter.OnSnapshotInfo(fmt.Sprintf("skip %s@%s: %s: %v",
				r.dep.Name, r.dep.Version, r.errMsg, r.err))
			continue
		}
		s.presenter.OnSnapshotInfo(fmt.Sprintf("submitted %s@%s (reporters=%d) → %s",
			r.dep.Name, r.dep.Version, r.ack.ReporterCount, r.ack.URL))
	}
}

// submitOne handles the per-dep pipeline: fetch tarball, analyze with
// evidence, attach provenance, POST. The errMsg return distinguishes
// which stage failed so the presenter can show "fetch" vs "analyze"
// vs "submit" — useful for debugging flaky tarballs vs flaky API.
func (s *Snapshot) submitOne(ctx context.Context, dep domain.Dependency, reporterID string) (PackageReportAck, string, error) {
	src, err := s.fetcher.Fetch(ctx, dep.Ecosystem, dep.Name, dep.Version)
	if err != nil {
		return PackageReportAck{}, "fetch", err
	}
	fp, evidence, err := s.evidenceAnalyzer.AnalyzeWithEvidence(ctx, dep.Ecosystem, src)
	if err != nil {
		return PackageReportAck{}, "analyze", err
	}

	risk := domain.RiskScore(&fp).
		ApplyAllowlist(dep.Ecosystem, dep.Name, dep.Version, s.allowlist)

	// Provenance: tarball hash from the fetcher's PackageSource (if
	// it filled the field), maintainer emails parsed from the
	// manifest, and a best-effort registry publish-time lookup. All
	// three are non-fatal: an empty value flows through to the API.
	emails := parseMaintainerEmails(src.Manifest)
	publishedAt := ""
	if s.publishedAt != nil {
		if t, err := s.publishedAt.PublishedAt(ctx, dep.Ecosystem, dep.Name, dep.Version); err == nil {
			publishedAt = t
		}
	}

	req := buildReportRequest(reporterID, s.aegisVersion, dep, fp, evidence, risk,
		src.TarballSha256, emails, publishedAt)
	ack, err := s.submitter.SubmitReport(ctx, req)
	if err != nil {
		return PackageReportAck{}, "submit", err
	}
	return ack, "", nil
}

func buildReportRequest(
	reporterID, aegisVersion string,
	dep domain.Dependency,
	fp domain.Fingerprint,
	evidence []domain.Evidence,
	risk domain.RiskAssessment,
	tarballSha256 string,
	maintainerEmails []string,
	publishedAt string,
) PackageReportRequest {
	caps := make([]string, 0, len(fp.Capabilities))
	for _, c := range fp.Capabilities {
		caps = append(caps, c.String())
	}
	hooks := make([]ReportHook, 0, len(fp.Hooks))
	for _, h := range fp.Hooks {
		hooks = append(hooks, ReportHook{
			Phase:  h.Phase.String(),
			Source: h.Source,
			Sha256: h.Sha256,
		})
	}
	ev := make([]ReportEvidence, 0, len(evidence))
	for _, e := range evidence {
		ev = append(ev, ReportEvidence{
			Capability: e.Capability.String(),
			File:       e.File,
			Line:       e.Line,
			Snippet:    e.Snippet,
		})
	}
	flags := make([]ReportRiskFlag, 0, len(risk.Flags))
	for _, f := range risk.Flags {
		if f.Suppressed {
			continue
		}
		flags = append(flags, ReportRiskFlag{
			Code: f.Code, Detail: f.Detail, Weight: f.Weight,
		})
	}
	if maintainerEmails == nil {
		maintainerEmails = []string{}
	}
	return PackageReportRequest{
		ReporterID:         reporterID,
		AegisVersion:       aegisVersion,
		Ecosystem:          string(dep.Ecosystem),
		Name:               dep.Name,
		Version:            dep.Version,
		Capabilities:       caps,
		EnvReads:           fp.EnvReads,
		Hooks:              hooks,
		Evidence:           ev,
		RiskScore:          risk.Score,
		RiskFlags:          flags,
		TarballSha256:      tarballSha256,
		MaintainerEmails:   maintainerEmails,
		PackagePublishedAt: publishedAt,
	}
}

// parseMaintainerEmails pulls every email visible in package.json's
// `author`, `maintainers`, and `contributors` fields. Each may be a
// string ("Name <email@host>") or an object ({name, email}); the npm
// spec allows either shape per field. Returns deduplicated, sorted
// addresses; returns an empty (non-nil) slice when the manifest is
// empty or unparseable.
func parseMaintainerEmails(manifest []byte) []string {
	if len(manifest) == 0 {
		return []string{}
	}
	// Use json.RawMessage so we can branch by JSON shape per-field
	// without committing to a struct that could fail the whole decode.
	var raw struct {
		Author       json.RawMessage `json:"author"`
		Maintainers  json.RawMessage `json:"maintainers"`
		Contributors json.RawMessage `json:"contributors"`
	}
	if err := json.Unmarshal(manifest, &raw); err != nil {
		return []string{}
	}
	seen := map[string]struct{}{}
	collectPersonField(raw.Author, seen)
	collectPersonField(raw.Maintainers, seen)
	collectPersonField(raw.Contributors, seen)
	out := make([]string, 0, len(seen))
	for e := range seen {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// collectPersonField handles all three legal shapes for a person-or-
// list-of-persons field: a single string, a single object, or an array
// of either.
func collectPersonField(raw json.RawMessage, seen map[string]struct{}) {
	if len(raw) == 0 {
		return
	}
	// Try array first.
	var asArray []json.RawMessage
	if err := json.Unmarshal(raw, &asArray); err == nil {
		for _, item := range asArray {
			collectOne(item, seen)
		}
		return
	}
	collectOne(raw, seen)
}

// collectOne extracts an email from one person value (string or object).
func collectOne(raw json.RawMessage, seen map[string]struct{}) {
	if len(raw) == 0 {
		return
	}
	// Object form: {name, email, url}
	var asObj struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &asObj); err == nil && asObj.Email != "" {
		add := strings.TrimSpace(asObj.Email)
		if add != "" {
			seen[add] = struct{}{}
		}
		return
	}
	// String form: "Name <email@host> (url)"
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil {
		if email := extractEmailFromPersonString(asStr); email != "" {
			seen[email] = struct{}{}
		}
	}
}

// extractEmailFromPersonString returns the email from a "Name <email>"
// person string, or "" if no email is present.
func extractEmailFromPersonString(s string) string {
	open := strings.Index(s, "<")
	if open < 0 {
		return ""
	}
	close := strings.Index(s[open+1:], ">")
	if close < 0 {
		return ""
	}
	return strings.TrimSpace(s[open+1 : open+1+close])
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

// lookupAdvisories does the post-AST vulnerability batch query and
// stamps the result onto each Dependency. No-op when the lookup
// adapter wasn't configured (offline mode); failures degrade to
// "no advisories" + an info line so Enrich never fails on a flaky
// network. Idempotent on its own state — re-running rewrites the
// Advisories slices in place.
func (s *Snapshot) lookupAdvisories(ctx context.Context, deps []domain.Dependency) {
	if s.vulnLookup == nil {
		return
	}
	if len(deps) == 0 {
		return
	}
	queries := make([]domain.AdvisoryQuery, 0, len(deps))
	indexByKey := make(map[string]int, len(deps))
	for i, d := range deps {
		q := domain.AdvisoryQuery{Ecosystem: d.Ecosystem, Name: d.Name, Version: d.Version}
		queries = append(queries, q)
		indexByKey[q.Key()] = i
	}

	results, err := s.vulnLookup.Lookup(ctx, queries)
	if err != nil {
		s.presenter.OnSnapshotInfo(fmt.Sprintf(
			"vulnerability lookup failed: %v (snapshot saved without advisories)", err))
		return
	}

	withAdvs := 0
	totalAdvs := 0
	for key, advs := range results {
		i, ok := indexByKey[key]
		if !ok {
			continue
		}
		// Empty slice (not nil) marks "looked up, none found" so
		// next Enrich doesn't re-query unchanged deps.
		if advs == nil {
			advs = []domain.Advisory{}
		}
		deps[i].Advisories = advs
		if len(advs) > 0 {
			withAdvs++
			totalAdvs += len(advs)
		}
	}
	if withAdvs > 0 {
		s.presenter.OnSnapshotInfo(fmt.Sprintf(
			"%d advisories across %d packages", totalAdvs, withAdvs))
	}
}
