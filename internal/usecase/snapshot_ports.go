package usecase

import (
	"context"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// SnapshotStore persists a snapshot to local disk. Implementation:
// infra/locksnap.
type SnapshotStore interface {
	// Save writes a snapshot to its canonical location (typically
	// aegis.lock at projectDir).
	Save(projectDir string, s domain.Snapshot) error
	// Load reads a snapshot from its canonical location, or returns
	// (zero, false, nil) if no snapshot exists yet.
	Load(projectDir string) (domain.Snapshot, bool, error)
	// LoadFile reads a snapshot from an explicit path (used for
	// `aegis snapshot diff <a> <b>`).
	LoadFile(path string) (domain.Snapshot, error)
	// Path returns the canonical save path for a project. Useful for
	// presenter output ("saved to aegis.lock").
	Path(projectDir string) string
}

// LockfileScanner reads the project's package-manager lockfile(s) and
// produces a deduplicated, sorted []Dependency. Implementation:
// infra/locksnap.
type LockfileScanner interface {
	// ScanProject autodetects the lockfile format(s) in projectDir
	// and returns the dependencies it sees. Errors only on malformed
	// input — a project with no lockfile returns ([], nil).
	ScanProject(projectDir string) ([]domain.Dependency, error)
}

// PackageSource is the output of fetching + extracting a package's
// distribution. Files maps relative-path → file body. Manifest is the
// raw package manifest (package.json / pyproject.toml / Cargo.toml /
// gemspec) when present at the root.
type PackageSource struct {
	Files    map[string][]byte
	Manifest []byte
}

// PackageSourceFetcher downloads and extracts a package's source
// distribution from its registry. Per-ecosystem implementations live
// in internal/infra/<eco>pkgsource (e.g. infra/jspkgsource for npm
// registry tarballs).
type PackageSourceFetcher interface {
	Fetch(ctx context.Context, eco domain.Ecosystem, name, version string) (PackageSource, error)
}

// ASTAnalyzer scans extracted package source for risky behaviors and
// declared install hooks, returning a Fingerprint with Analyzed=true.
// Per-ecosystem implementations live in infra/astscan/<lang>scan.
type ASTAnalyzer interface {
	Analyze(ctx context.Context, eco domain.Ecosystem, src PackageSource) (domain.Fingerprint, error)
}

// FingerprintCache stores AST scan results keyed by
// (ecosystem, name, version). Implementation: infra/diskcache.
type FingerprintCache interface {
	Get(eco domain.Ecosystem, name, version string) (domain.Fingerprint, bool)
	Put(eco domain.Ecosystem, name, version string, fp domain.Fingerprint) error
}

// DiffEntryKind names the kind of change in a diff entry.
type DiffEntryKind int

const (
	DiffAdded DiffEntryKind = iota + 1
	DiffRemoved
	DiffUpgraded
)

// DiffEntry pairs one snapshot delta entry with the risk engine's
// assessment. Presenters render entries directly.
type DiffEntry struct {
	Kind    DiffEntryKind
	Old     *domain.Dependency // set for Removed and Upgraded
	New     *domain.Dependency // set for Added and Upgraded
	Risk    domain.RiskAssessment
	Drift   domain.RiskAssessment
	Verdict domain.VerdictKind
}

// Name returns the dep name regardless of entry kind.
func (e DiffEntry) Name() string {
	if e.New != nil {
		return e.New.Name
	}
	if e.Old != nil {
		return e.Old.Name
	}
	return ""
}

// DiffReport is the use case's verdict over a whole diff.
type DiffReport struct {
	Entries    []DiffEntry
	AnyBlocked bool
	AnyPrompt  bool
}

// SnapshotPresenter renders snapshot operations to the user. Note
// that OnSnapshotDiff now takes a DiffReport (not a raw
// SnapshotDelta) — presenters render risk verdicts inline.
type SnapshotPresenter interface {
	OnSnapshotSaved(path string, depCount int)
	OnSnapshotShow(s domain.Snapshot, directOnly bool)
	OnSnapshotDiff(report DiffReport)
	OnSnapshotEnrichProgress(done, total int, name string)
	OnSnapshotEmpty(reason string)
	OnSnapshotInfo(message string)
	OnSnapshotError(err error)
}
