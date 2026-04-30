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
//
// TarballSha256 is the hex sha256 of the raw distribution tarball the
// fetcher downloaded (npm: the .tgz). Empty string when the source
// didn't come from a tarball (cache reload, alternative ecosystems
// without tarballs). The submit pipeline reads this to send the
// provenance hash with each report so consumers can verify the
// reporter actually saw the bytes they claim.
type PackageSource struct {
	Files         map[string][]byte
	Manifest      []byte
	TarballSha256 string
}

// PackageSourceFetcher downloads and extracts a package's source
// distribution from its registry. Per-ecosystem implementations live
// in internal/infra/<eco>pkgsource (e.g. infra/jspkgsource for npm
// registry tarballs).
//
// Concurrency: Snapshot.Enrich/Submit may call Fetch from up to
// enrichWorkers goroutines simultaneously; implementations MUST be
// safe for concurrent use. The shared HTTP transport in infra/httpx
// already is.
type PackageSourceFetcher interface {
	Fetch(ctx context.Context, eco domain.Ecosystem, name, version string) (PackageSource, error)
}

// ASTAnalyzer scans extracted package source for risky behaviors and
// declared install hooks, returning a Fingerprint with Analyzed=true.
// Per-ecosystem implementations live in infra/astscan/<lang>scan.
//
// Concurrency: must be safe for concurrent calls — the worker pool
// invokes Analyze from N goroutines on independent PackageSource
// values. Tree-sitter parsers are not concurrent-safe per-instance,
// so implementations either pool parsers or create one per call.
type ASTAnalyzer interface {
	Analyze(ctx context.Context, eco domain.Ecosystem, src PackageSource) (domain.Fingerprint, error)
}

// EvidenceAnalyzer runs the same scan as ASTAnalyzer but additionally
// returns flat per-capture evidence rows. Used by the submit pipeline;
// the API builds graphs from these. Kept separate from ASTAnalyzer so
// existing fakes / risk-engine paths don't need to grow.
//
// Concurrency: same contract as ASTAnalyzer.
type EvidenceAnalyzer interface {
	AnalyzeWithEvidence(ctx context.Context, eco domain.Ecosystem, src PackageSource) (domain.Fingerprint, []domain.Evidence, error)
}

// ReportSubmitter posts a per-package report to the Aegis API. The
// adapter lives in infra/aegisapi.
//
// Concurrency: must be safe for concurrent calls. Submit fans out via
// submitWorkers; the API handles dedup server-side keyed by
// (reporter_id, ecosystem, name, version) so retries and parallel
// posts of the same dep are idempotent.
type ReportSubmitter interface {
	SubmitReport(ctx context.Context, r PackageReportRequest) (PackageReportAck, error)
}

// PackageReportRequest is the wire payload sent to the API. Field tags
// match the API's expected JSON shape; the use case constructs this
// from a Snapshot dep + scanner output.
//
// Provenance fields (TarballSha256, MaintainerEmails, PackagePublishedAt)
// always serialize, even when empty: the API persists "no provenance"
// as empty/zero values rather than absent fields, and consumers expect
// the keys to be present so they can render "unknown" cleanly.
type PackageReportRequest struct {
	ReporterID         string           `json:"reporter_id"`
	AegisVersion       string           `json:"aegis_version"`
	Ecosystem          string           `json:"ecosystem"`
	Name               string           `json:"name"`
	Version            string           `json:"version"`
	ManifestSha        string           `json:"manifest_sha256,omitempty"`
	Capabilities       []string         `json:"capabilities"`
	EnvReads           []string         `json:"env_reads,omitempty"`
	Hooks              []ReportHook     `json:"hooks,omitempty"`
	Evidence           []ReportEvidence `json:"evidence,omitempty"`
	RiskScore          int              `json:"risk_score"`
	RiskFlags          []ReportRiskFlag `json:"risk_flags,omitempty"`
	TarballSha256      string           `json:"tarball_sha256"`
	MaintainerEmails   []string         `json:"maintainer_emails"`
	PackagePublishedAt string           `json:"package_published_at"`
}

// ReportHook is the wire shape for one declared install hook.
type ReportHook struct {
	Phase  string `json:"phase"`
	Source string `json:"source"`
	Sha256 string `json:"sha256,omitempty"`
}

// ReportEvidence is the wire shape for one capture.
type ReportEvidence struct {
	Capability string `json:"capability"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Snippet    string `json:"snippet,omitempty"`
}

// ReportRiskFlag is the wire shape for one risk-engine flag.
type ReportRiskFlag struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Weight int    `json:"weight"`
}

// PackageReportAck is the API's response to a submit. URL points at
// the web view of the aggregated report.
type PackageReportAck struct {
	ReportID       string `json:"report_id"`
	URL            string `json:"url"`
	ReporterCount  int    `json:"reporter_count"`
}

// ReporterIdentity provides a stable per-machine reporter ID. Today
// it's a UUID stored under ~/.aegis/reporter.id; future versions will
// upgrade to ed25519 keys for signed reports.
type ReporterIdentity interface {
	ID() (string, error)
}

// PublishedAtResolver resolves the upstream registry's "publish time"
// for a (ecosystem, name, version). For npm this is the `time[version]`
// value on the packument. Adapter: infra/npmregistry. Returns an empty
// string when the registry doesn't expose the field — the submit
// pipeline treats that as "unknown" and continues.
type PublishedAtResolver interface {
	PublishedAt(ctx context.Context, eco domain.Ecosystem, name, version string) (string, error)
}

// FingerprintCache stores AST scan results keyed by
// (ecosystem, name, version). Implementation: infra/diskcache.
//
// Concurrency: must be safe for concurrent Get/Put calls. The disk
// adapter writes one file per key with atomicwrite, so different keys
// don't contend; same-key writes are last-write-wins and harmless
// (analyzers are deterministic — both writes produce the same bytes).
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
