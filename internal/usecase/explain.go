package usecase

import (
	"context"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Explain answers "why is this dep flagged?" for a single package.
// It looks the package up in the saved snapshot first (zero network);
// if not present (or not yet analyzed), falls back to a fresh fetch
// + AST scan. Output goes to ExplainPresenter, which renders each
// capability with its human description, the per-flag breakdown, and
// (if available) per-capture evidence.
//
// This is the "I trust the verdict but I don't understand it" command.
// Designed for non-security people on the team.
type Explain struct {
	store     SnapshotStore
	analyze   *Analyze // delegate when the snapshot has nothing to show
	presenter ExplainPresenter
	allowlist domain.AllowSet
}

// NewExplain wires the use case. Analyze is required so we have a
// fallback path when the saved snapshot doesn't contain the dep yet.
func NewExplain(store SnapshotStore, analyze *Analyze, presenter ExplainPresenter) *Explain {
	return &Explain{store: store, analyze: analyze, presenter: presenter}
}

// WithAllowlist attaches an AllowSet so suppressed flags display
// their suppression reason. Empty set behaves as no suppression.
func (e *Explain) WithAllowlist(set domain.AllowSet) *Explain {
	e.allowlist = set
	return e
}

// ExplainRequest is the input.
type ExplainRequest struct {
	ProjectDir string
	Ecosystem  domain.Ecosystem
	Name       string
	Version    string
	// AllowFreshScan controls whether we fall back to a fetch + AST
	// scan when the snapshot doesn't have an analyzed fingerprint.
	// True for `aegis explain` itself; false would be useful for an
	// offline mode (cache-only).
	AllowFreshScan bool
}

// ExplainResult is what Run returns and the presenter renders.
type ExplainResult struct {
	Source        string // "snapshot" | "fresh-scan"
	Ecosystem     domain.Ecosystem
	Name          string
	Version       string
	Direct        bool // from the snapshot (false when fresh)
	Fingerprint   domain.Fingerprint
	Evidence      []domain.Evidence
	Risk          domain.RiskAssessment
	Verdict       domain.VerdictKind
	TarballSha256 string
	SourceBytes   int
}

// ExplainPresenter renders the explanation.
type ExplainPresenter interface {
	OnExplainResult(r ExplainResult)
	OnExplainError(eco domain.Ecosystem, name, version string, err error)
}

// Run finds the dep (snapshot first, fresh scan fallback) and emits
// the structured ExplainResult. Returns the result so the CLI can
// derive an exit code from the verdict.
func (e *Explain) Run(ctx context.Context, req ExplainRequest) (ExplainResult, error) {
	if req.Name == "" || req.Version == "" {
		err := fmt.Errorf("explain: name and version required")
		e.presenter.OnExplainError(req.Ecosystem, req.Name, req.Version, err)
		return ExplainResult{}, err
	}

	dep, found := e.findInSnapshot(req)
	hasAnalyzedFingerprint := found && dep.Fingerprint != nil && dep.Fingerprint.Analyzed
	if hasAnalyzedFingerprint {
		out := e.scoreFromSnapshot(dep)
		e.presenter.OnExplainResult(out)
		return out, nil
	}

	if !req.AllowFreshScan {
		err := fmt.Errorf("explain: no analyzed fingerprint in snapshot and fresh scan disabled")
		e.presenter.OnExplainError(req.Ecosystem, req.Name, req.Version, err)
		return ExplainResult{}, err
	}
	if e.analyze == nil {
		err := fmt.Errorf("explain: analyze use case not configured (build with AST scanner)")
		e.presenter.OnExplainError(req.Ecosystem, req.Name, req.Version, err)
		return ExplainResult{}, err
	}

	// Fresh scan path. Run Analyze under the hood; transform its
	// AnalyzeResult into our ExplainResult shape so the presenter
	// only deals with one type. We use a no-op AnalyzePresenter
	// (passed at construction by composition root) so the analyze
	// command's stage messages don't double-up here — the explain
	// presenter handles the user-facing rendering.
	ar, err := e.analyze.Run(ctx, AnalyzeRequest{
		Ecosystem:    req.Ecosystem,
		Name:         req.Name,
		Version:      req.Version,
		WantEvidence: true,
		Silent:       true, // explain renders its own format
	})
	if err != nil {
		// Analyze already fired its presenter's error. Don't double-fire.
		return ExplainResult{}, err
	}
	out := ExplainResult{
		Source:        "fresh-scan",
		Ecosystem:     ar.Ecosystem,
		Name:          ar.Name,
		Version:       ar.Version,
		Fingerprint:   ar.Fingerprint,
		Evidence:      ar.Evidence,
		Risk:          ar.Risk,
		Verdict:       ar.Verdict,
		TarballSha256: ar.TarballSha256,
		SourceBytes:   ar.SourceBytes,
	}
	e.presenter.OnExplainResult(out)
	return out, nil
}

// findInSnapshot looks up (eco, name, version) in the saved snapshot
// at projectDir. Returns the dep + true on match, zero value + false
// on no snapshot / no match. Errors loading the snapshot are squashed
// to "not found" — we prefer the fresh-scan fallback over an error.
func (e *Explain) findInSnapshot(req ExplainRequest) (domain.Dependency, bool) {
	snap, ok, err := e.store.Load(req.ProjectDir)
	if err != nil || !ok {
		return domain.Dependency{}, false
	}
	for _, d := range snap.Deps {
		if d.Ecosystem == req.Ecosystem && d.Name == req.Name && d.Version == req.Version {
			return d, true
		}
	}
	// Fallback: a bare `name@version` defaults req.Ecosystem to npm, but
	// the dep may live under another ecosystem in the snapshot. Match on
	// name+version alone so `explain` works for pypi/hex/pub/... deps
	// without an explicit ecosystem prefix.
	for _, d := range snap.Deps {
		if d.Name == req.Name && d.Version == req.Version {
			return d, true
		}
	}
	return domain.Dependency{}, false
}

// scoreFromSnapshot builds an ExplainResult from a snapshot dep that
// has an analyzed fingerprint. No network. Evidence is empty (the
// snapshot stores the fingerprint, not the per-capture rows).
func (e *Explain) scoreFromSnapshot(dep domain.Dependency) ExplainResult {
	risk := domain.RiskScore(dep.Fingerprint).
		ApplyAllowlist(dep.Ecosystem, dep.Name, dep.Version, e.allowlist).
		DowngradeUnused(dep.Reachability, unusedSuppressEnabled())
	astVerdict := domain.Verdict(risk, domain.RiskAssessment{})
	// Advisories drive the verdict too — mirror ci's scoreSnapshot so
	// explain doesn't say "safe" for a dep that ci blocks on a CVE.
	var active []domain.Advisory
	for _, a := range dep.Advisories {
		if a.VEXSuppressed || a.FunctionUnreachable {
			continue
		}
		active = append(active, a)
	}
	verdict := max(astVerdict, domain.VerdictForAdvisories(active))
	return ExplainResult{
		Source:      "snapshot",
		Ecosystem:   dep.Ecosystem,
		Name:        dep.Name,
		Version:     dep.Version,
		Direct:      dep.Direct,
		Fingerprint: *dep.Fingerprint,
		Risk:        risk,
		Verdict:     verdict,
		SourceBytes: dep.Fingerprint.SourceSizeBytes,
	}
}
