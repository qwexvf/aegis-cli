package usecase

import (
	"context"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Analyze is the on-demand single-package use case: fetch a package's
// distribution, run the AST scanner with evidence collection, score it,
// and hand the result to a presenter. Used by `aegis analyze
// <pkg>@<ver>` to close the gap when the incident DB has no record but
// the user still wants to know if a specific package is suspicious.
//
// Unlike Snapshot.Enrich which operates on the whole project's
// aegis.lock, Analyze is per-package and synchronous. There's no fpCache
// lookup here on purpose — the user is asking for a fresh look, not the
// last cached verdict.
type Analyze struct {
	fetcher          PackageSourceFetcher
	evidenceAnalyzer EvidenceAnalyzer
	presenter        AnalyzePresenter
	allowlist        domain.AllowSet
}

// NewAnalyze wires the bare minimum (presenter only). Risk-engine
// dependencies are attached separately via WithRiskEngine so the
// composition root can share the fetcher + dispatcher with Snapshot.
func NewAnalyze(presenter AnalyzePresenter) *Analyze {
	return &Analyze{presenter: presenter}
}

// WithRiskEngine attaches the source fetcher and evidence-capable AST
// analyzer. Without these, Run reports "risk engine not configured".
func (a *Analyze) WithRiskEngine(fetcher PackageSourceFetcher, analyzer EvidenceAnalyzer) *Analyze {
	a.fetcher = fetcher
	a.evidenceAnalyzer = analyzer
	return a
}

// WithAllowlist attaches an AllowSet so suppressed flags don't
// manufacture false-positive verdicts. Empty AllowSet behaves as no
// suppression.
func (a *Analyze) WithAllowlist(set domain.AllowSet) *Analyze {
	a.allowlist = set
	return a
}

// AnalyzeRequest is the input to Analyze.Run. WantEvidence is a hint
// for the presenter — the use case always collects evidence (cheap for
// one package) so the JSON consumer can opt in without a re-analyze.
//
// Silent suppresses every presenter callback. Used by sibling use
// cases (Explain) that want to render their own format on top of the
// raw result without doubling up the per-stage chatter.
type AnalyzeRequest struct {
	Ecosystem    domain.Ecosystem
	Name         string
	Version      string
	WantEvidence bool
	Silent       bool
}

// AnalyzeResult is the structured output of Analyze.Run. The CLI
// presenter renders this; the JSON presenter marshals it directly.
type AnalyzeResult struct {
	Ecosystem      domain.Ecosystem
	Name           string
	Version        string
	Fingerprint    domain.Fingerprint
	Evidence       []domain.Evidence
	Risk           domain.RiskAssessment
	Verdict        domain.VerdictKind
	TarballSha256  string
	FilesAnalyzed  int
	SourceBytes    int
}

// AnalyzePresenter renders progress + the final verdict for `aegis
// analyze`. Implementations live in presenter/cli/analyze_render.go.
type AnalyzePresenter interface {
	OnAnalyzeStart(eco domain.Ecosystem, name, version string)
	OnAnalyzeStage(stage EnrichStage)
	OnAnalyzeResult(r AnalyzeResult, withEvidence bool)
	OnAnalyzeError(eco domain.Ecosystem, name, version string, err error)
}

// Run executes the analyze pipeline. Returns the AnalyzeResult so the
// CLI can derive an exit code from the verdict; presenter callbacks
// have already been fired by the time Run returns.
//
// Errors flow through OnAnalyzeError AND are returned — the caller
// (Cobra command) maps the error to exit code 2 ("couldn't get a
// verdict") distinct from a successful BLOCK verdict (exit 1).
func (a *Analyze) Run(ctx context.Context, req AnalyzeRequest) (AnalyzeResult, error) {
	emit := func(fn func()) {
		if !req.Silent {
			fn()
		}
	}
	if a.fetcher == nil || a.evidenceAnalyzer == nil {
		err := fmt.Errorf("risk engine not configured (build with AST scanner)")
		emit(func() { a.presenter.OnAnalyzeError(req.Ecosystem, req.Name, req.Version, err) })
		return AnalyzeResult{}, err
	}
	if req.Name == "" || req.Version == "" {
		err := fmt.Errorf("name and version required")
		emit(func() { a.presenter.OnAnalyzeError(req.Ecosystem, req.Name, req.Version, err) })
		return AnalyzeResult{}, err
	}

	emit(func() { a.presenter.OnAnalyzeStart(req.Ecosystem, req.Name, req.Version) })
	emit(func() { a.presenter.OnAnalyzeStage(EnrichStageFetch) })

	src, err := a.fetcher.Fetch(ctx, req.Ecosystem, req.Name, req.Version)
	if err != nil {
		wrapped := fmt.Errorf("fetch: %w", err)
		emit(func() { a.presenter.OnAnalyzeError(req.Ecosystem, req.Name, req.Version, wrapped) })
		return AnalyzeResult{}, wrapped
	}

	emit(func() { a.presenter.OnAnalyzeStage(EnrichStageScan) })
	fp, evidence, err := a.evidenceAnalyzer.AnalyzeWithEvidence(ctx, req.Ecosystem, src)
	if err != nil {
		wrapped := fmt.Errorf("analyze: %w", err)
		emit(func() { a.presenter.OnAnalyzeError(req.Ecosystem, req.Name, req.Version, wrapped) })
		return AnalyzeResult{}, wrapped
	}

	risk := domain.RiskScore(&fp).
		ApplyAllowlist(req.Ecosystem, req.Name, req.Version, a.allowlist)
	// Drift is empty here — single-version analyze has no prior
	// fingerprint to compare against. Verdict therefore reflects only
	// the absolute risk of the requested version.
	verdict := domain.Verdict(risk, domain.RiskAssessment{})

	result := AnalyzeResult{
		Ecosystem:     req.Ecosystem,
		Name:          req.Name,
		Version:       req.Version,
		Fingerprint:   fp,
		Evidence:      evidence,
		Risk:          risk,
		Verdict:       verdict,
		TarballSha256: src.TarballSha256,
		SourceBytes:   fp.SourceSizeBytes,
		FilesAnalyzed: len(src.Files),
	}
	emit(func() { a.presenter.OnAnalyzeResult(result, req.WantEvidence) })
	return result, nil
}
