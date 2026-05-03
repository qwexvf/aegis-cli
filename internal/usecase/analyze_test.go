package usecase

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// fakeEvidenceAnalyzer captures AnalyzeWithEvidence calls and returns
// canned output. Concurrency-safe (Run is synchronous, but tests may
// share fixtures).
type fakeEvidenceAnalyzer struct {
	mu       sync.Mutex
	calls    int
	out      domain.Fingerprint
	evidence []domain.Evidence
	err      error
}

func (f *fakeEvidenceAnalyzer) AnalyzeWithEvidence(_ context.Context, _ domain.Ecosystem, _ PackageSource) (domain.Fingerprint, []domain.Evidence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return domain.Fingerprint{}, nil, f.err
	}
	return f.out, f.evidence, nil
}

// analyzeCapturingPresenter records calls for assertions.
type analyzeCapturingPresenter struct {
	starts  int
	stages  []EnrichStage
	results []AnalyzeResult
	errors  []error
}

func (p *analyzeCapturingPresenter) OnAnalyzeStart(_ domain.Ecosystem, _, _ string) {
	p.starts++
}
func (p *analyzeCapturingPresenter) OnAnalyzeStage(s EnrichStage) {
	p.stages = append(p.stages, s)
}
func (p *analyzeCapturingPresenter) OnAnalyzeResult(r AnalyzeResult, _ bool) {
	p.results = append(p.results, r)
}
func (p *analyzeCapturingPresenter) OnAnalyzeError(_ domain.Ecosystem, _, _ string, e error) {
	p.errors = append(p.errors, e)
}

func TestAnalyze_NoRiskEngineErrors(t *testing.T) {
	pres := &analyzeCapturingPresenter{}
	a := NewAnalyze(pres)

	_, err := a.Run(context.Background(), AnalyzeRequest{
		Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21",
	})
	if err == nil {
		t.Fatal("expected error when risk engine not configured")
	}
	if len(pres.errors) != 1 {
		t.Errorf("expected 1 presenter error, got %d", len(pres.errors))
	}
}

func TestAnalyze_MissingNameOrVersionErrors(t *testing.T) {
	pres := &analyzeCapturingPresenter{}
	a := NewAnalyze(pres).
		WithRiskEngine(&fakeFetcher{}, &fakeEvidenceAnalyzer{})

	cases := []AnalyzeRequest{
		{Ecosystem: domain.EcoNpm, Name: "", Version: "1"},
		{Ecosystem: domain.EcoNpm, Name: "x", Version: ""},
	}
	for _, req := range cases {
		_, err := a.Run(context.Background(), req)
		if err == nil {
			t.Errorf("expected error for %+v", req)
		}
	}
}

func TestAnalyze_FetchErrorBubblesUp(t *testing.T) {
	pres := &analyzeCapturingPresenter{}
	a := NewAnalyze(pres).
		WithRiskEngine(&fakeFetcher{err: errors.New("network down")}, &fakeEvidenceAnalyzer{})

	_, err := a.Run(context.Background(), AnalyzeRequest{
		Ecosystem: domain.EcoNpm, Name: "x", Version: "1",
	})
	if err == nil {
		t.Fatal("expected fetch error")
	}
	if len(pres.errors) != 1 {
		t.Errorf("expected presenter error, got %d", len(pres.errors))
	}
	if len(pres.results) != 0 {
		t.Error("OnAnalyzeResult should not fire on fetch error")
	}
}

func TestAnalyze_AnalyzeErrorBubblesUp(t *testing.T) {
	pres := &analyzeCapturingPresenter{}
	a := NewAnalyze(pres).
		WithRiskEngine(&fakeFetcher{}, &fakeEvidenceAnalyzer{err: errors.New("parse fail")})

	_, err := a.Run(context.Background(), AnalyzeRequest{
		Ecosystem: domain.EcoNpm, Name: "x", Version: "1",
	})
	if err == nil {
		t.Fatal("expected analyze error")
	}
	if len(pres.results) != 0 {
		t.Error("OnAnalyzeResult should not fire on analyze error")
	}
}

func TestAnalyze_HappyPathSafeVerdict(t *testing.T) {
	pres := &analyzeCapturingPresenter{}
	fetcher := &fakeFetcher{
		manifest: []byte(`{"name":"clean","version":"1.0.0"}`),
		files:    map[string][]byte{"index.js": []byte("module.exports = 1")},
	}
	analyzer := &fakeEvidenceAnalyzer{
		out: domain.Fingerprint{
			Analyzed:        true,
			Capabilities:    domain.NewCapabilitySet(),
			SourceSizeBytes: 18,
		},
	}
	a := NewAnalyze(pres).WithRiskEngine(fetcher, analyzer)

	result, err := a.Run(context.Background(), AnalyzeRequest{
		Ecosystem: domain.EcoNpm, Name: "clean", Version: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != domain.VerdictSafe {
		t.Errorf("verdict = %s, want safe", result.Verdict)
	}
	if pres.starts != 1 {
		t.Errorf("expected 1 start, got %d", pres.starts)
	}
	wantStages := []EnrichStage{EnrichStageFetch, EnrichStageScan}
	if len(pres.stages) != 2 || pres.stages[0] != wantStages[0] || pres.stages[1] != wantStages[1] {
		t.Errorf("stages = %v, want %v", pres.stages, wantStages)
	}
	if len(pres.results) != 1 {
		t.Errorf("expected 1 result event, got %d", len(pres.results))
	}
}

func TestAnalyze_HighRiskProducesBlock(t *testing.T) {
	pres := &analyzeCapturingPresenter{}
	fetcher := &fakeFetcher{}
	// Capabilities + hook → high score → block.
	analyzer := &fakeEvidenceAnalyzer{
		out: domain.Fingerprint{
			Analyzed: true,
			Capabilities: domain.NewCapabilitySet(
				domain.CapShellSpawn, domain.CapDynamicEval,
				domain.CapBase64Decode, domain.CapNetEgress,
			),
			Hooks: []domain.InstallHook{
				{Phase: domain.PhasePostInstall, Source: "scripts.postinstall"},
			},
		},
	}
	a := NewAnalyze(pres).WithRiskEngine(fetcher, analyzer)

	result, err := a.Run(context.Background(), AnalyzeRequest{
		Ecosystem: domain.EcoNpm, Name: "evil", Version: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != domain.VerdictBlock {
		t.Errorf("verdict = %s, want block", result.Verdict)
	}
	if result.Risk.Score == 0 {
		t.Errorf("expected non-zero risk score, got %d", result.Risk.Score)
	}
}

func TestAnalyze_AllowlistSuppressesFlags(t *testing.T) {
	pres := &analyzeCapturingPresenter{}
	fetcher := &fakeFetcher{}
	analyzer := &fakeEvidenceAnalyzer{
		out: domain.Fingerprint{
			Analyzed:     true,
			Capabilities: domain.NewCapabilitySet(domain.CapDynamicEval),
		},
	}

	rules := []domain.AllowRule{
		{Ecosystem: domain.EcoNpm, Name: "trusted", VersionRange: "*", Capability: domain.CapDynamicEval, Reason: "test"},
	}
	set, err := domain.NewAllowSet(rules)
	if err != nil {
		t.Fatal(err)
	}

	a := NewAnalyze(pres).WithRiskEngine(fetcher, analyzer).WithAllowlist(set)

	result, err := a.Run(context.Background(), AnalyzeRequest{
		Ecosystem: domain.EcoNpm, Name: "trusted", Version: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The flag should be present but suppressed; score should reflect
	// the suppression (lower than without allowlist).
	suppressed := false
	for _, f := range result.Risk.Flags {
		if f.Suppressed && f.Code == "dynamic-eval" {
			suppressed = true
		}
	}
	if !suppressed {
		t.Errorf("expected dynamic-eval flag to be suppressed: %+v", result.Risk.Flags)
	}
}
