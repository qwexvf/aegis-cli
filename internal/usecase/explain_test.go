package usecase

import (
	"context"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

type explainCapturingPresenter struct {
	results []ExplainResult
	errors  []error
}

func (p *explainCapturingPresenter) OnExplainResult(r ExplainResult) {
	p.results = append(p.results, r)
}
func (p *explainCapturingPresenter) OnExplainError(_ domain.Ecosystem, _, _ string, e error) {
	p.errors = append(p.errors, e)
}

func TestExplain_FromSnapshotWhenAnalyzed(t *testing.T) {
	fp := &domain.Fingerprint{
		Analyzed: true,
		Capabilities: domain.NewCapabilitySet(
			domain.CapShellSpawn, domain.CapNetEgress,
		),
	}
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "p", Version: "1.0.0", Direct: true, Fingerprint: fp},
	}}
	pres := &explainCapturingPresenter{}
	ex := NewExplain(store, nil, pres)

	result, err := ex.Run(context.Background(), ExplainRequest{
		ProjectDir: "/proj",
		Ecosystem:  domain.EcoNpm,
		Name:       "p", Version: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Source != "snapshot" {
		t.Errorf("source = %q, want snapshot", result.Source)
	}
	if !result.Direct {
		t.Errorf("direct flag should be carried from snapshot")
	}
	if !result.Fingerprint.Capabilities.Has(domain.CapShellSpawn) {
		t.Errorf("capabilities not carried over")
	}
	if len(pres.results) != 1 {
		t.Errorf("expected 1 OnExplainResult call")
	}
}

func TestExplain_SnapshotMissingFingerprintFallsBackToFreshScan(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "p", Version: "1.0.0"}, // no fingerprint
	}}
	fetcher := &fakeFetcher{}
	analyzer := &fakeEvidenceAnalyzer{
		out: domain.Fingerprint{
			Analyzed: true, Capabilities: domain.NewCapabilitySet(domain.CapNetEgress),
		},
	}
	analyze := NewAnalyze(&analyzeCapturingPresenter{}).WithRiskEngine(fetcher, analyzer)
	pres := &explainCapturingPresenter{}
	ex := NewExplain(store, analyze, pres)

	result, err := ex.Run(context.Background(), ExplainRequest{
		ProjectDir:     "/proj",
		Ecosystem:      domain.EcoNpm,
		Name:           "p", Version: "1.0.0",
		AllowFreshScan: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Source != "fresh-scan" {
		t.Errorf("source = %q, want fresh-scan", result.Source)
	}
	if !result.Fingerprint.Capabilities.Has(domain.CapNetEgress) {
		t.Errorf("fresh-scan capabilities missing")
	}
}

func TestExplain_SnapshotOnlyErrorsIfMissing(t *testing.T) {
	store := newFakeStore() // empty
	pres := &explainCapturingPresenter{}
	ex := NewExplain(store, nil, pres)

	_, err := ex.Run(context.Background(), ExplainRequest{
		ProjectDir:     "/proj",
		Ecosystem:      domain.EcoNpm,
		Name:           "p", Version: "1.0.0",
		AllowFreshScan: false,
	})
	if err == nil {
		t.Error("expected error when snapshot has no entry and fresh scan disabled")
	}
	if len(pres.errors) != 1 {
		t.Errorf("expected 1 OnExplainError, got %d", len(pres.errors))
	}
}

func TestExplain_NameOrVersionEmptyErrors(t *testing.T) {
	pres := &explainCapturingPresenter{}
	ex := NewExplain(newFakeStore(), nil, pres)

	for _, req := range []ExplainRequest{
		{ProjectDir: "/proj", Ecosystem: domain.EcoNpm, Name: "", Version: "1"},
		{ProjectDir: "/proj", Ecosystem: domain.EcoNpm, Name: "p", Version: ""},
	} {
		if _, err := ex.Run(context.Background(), req); err == nil {
			t.Errorf("expected error for %+v", req)
		}
	}
}

func TestExplain_AllowlistAffectsVerdict(t *testing.T) {
	rules := []domain.AllowRule{
		{Ecosystem: domain.EcoNpm, Name: "trusted", VersionRange: "*",
			Capability: domain.CapDynamicEval, Reason: "test"},
	}
	set, _ := domain.NewAllowSet(rules)

	fp := &domain.Fingerprint{
		Analyzed:     true,
		Capabilities: domain.NewCapabilitySet(domain.CapDynamicEval),
	}
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "trusted", Version: "1.0.0", Fingerprint: fp},
	}}
	pres := &explainCapturingPresenter{}
	ex := NewExplain(store, nil, pres).WithAllowlist(set)

	result, _ := ex.Run(context.Background(), ExplainRequest{
		ProjectDir: "/proj",
		Ecosystem:  domain.EcoNpm,
		Name:       "trusted", Version: "1.0.0",
	})
	suppressed := false
	for _, f := range result.Risk.Flags {
		if f.Suppressed {
			suppressed = true
		}
	}
	if !suppressed {
		t.Errorf("expected at least one suppressed flag: %+v", result.Risk.Flags)
	}
}

func TestExplain_FreshScanWithoutAnalyzeUseCaseErrors(t *testing.T) {
	store := newFakeStore() // empty — no snapshot lookup hit
	pres := &explainCapturingPresenter{}
	ex := NewExplain(store, nil, pres) // no Analyze wired

	_, err := ex.Run(context.Background(), ExplainRequest{
		ProjectDir:     "/proj",
		Ecosystem:      domain.EcoNpm,
		Name:           "p", Version: "1.0.0",
		AllowFreshScan: true,
	})
	if err == nil {
		t.Error("expected error when AllowFreshScan but no Analyze wired")
	}
}

func TestCapabilityDescription_AllCapsHaveOne(t *testing.T) {
	for _, c := range domain.AllCapabilities() {
		if d := c.Description(); d == "" || d == "no description available" {
			t.Errorf("capability %s has no description", c)
		}
	}
}
