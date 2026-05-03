package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// recheckFakeChecker implements DecisionChecker; returns a canned Decision
// per (name, version) pair, falling back to allow.
type recheckFakeChecker struct {
	byKey map[string]domain.Decision
	err   error
}

func (f *recheckFakeChecker) Check(_ context.Context, eco domain.Ecosystem, name, version string) (domain.Decision, error) {
	if f.err != nil {
		return domain.Decision{}, f.err
	}
	if dec, ok := f.byKey[string(eco)+"/"+name+"@"+version]; ok {
		return dec, nil
	}
	return domain.Decision{Kind: domain.DecisionAllow}, nil
}

type recheckCapturingPresenter struct {
	begins   int
	progress int
	results  []RecheckResult
	errors   []error
}

func (p *recheckCapturingPresenter) OnRecheckBegin(int)             { p.begins++ }
func (p *recheckCapturingPresenter) OnRecheckProgress(int, int, string) { p.progress++ }
func (p *recheckCapturingPresenter) OnRecheckResult(r RecheckResult) {
	p.results = append(p.results, r)
}
func (p *recheckCapturingPresenter) OnRecheckError(err error) { p.errors = append(p.errors, err) }

func direct(name, ver string) domain.Dependency {
	return domain.Dependency{Ecosystem: domain.EcoNpm, Name: name, Version: ver, Direct: true}
}

func transitive(name, ver string) domain.Dependency {
	return domain.Dependency{Ecosystem: domain.EcoNpm, Name: name, Version: ver, Direct: false}
}

func TestRecheck_AllAllowedPasses(t *testing.T) {
	scanner := &fakeScanner{deps: []domain.Dependency{direct("a", "1"), direct("b", "1")}}
	checker := &recheckFakeChecker{}
	pres := &recheckCapturingPresenter{}
	rc := NewRecheck(scanner, checker, pres)

	result, err := rc.Run(context.Background(), RecheckRequest{ProjectDir: "/proj"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed {
		t.Errorf("expected pass when all allowed")
	}
	if result.Summary.Allowed != 2 || result.Summary.Total != 2 {
		t.Errorf("summary: %+v", result.Summary)
	}
}

func TestRecheck_BlockedFailsByDefault(t *testing.T) {
	scanner := &fakeScanner{deps: []domain.Dependency{direct("evil", "1.0")}}
	checker := &recheckFakeChecker{
		byKey: map[string]domain.Decision{
			"npm/evil@1.0": {Kind: domain.DecisionBlock, Severity: "critical"},
		},
	}
	pres := &recheckCapturingPresenter{}
	rc := NewRecheck(scanner, checker, pres)

	result, _ := rc.Run(context.Background(), RecheckRequest{ProjectDir: "/proj"})
	if result.Passed {
		t.Errorf("expected fail on blocked dep")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Decision.Kind != domain.DecisionBlock {
		t.Errorf("finding decision = %s, want block", result.Findings[0].Decision.Kind)
	}
}

func TestRecheck_PromptIgnoredByDefault(t *testing.T) {
	scanner := &fakeScanner{deps: []domain.Dependency{direct("p", "1")}}
	checker := &recheckFakeChecker{
		byKey: map[string]domain.Decision{
			"npm/p@1": {Kind: domain.DecisionPrompt},
		},
	}
	pres := &recheckCapturingPresenter{}
	rc := NewRecheck(scanner, checker, pres)

	result, _ := rc.Run(context.Background(), RecheckRequest{ProjectDir: "/proj"})
	if !result.Passed {
		t.Errorf("expected pass — prompt is not a failure unless --fail-on-prompt")
	}
	if result.Summary.Prompts != 1 {
		t.Errorf("summary.prompts = %d, want 1", result.Summary.Prompts)
	}
}

func TestRecheck_PromptFailsWithFlag(t *testing.T) {
	scanner := &fakeScanner{deps: []domain.Dependency{direct("p", "1")}}
	checker := &recheckFakeChecker{
		byKey: map[string]domain.Decision{
			"npm/p@1": {Kind: domain.DecisionPrompt},
		},
	}
	pres := &recheckCapturingPresenter{}
	rc := NewRecheck(scanner, checker, pres)

	result, _ := rc.Run(context.Background(), RecheckRequest{
		ProjectDir: "/proj", FailOnPrompt: true,
	})
	if result.Passed {
		t.Errorf("expected fail with --fail-on-prompt")
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestRecheck_DirectOnlyByDefault(t *testing.T) {
	scanner := &fakeScanner{deps: []domain.Dependency{
		direct("dep", "1"),
		transitive("transitive", "1"),
	}}
	checker := &recheckFakeChecker{
		byKey: map[string]domain.Decision{
			"npm/transitive@1": {Kind: domain.DecisionBlock},
		},
	}
	pres := &recheckCapturingPresenter{}
	rc := NewRecheck(scanner, checker, pres)

	result, _ := rc.Run(context.Background(), RecheckRequest{ProjectDir: "/proj"})
	if !result.Passed {
		t.Errorf("expected pass — transitive block ignored without --all")
	}
	if result.Summary.Total != 1 {
		t.Errorf("summary.total = %d, want 1 (direct only)", result.Summary.Total)
	}
}

func TestRecheck_AllIncludesTransitives(t *testing.T) {
	scanner := &fakeScanner{deps: []domain.Dependency{
		direct("dep", "1"),
		transitive("transitive", "1"),
	}}
	checker := &recheckFakeChecker{
		byKey: map[string]domain.Decision{
			"npm/transitive@1": {Kind: domain.DecisionBlock},
		},
	}
	pres := &recheckCapturingPresenter{}
	rc := NewRecheck(scanner, checker, pres)

	result, _ := rc.Run(context.Background(), RecheckRequest{
		ProjectDir: "/proj", IncludeAll: true,
	})
	if result.Passed {
		t.Errorf("expected fail — transitive block surfaced with --all")
	}
}

func TestRecheck_PerDepErrorCountsAsErrorBucket(t *testing.T) {
	scanner := &fakeScanner{deps: []domain.Dependency{direct("a", "1")}}
	checker := &recheckFakeChecker{err: errors.New("network blip")}
	pres := &recheckCapturingPresenter{}
	rc := NewRecheck(scanner, checker, pres)

	result, _ := rc.Run(context.Background(), RecheckRequest{ProjectDir: "/proj"})
	// Per-dep error → counted in Summary.Errors, doesn't fail the run.
	if !result.Passed {
		t.Errorf("expected pass — per-dep error is not a failure")
	}
	if result.Summary.Errors != 1 {
		t.Errorf("summary.errors = %d, want 1", result.Summary.Errors)
	}
}

func TestRecheck_FindingsSortedBlockBeforePrompt(t *testing.T) {
	scanner := &fakeScanner{deps: []domain.Dependency{
		direct("z-prompt", "1"),
		direct("a-block", "1"),
	}}
	checker := &recheckFakeChecker{
		byKey: map[string]domain.Decision{
			"npm/z-prompt@1": {Kind: domain.DecisionPrompt},
			"npm/a-block@1":  {Kind: domain.DecisionBlock},
		},
	}
	pres := &recheckCapturingPresenter{}
	rc := NewRecheck(scanner, checker, pres)

	result, _ := rc.Run(context.Background(), RecheckRequest{
		ProjectDir: "/proj", FailOnPrompt: true,
	})
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.Findings[0].Decision.Kind != domain.DecisionBlock {
		t.Errorf("first finding should be block, got %s", result.Findings[0].Decision.Kind)
	}
}

func TestRecheck_EmptyLockfilePassesNoOp(t *testing.T) {
	scanner := &fakeScanner{deps: nil}
	pres := &recheckCapturingPresenter{}
	rc := NewRecheck(scanner, &recheckFakeChecker{}, pres)

	result, _ := rc.Run(context.Background(), RecheckRequest{ProjectDir: "/proj"})
	if !result.Passed {
		t.Errorf("expected pass on empty lockfile")
	}
	if pres.begins != 0 {
		t.Errorf("OnRecheckBegin should not fire when nothing to do")
	}
}
