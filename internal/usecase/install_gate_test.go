package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// --- mock ports ---------------------------------------------------------

type fakeResolver struct {
	calls int
	ret   string
	err   error
}

func (f *fakeResolver) Resolve(_ context.Context, _ domain.Ecosystem, _, _ string) (string, error) {
	f.calls++
	return f.ret, f.err
}

type fakeChecker struct {
	calls int
	ret   domain.Decision
	err   error
}

func (f *fakeChecker) Check(_ context.Context, _ domain.Ecosystem, _, _ string) (domain.Decision, error) {
	f.calls++
	if f.err != nil {
		return domain.Decision{}, f.err
	}
	return f.ret, nil
}

type fakeCache struct {
	store map[string]domain.Decision
	puts  int
	gets  int
}

func newFakeCache() *fakeCache { return &fakeCache{store: map[string]domain.Decision{}} }

func (f *fakeCache) Get(key string) (domain.Decision, bool) {
	f.gets++
	d, ok := f.store[key]
	return d, ok
}

func (f *fakeCache) Put(key string, d domain.Decision) error {
	f.puts++
	f.store[key] = d
	return nil
}

type fakeAudit struct{ entries []domain.Outcome }

func (f *fakeAudit) Write(o domain.Outcome) error {
	f.entries = append(f.entries, o)
	return nil
}

type fakeConfirmer struct {
	result ConfirmResult
	calls  int
}

func (f *fakeConfirmer) Confirm(string) ConfirmResult { f.calls++; return f.result }

type fakeEnv struct {
	ci             bool
	overrideAllow  bool
	overrideReason string
}

func (f *fakeEnv) IsCI() bool               { return f.ci }
func (f *fakeEnv) Override() (bool, string) { return f.overrideAllow, f.overrideReason }

type capturingPresenter struct {
	resolves   int
	skips      int
	decisions  []domain.Decision
	outcomes   []domain.Outcome
	apiErrors  int
	infos      []string
	resolveErr int
}

func (p *capturingPresenter) OnResolveStart(domain.PackageSpec, string, bool) { p.resolves++ }
func (p *capturingPresenter) OnResolveError(domain.PackageSpec, error)        { p.resolveErr++ }
func (p *capturingPresenter) OnSkipped(domain.PackageSpec)                    { p.skips++ }
func (p *capturingPresenter) OnDecision(d domain.Decision)                    { p.decisions = append(p.decisions, d) }
func (p *capturingPresenter) OnOutcome(o domain.Outcome, _, _ string) {
	p.outcomes = append(p.outcomes, o)
}
func (p *capturingPresenter) OnAPIError(domain.PackageSpec, string, error) { p.apiErrors++ }
func (p *capturingPresenter) OnInfo(m string)                              { p.infos = append(p.infos, m) }

// --- harness ------------------------------------------------------------

type harness struct {
	resolver *fakeResolver
	checker  *fakeChecker
	cache    *fakeCache
	audit    *fakeAudit
	confirm  *fakeConfirmer
	env      *fakeEnv
	pres     *capturingPresenter
	gate     *InstallGate
}

func newHarness() *harness {
	h := &harness{
		resolver: &fakeResolver{ret: "1.0.0"},
		checker:  &fakeChecker{ret: domain.Decision{Kind: domain.DecisionAllow, Severity: domain.SevInfo}},
		cache:    newFakeCache(),
		audit:    &fakeAudit{},
		confirm:  &fakeConfirmer{result: ConfirmDeny},
		env:      &fakeEnv{},
		pres:     &capturingPresenter{},
	}
	h.gate = NewInstallGate(h.resolver, h.checker, h.cache, h.audit, h.confirm, h.env, h.pres)
	return h
}

func req(specs ...domain.PackageSpec) Request {
	return Request{PMName: "npm", InstallVerb: "install", Specs: specs}
}

func spec(name, ver string) domain.PackageSpec {
	return domain.PackageSpec{Ecosystem: domain.EcoNpm, Name: name, Version: ver, Raw: name + "@" + ver}
}

// --- tests --------------------------------------------------------------

func TestGate_AllowProceeds(t *testing.T) {
	h := newHarness()
	res, err := h.gate.Run(context.Background(), req(spec("lodash", "4.17.21")))
	if err != nil {
		t.Fatal(err)
	}
	if res.AnyBlocked {
		t.Error("AnyBlocked should be false on allow")
	}
	if len(res.Outcomes) != 1 || res.Outcomes[0].Action != domain.ActionProceed {
		t.Errorf("outcomes: %+v", res.Outcomes)
	}
	if h.audit.entries[0].Action != domain.ActionProceed {
		t.Error("audit missing proceed")
	}
}

func TestGate_BlockBlocks(t *testing.T) {
	h := newHarness()
	h.checker.ret = domain.Decision{Kind: domain.DecisionBlock, Severity: domain.SevCritical}

	res, _ := h.gate.Run(context.Background(), req(spec("p", "1.0.0")))
	if !res.AnyBlocked {
		t.Error("expected AnyBlocked=true")
	}
	if res.Outcomes[0].Action != domain.ActionBlock {
		t.Errorf("expected Block, got %d", res.Outcomes[0].Action)
	}
}

func TestGate_OverrideRequiresReason(t *testing.T) {
	h := newHarness()
	h.env.overrideAllow = true
	h.env.overrideReason = ""
	h.checker.ret = domain.Decision{Kind: domain.DecisionBlock, Severity: domain.SevCritical}

	res, _ := h.gate.Run(context.Background(), req(spec("p", "1.0.0")))
	if !res.AnyBlocked {
		t.Error("override without reason must still block")
	}
	found := false
	for _, m := range h.pres.infos {
		if m == "AEGIS_OVERRIDE_REASON required to override — refusing" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected refusal info; got %v", h.pres.infos)
	}
}

func TestGate_OverrideWithReasonProceeds(t *testing.T) {
	h := newHarness()
	h.env.overrideAllow = true
	h.env.overrideReason = "hotfix"
	h.checker.ret = domain.Decision{Kind: domain.DecisionBlock, Severity: domain.SevCritical}

	res, _ := h.gate.Run(context.Background(), req(spec("p", "1.0.0")))
	if res.AnyBlocked {
		t.Error("valid override must proceed")
	}
	if !res.Outcomes[0].OverrideUsed || res.Outcomes[0].OverrideReason != "hotfix" {
		t.Errorf("outcome: %+v", res.Outcomes[0])
	}
}

func TestGate_PromptInCIBlocks(t *testing.T) {
	h := newHarness()
	h.env.ci = true
	h.checker.ret = domain.Decision{Kind: domain.DecisionPrompt, Severity: domain.SevHigh}

	res, _ := h.gate.Run(context.Background(), req(spec("p", "1.0.0")))
	if !res.AnyBlocked || !res.Outcomes[0].PromotedFromPrompt {
		t.Errorf("expected blocked + promoted; got %+v", res.Outcomes[0])
	}
	if h.confirm.calls != 0 {
		t.Errorf("CI must not prompt; got %d calls", h.confirm.calls)
	}
}

func TestGate_PromptUserAllows(t *testing.T) {
	h := newHarness()
	h.confirm.result = ConfirmAllow
	h.checker.ret = domain.Decision{Kind: domain.DecisionPrompt, Severity: domain.SevHigh}

	res, _ := h.gate.Run(context.Background(), req(spec("p", "1.0.0")))
	if res.AnyBlocked {
		t.Error("user-allowed prompt should proceed")
	}
	if !res.Outcomes[0].OverrideUsed {
		t.Error("audit should mark OverrideUsed for human-allowed prompt")
	}
}

func TestGate_PromptUserDenies(t *testing.T) {
	h := newHarness()
	h.confirm.result = ConfirmDeny
	h.checker.ret = domain.Decision{Kind: domain.DecisionPrompt, Severity: domain.SevHigh}

	res, _ := h.gate.Run(context.Background(), req(spec("p", "1.0.0")))
	if !res.AnyBlocked {
		t.Error("denied prompt must block")
	}
}

func TestGate_NonRegistrySkips(t *testing.T) {
	h := newHarness()
	s := spec("./local", "")
	s.NonRegistry = true

	_, _ = h.gate.Run(context.Background(), req(s))
	if h.checker.calls != 0 {
		t.Errorf("non-registry must skip API; got %d calls", h.checker.calls)
	}
	if h.pres.skips != 1 {
		t.Errorf("expected 1 skip presented, got %d", h.pres.skips)
	}
}

func TestGate_ExactVersionSkipsResolver(t *testing.T) {
	h := newHarness()
	_, _ = h.gate.Run(context.Background(), req(spec("lodash", "4.17.21")))
	if h.resolver.calls != 0 {
		t.Errorf("exact version must skip resolver; got %d calls", h.resolver.calls)
	}
}

func TestGate_RangeTriggersResolver(t *testing.T) {
	h := newHarness()
	h.resolver.ret = "4.17.21"
	_, _ = h.gate.Run(context.Background(), req(spec("lodash", "^4.17.0")))
	if h.resolver.calls != 1 {
		t.Errorf("range must trigger resolver; got %d calls", h.resolver.calls)
	}
}

func TestGate_CacheHitSkipsAPI(t *testing.T) {
	h := newHarness()
	key := CacheKey(domain.EcoNpm, "lodash", "4.17.21")
	h.cache.store[key] = domain.Decision{Kind: domain.DecisionAllow, Severity: domain.SevInfo}

	_, _ = h.gate.Run(context.Background(), req(spec("lodash", "4.17.21")))
	if h.checker.calls != 0 {
		t.Errorf("cache hit must skip API; got %d calls", h.checker.calls)
	}
	if h.audit.entries[0].Decision.Source != domain.SourceCache {
		t.Errorf("expected audit source=cache; got %q", h.audit.entries[0].Decision.Source)
	}
}

func TestGate_CacheMissPopulates(t *testing.T) {
	h := newHarness()
	_, _ = h.gate.Run(context.Background(), req(spec("lodash", "4.17.21")))
	if h.cache.puts != 1 {
		t.Errorf("expected 1 cache put; got %d", h.cache.puts)
	}
}

func TestGate_APIErrorFailsOpen(t *testing.T) {
	h := newHarness()
	h.checker.err = errors.New("boom")

	res, _ := h.gate.Run(context.Background(), req(spec("lodash", "4.17.21")))
	if res.AnyBlocked {
		t.Error("API error must fail open, not block")
	}
	if h.pres.apiErrors != 1 {
		t.Errorf("expected presenter API error; got %d", h.pres.apiErrors)
	}
	if len(h.audit.entries) != 1 || h.audit.entries[0].Decision.Source != domain.SourceError {
		t.Errorf("expected audit source=error; got %+v", h.audit.entries)
	}
}
