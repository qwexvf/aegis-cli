package pm

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/api"
	"github.com/qwexvf/aegis/services/cli/internal/audit"
	"github.com/qwexvf/aegis/services/cli/internal/cache"
	"github.com/qwexvf/aegis/services/cli/internal/prompt"
)

// fakePM is a controllable PackageManager for runner tests.
type fakePM struct {
	name        string
	ecosystem   string
	isInstall   bool
	installArgs []PackageSpec
	execCalled  bool
	execArgs    []string
}

func (f *fakePM) Name() string                                  { return f.name }
func (f *fakePM) Ecosystem() string                             { return f.ecosystem }
func (f *fakePM) IsInstallCommand(argv []string) bool           { return f.isInstall }
func (f *fakePM) ParseInstallArgs(argv []string) []PackageSpec  { return f.installArgs }
func (f *fakePM) Exec(args []string) error {
	f.execCalled = true
	f.execArgs = args
	return nil
}

type fakeResolver struct {
	resolveTo string
	err       error
}

func (f fakeResolver) Resolve(_ context.Context, _, _ string) (string, error) {
	return f.resolveTo, f.err
}

type fakeChecker struct {
	decision *api.Decision
	err      error
	calls    int
}

func (f *fakeChecker) Check(_ context.Context, ecosystem, pkg, version string) (*api.Decision, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	d := *f.decision
	d.Ecosystem = ecosystem
	d.Package = pkg
	d.Version = version
	return &d, nil
}

type fakeConfirmer struct {
	result prompt.Result
	calls  int
}

func (f *fakeConfirmer) Confirm(string) prompt.Result {
	f.calls++
	return f.result
}

type fakeAudit struct {
	entries []audit.Entry
}

func (f *fakeAudit) Write(e audit.Entry) error {
	f.entries = append(f.entries, e)
	return nil
}

type runnerHarness struct {
	pm       *fakePM
	resolver *countingResolver
	api      *fakeChecker
	cache    *cache.Cache
	confirm  *fakeConfirmer
	audit    *fakeAudit
	out      *bytes.Buffer
	exitCode *int
	runner   *Runner
}

func newHarness(t *testing.T) *runnerHarness {
	t.Helper()
	h := &runnerHarness{
		pm:       &fakePM{name: "npm", ecosystem: "npm", isInstall: true},
		resolver: &countingResolver{},
		api:      &fakeChecker{decision: &api.Decision{Decision: "allow", Severity: "info"}},
		cache:    cache.NewAt(filepath.Join(t.TempDir(), "decisions.json")),
		confirm:  &fakeConfirmer{result: prompt.ResultDenied},
		audit:    &fakeAudit{},
		out:      &bytes.Buffer{},
	}
	exitCode := -1
	h.exitCode = &exitCode
	h.runner = &Runner{
		pm:          h.pm,
		registry:    h.resolver,
		api:         h.api,
		cache:       h.cache,
		audit:       h.audit,
		confirm:     h.confirm,
		isCI:        func() bool { return false },
		out:         h.out,
		timeout:     5 * time.Second,
		installVerb: "install",
		exitFn:      func(c int) { *h.exitCode = c },
	}
	return h
}

func TestRunner_NonInstallPassthrough(t *testing.T) {
	h := newHarness(t)
	h.pm.isInstall = false

	if err := h.runner.Run([]string{"run", "build"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !h.pm.execCalled {
		t.Error("expected Exec to be called for non-install argv")
	}
	if h.api.calls != 0 {
		t.Errorf("expected 0 API calls, got %d", h.api.calls)
	}
	if *h.exitCode != -1 {
		t.Errorf("expected no exit, got code %d", *h.exitCode)
	}
}

func TestRunner_AllowProceedsToExec(t *testing.T) {
	h := newHarness(t)
	h.pm.installArgs = []PackageSpec{{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}}

	if err := h.runner.Run([]string{"install", "lodash@4.17.21"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !h.pm.execCalled {
		t.Error("expected Exec to be called after allow decision")
	}
	if h.api.calls != 1 {
		t.Errorf("expected 1 API call, got %d", h.api.calls)
	}
	if *h.exitCode != -1 {
		t.Errorf("expected no exit, got %d", *h.exitCode)
	}
	if len(h.audit.entries) != 1 || h.audit.entries[0].Decision != "allow" {
		t.Errorf("expected 1 audit entry decision=allow, got %+v", h.audit.entries)
	}
}

func TestRunner_BlockExitsWithoutExec(t *testing.T) {
	t.Setenv("AEGIS_OVERRIDE", "")
	t.Setenv("AEGIS_OVERRIDE_REASON", "")
	h := newHarness(t)
	h.api.decision = &api.Decision{Decision: "block", Severity: "critical", AdvisoryID: "GHSA-X"}
	h.pm.installArgs = []PackageSpec{{Name: "@bitwarden/cli", Version: "2026.4.0", Raw: "@bitwarden/cli@2026.4.0"}}

	if err := h.runner.Run([]string{"install", "@bitwarden/cli@2026.4.0"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if h.pm.execCalled {
		t.Error("Exec must NOT be called when blocked")
	}
	if *h.exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", *h.exitCode)
	}
	if len(h.audit.entries) != 1 || h.audit.entries[0].AdvisoryID != "GHSA-X" {
		t.Errorf("expected audit entry with AdvisoryID, got %+v", h.audit.entries)
	}
}

func TestRunner_OverrideRequiresReason(t *testing.T) {
	t.Setenv("AEGIS_OVERRIDE", "allow")
	t.Setenv("AEGIS_OVERRIDE_REASON", "")
	h := newHarness(t)
	h.api.decision = &api.Decision{Decision: "block", Severity: "critical"}
	h.pm.installArgs = []PackageSpec{{Name: "p", Version: "1.0.0", Raw: "p@1.0.0"}}

	if err := h.runner.Run([]string{"install", "p@1.0.0"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if h.pm.execCalled {
		t.Error("override without reason must NOT proceed")
	}
	if *h.exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", *h.exitCode)
	}
	if !strings.Contains(h.out.String(), "AEGIS_OVERRIDE_REASON required") {
		t.Errorf("expected refusal message, got:\n%s", h.out.String())
	}
}

func TestRunner_OverrideWithReasonProceeds(t *testing.T) {
	t.Setenv("AEGIS_OVERRIDE", "allow")
	t.Setenv("AEGIS_OVERRIDE_REASON", "hotfix-123")
	h := newHarness(t)
	h.api.decision = &api.Decision{Decision: "block", Severity: "critical"}
	h.pm.installArgs = []PackageSpec{{Name: "p", Version: "1.0.0", Raw: "p@1.0.0"}}

	if err := h.runner.Run([]string{"install", "p@1.0.0"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !h.pm.execCalled {
		t.Error("override with reason should proceed to Exec")
	}
	if *h.exitCode != -1 {
		t.Errorf("expected no exit, got %d", *h.exitCode)
	}
	if len(h.audit.entries) != 1 || !h.audit.entries[0].OverrideUsed || h.audit.entries[0].OverrideReason != "hotfix-123" {
		t.Errorf("expected audit entry with override+reason, got %+v", h.audit.entries)
	}
}

func TestRunner_PromptInTTY_UserAllows(t *testing.T) {
	h := newHarness(t)
	h.confirm.result = prompt.ResultAllowed
	h.api.decision = &api.Decision{Decision: "prompt", Severity: "high"}
	h.pm.installArgs = []PackageSpec{{Name: "p", Version: "1.0.0", Raw: "p@1.0.0"}}

	if err := h.runner.Run([]string{"install", "p@1.0.0"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if h.confirm.calls != 1 {
		t.Errorf("expected 1 prompt call, got %d", h.confirm.calls)
	}
	if !h.pm.execCalled {
		t.Error("user-allowed prompt should proceed to Exec")
	}
	if *h.exitCode != -1 {
		t.Errorf("expected no exit, got %d", *h.exitCode)
	}
}

func TestRunner_PromptInTTY_UserDenies(t *testing.T) {
	h := newHarness(t)
	h.confirm.result = prompt.ResultDenied
	h.api.decision = &api.Decision{Decision: "prompt", Severity: "high"}
	h.pm.installArgs = []PackageSpec{{Name: "p", Version: "1.0.0", Raw: "p@1.0.0"}}

	if err := h.runner.Run([]string{"install", "p@1.0.0"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if *h.exitCode != 1 {
		t.Errorf("expected exit code 1 after deny, got %d", *h.exitCode)
	}
	if h.pm.execCalled {
		t.Error("denied prompt must NOT proceed")
	}
}

func TestRunner_PromptInCI_PromotedToBlock(t *testing.T) {
	h := newHarness(t)
	h.runner.isCI = func() bool { return true }
	h.api.decision = &api.Decision{Decision: "prompt", Severity: "high"}
	h.pm.installArgs = []PackageSpec{{Name: "p", Version: "1.0.0", Raw: "p@1.0.0"}}

	if err := h.runner.Run([]string{"install", "p@1.0.0"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if h.confirm.calls != 0 {
		t.Errorf("CI mode must NOT prompt, got %d calls", h.confirm.calls)
	}
	if *h.exitCode != 1 {
		t.Errorf("expected exit code 1 in CI prompt, got %d", *h.exitCode)
	}
	if !strings.Contains(h.out.String(), "CI detected") {
		t.Errorf("expected CI promotion message, got:\n%s", h.out.String())
	}
}

func TestRunner_PromptNoTTY_PromotedToBlock(t *testing.T) {
	h := newHarness(t)
	h.confirm.result = prompt.ResultUnavailable
	h.api.decision = &api.Decision{Decision: "prompt", Severity: "high"}
	h.pm.installArgs = []PackageSpec{{Name: "p", Version: "1.0.0", Raw: "p@1.0.0"}}

	if err := h.runner.Run([]string{"install", "p@1.0.0"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if *h.exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", *h.exitCode)
	}
	if !strings.Contains(h.out.String(), "no TTY") {
		t.Errorf("expected no-TTY message, got:\n%s", h.out.String())
	}
}

func TestRunner_NonRegistrySkipsCheck(t *testing.T) {
	h := newHarness(t)
	h.pm.installArgs = []PackageSpec{{Raw: "./local", NonRegistry: true}}

	if err := h.runner.Run([]string{"install", "./local"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if h.api.calls != 0 {
		t.Errorf("non-registry must skip API check, got %d calls", h.api.calls)
	}
	if !h.pm.execCalled {
		t.Error("Exec should still run for non-registry installs")
	}
	if !strings.Contains(h.out.String(), "passthrough") {
		t.Errorf("expected passthrough message, got:\n%s", h.out.String())
	}
}

func TestRunner_ExactVersionSkipsResolve(t *testing.T) {
	h := newHarness(t)
	h.pm.installArgs = []PackageSpec{{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}}

	if err := h.runner.Run([]string{"install", "lodash@4.17.21"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if h.resolver.calls != 0 {
		t.Errorf("exact version must skip resolver, got %d calls", h.resolver.calls)
	}
}

func TestRunner_RangeTriggersResolve(t *testing.T) {
	h := newHarness(t)
	h.resolver.ret = "4.17.21"
	h.pm.installArgs = []PackageSpec{{Name: "lodash", Version: "^4.17.0", Raw: "lodash@^4.17.0"}}

	if err := h.runner.Run([]string{"install", "lodash@^4.17.0"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if h.resolver.calls != 1 {
		t.Errorf("range must trigger resolver, got %d calls", h.resolver.calls)
	}
}

func TestRunner_APIErrorFailsOpen(t *testing.T) {
	h := newHarness(t)
	h.api.err = errors.New("boom")
	h.pm.installArgs = []PackageSpec{{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}}

	if err := h.runner.Run([]string{"install", "lodash@4.17.21"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !h.pm.execCalled {
		t.Error("API error must fail open — Exec should still run")
	}
	if *h.exitCode != -1 {
		t.Errorf("expected no exit on API error, got %d", *h.exitCode)
	}
	if !strings.Contains(h.out.String(), "passing through") {
		t.Errorf("expected fail-open message, got:\n%s", h.out.String())
	}
	if len(h.audit.entries) != 1 || h.audit.entries[0].Source != "error" {
		t.Errorf("expected audit error entry, got %+v", h.audit.entries)
	}
}

func TestRunner_CacheHitSkipsAPI(t *testing.T) {
	h := newHarness(t)
	h.pm.installArgs = []PackageSpec{{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}}
	// Pre-populate cache.
	h.cache.Put(cache.Key("npm", "lodash", "4.17.21"),
		&api.Decision{Decision: "allow", Severity: "info"}, time.Minute)

	if err := h.runner.Run([]string{"install", "lodash@4.17.21"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if h.api.calls != 0 {
		t.Errorf("cache hit must skip API, got %d calls", h.api.calls)
	}
	if !h.pm.execCalled {
		t.Error("Exec should still run after allow")
	}
	if !strings.Contains(h.out.String(), "(cached)") {
		t.Errorf("expected (cached) marker in output, got:\n%s", h.out.String())
	}
	if len(h.audit.entries) != 1 || h.audit.entries[0].Source != "cache" {
		t.Errorf("expected audit source=cache, got %+v", h.audit.entries)
	}
}

type countingResolver struct {
	calls int
	ret   string
	err   error
}

func (c *countingResolver) Resolve(_ context.Context, _, _ string) (string, error) {
	c.calls++
	return c.ret, c.err
}
