package usecase_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// writeWorkflow creates a .github/workflows/<name> file inside dir.
func writeWorkflow(t *testing.T, dir, name, body string) {
	t.Helper()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasKind(findings []domain.WorkflowFinding, kind domain.WorkflowFindingKind) bool {
	return slices.ContainsFunc(findings, func(f domain.WorkflowFinding) bool {
		return f.Kind == kind
	})
}

const cleanWorkflow = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0e58ed8671d6b60d0890c21b07f8835ace038e67
      - run: go test ./...
`

const prTargetCheckoutWorkflow = `on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`

const unpinnedWorkflow = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@v45
      - run: echo done
`

const writeAllWorkflow = `on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`

func TestActions_Scan_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	a := usecase.NewActions()
	res, err := a.Scan(usecase.ActionsScanRequest{ProjectDir: dir, FailOn: domain.SevHigh})
	if err != nil {
		t.Fatal(err)
	}
	if res.Workflows != 0 {
		t.Errorf("workflows: got %d want 0", res.Workflows)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings: got %v want none", res.Findings)
	}
	if !res.Passed {
		t.Error("empty dir should pass")
	}
}

func TestActions_Scan_CleanWorkflow(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", cleanWorkflow)
	a := usecase.NewActions()
	res, err := a.Scan(usecase.ActionsScanRequest{ProjectDir: dir, FailOn: domain.SevHigh})
	if err != nil {
		t.Fatal(err)
	}
	if res.Workflows != 1 {
		t.Errorf("workflows: got %d want 1", res.Workflows)
	}
	for _, f := range res.Findings {
		if f.Severity == domain.SevHigh || f.Severity == domain.SevCritical {
			t.Errorf("unexpected high/critical finding: %+v", f)
		}
	}
	if !res.Passed {
		t.Errorf("clean workflow should pass at high threshold; findings: %v", res.Findings)
	}
}

func TestActions_Scan_DetectsPullRequestTargetCheckout(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "pr.yml", prTargetCheckoutWorkflow)
	a := usecase.NewActions()
	res, err := a.Scan(usecase.ActionsScanRequest{ProjectDir: dir, FailOn: domain.SevHigh})
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Error("pr_target+checkout should fail")
	}
	if !hasKind(res.Findings, domain.FindingPullRequestTargetCheckout) {
		t.Errorf("expected FindingPullRequestTargetCheckout; got %v", res.Findings)
	}
}

func TestActions_Scan_DetectsUnpinnedRef(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "build.yml", unpinnedWorkflow)
	a := usecase.NewActions()
	res, err := a.Scan(usecase.ActionsScanRequest{ProjectDir: dir, FailOn: domain.SevHigh})
	if err != nil {
		t.Fatal(err)
	}
	if !hasKind(res.Findings, domain.FindingUnpinnedRef) {
		t.Errorf("expected FindingUnpinnedRef; got %v", res.Findings)
	}
	// tj-actions (third-party) should be High; actions/checkout should be Medium
	for _, f := range res.Findings {
		if f.Kind != domain.FindingUnpinnedRef || f.Ref == nil {
			continue
		}
		if f.Ref.Owner == "tj-actions" && f.Severity != domain.SevHigh {
			t.Errorf("tj-actions unpinned ref: got severity %q want high", f.Severity)
		}
	}
}

func TestActions_Scan_MultipleWorkflows(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "clean.yml", cleanWorkflow)
	writeWorkflow(t, dir, "vuln.yml", writeAllWorkflow)
	a := usecase.NewActions()
	res, err := a.Scan(usecase.ActionsScanRequest{ProjectDir: dir, FailOn: domain.SevHigh})
	if err != nil {
		t.Fatal(err)
	}
	if res.Workflows != 2 {
		t.Errorf("workflows: got %d want 2", res.Workflows)
	}
	if res.Passed {
		t.Error("should fail: vuln.yml has write-all permissions")
	}
}

func TestActions_Scan_FailOnThreshold(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "build.yml", unpinnedWorkflow)
	a := usecase.NewActions()

	// At critical threshold: unpinned refs (medium/high) should not fail
	res, err := a.Scan(usecase.ActionsScanRequest{ProjectDir: dir, FailOn: domain.SevCritical})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		t.Errorf("unpinned refs should pass at critical threshold; findings: %v", res.Findings)
	}

	// At medium threshold: should fail (tj-actions is high)
	res, err = a.Scan(usecase.ActionsScanRequest{ProjectDir: dir, FailOn: domain.SevMedium})
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Error("should fail at medium threshold with unpinned high-severity refs")
	}
}

func TestActions_Scan_IgnoreRuleSuppressesFinding(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "pr.yml", prTargetCheckoutWorkflow)
	ignore := domain.NewActionsIgnoreSet([]domain.ActionsIgnoreRule{
		{Kind: "pull_request_target_checkout", Reason: "reviewed, intentional"},
	})
	a := usecase.NewActions()
	res, err := a.Scan(usecase.ActionsScanRequest{
		ProjectDir: dir,
		FailOn:     domain.SevCritical,
		Ignore:     ignore,
	})
	if err != nil {
		t.Fatal(err)
	}
	// finding still present but suppressed
	suppressed := 0
	for _, f := range res.Findings {
		if f.Kind == domain.FindingPullRequestTargetCheckout {
			if !f.Suppressed {
				t.Error("finding should be suppressed")
			}
			if f.SuppressBy != "reviewed, intentional" {
				t.Errorf("SuppressBy: got %q want %q", f.SuppressBy, "reviewed, intentional")
			}
			suppressed++
		}
	}
	if suppressed == 0 {
		t.Error("expected at least one suppressed finding")
	}
	if !res.Passed {
		t.Error("suppressed finding should not fail the scan")
	}
}

func TestActions_Scan_IgnoreByFile(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "pr.yml", prTargetCheckoutWorkflow)
	writeWorkflow(t, dir, "other.yml", prTargetCheckoutWorkflow)
	// suppress only in pr.yml
	ignore := domain.NewActionsIgnoreSet([]domain.ActionsIgnoreRule{
		{Kind: "pull_request_target_checkout", File: "pr.yml", Reason: "ok"},
	})
	a := usecase.NewActions()
	res, err := a.Scan(usecase.ActionsScanRequest{
		ProjectDir: dir,
		FailOn:     domain.SevCritical,
		Ignore:     ignore,
	})
	if err != nil {
		t.Fatal(err)
	}
	// pr.yml finding: suppressed; other.yml finding: not suppressed
	for _, f := range res.Findings {
		if f.Kind != domain.FindingPullRequestTargetCheckout {
			continue
		}
		if filepath.Base(f.File) == "pr.yml" && !f.Suppressed {
			t.Error("pr.yml finding should be suppressed")
		}
		if filepath.Base(f.File) == "other.yml" && f.Suppressed {
			t.Error("other.yml finding should NOT be suppressed")
		}
	}
	if res.Passed {
		t.Error("other.yml finding not suppressed → should fail")
	}
}

func TestActions_Scan_SortedOutput(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "b.yml", unpinnedWorkflow)
	writeWorkflow(t, dir, "a.yml", writeAllWorkflow)
	ignore := domain.NewActionsIgnoreSet([]domain.ActionsIgnoreRule{
		{Kind: "write_all_permissions", Reason: "sort test"},
	})
	a := usecase.NewActions()
	res, err := a.Scan(usecase.ActionsScanRequest{ProjectDir: dir, Ignore: ignore})
	if err != nil {
		t.Fatal(err)
	}
	// sort order preserved
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i].File < res.Findings[i-1].File {
			t.Errorf("findings not sorted by file: %q before %q",
				res.Findings[i-1].File, res.Findings[i].File)
		}
	}
	// suppression state survives sort
	hasSuppressed := false
	for _, f := range res.Findings {
		if f.Suppressed {
			hasSuppressed = true
			break
		}
	}
	if !hasSuppressed {
		t.Error("suppressed findings should be preserved in sorted output")
	}
}
