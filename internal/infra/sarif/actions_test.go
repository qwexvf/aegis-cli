package sarif_test

import (
	"encoding/json"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/sarif"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func TestActionsToSARIF_Structure(t *testing.T) {
	result := usecase.ActionsScanResult{
		Workflows: 2,
		Findings: []domain.WorkflowFinding{
			{
				Kind:     domain.FindingUnpinnedRef,
				Severity: domain.SevMedium,
				File:     ".github/workflows/ci.yml",
				Line:     10,
				Message:  "actions/checkout@v4 not pinned",
			},
			{
				Kind:     domain.FindingPullRequestTargetCheckout,
				Severity: domain.SevCritical,
				File:     ".github/workflows/pr.yml",
				Line:     5,
				Message:  "pr_target + checkout",
			},
		},
		Passed: false,
	}
	log := sarif.ActionsToSARIF(result, "0.1.0-test", "")

	if log.Version != sarif.Version210 {
		t.Errorf("version: got %q want %q", log.Version, sarif.Version210)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs: got %d want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "aegis-cli" {
		t.Errorf("tool name: got %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "0.1.0-test" {
		t.Errorf("tool version: got %q", run.Tool.Driver.Version)
	}
	if len(run.Results) != 2 {
		t.Fatalf("results: got %d want 2", len(run.Results))
	}
	// Medium severity → warning
	if run.Results[0].Level != "warning" {
		t.Errorf("medium→SARIF level: got %q want warning", run.Results[0].Level)
	}
	// Critical → error
	if run.Results[1].Level != "error" {
		t.Errorf("critical→SARIF level: got %q want error", run.Results[1].Level)
	}
	// Rule IDs match finding kinds
	if run.Results[0].RuleID != domain.FindingUnpinnedRef.String() {
		t.Errorf("ruleId: got %q", run.Results[0].RuleID)
	}
	// Location is set
	loc := run.Results[0].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != ".github/workflows/ci.yml" {
		t.Errorf("uri: got %q", loc.ArtifactLocation.URI)
	}
	if loc.Region.StartLine != 10 {
		t.Errorf("startLine: got %d want 10", loc.Region.StartLine)
	}
}

func TestActionsToSARIF_SuppressedFinding(t *testing.T) {
	result := usecase.ActionsScanResult{
		Findings: []domain.WorkflowFinding{
			{
				Kind:       domain.FindingUnpinnedRef,
				Severity:   domain.SevMedium,
				File:       ".github/workflows/ci.yml",
				Line:       1,
				Suppressed: true,
				SuppressBy: "audited via dependabot",
			},
		},
	}
	log := sarif.ActionsToSARIF(result, "", "")
	r := log.Runs[0].Results[0]
	if len(r.Suppressions) == 0 {
		t.Fatal("want suppressions entry for suppressed finding")
	}
	if r.Suppressions[0].Justification != "audited via dependabot" {
		t.Errorf("justification: got %q", r.Suppressions[0].Justification)
	}
}

func TestActionsToSARIF_ValidJSON(t *testing.T) {
	result := usecase.ActionsScanResult{
		Findings: []domain.WorkflowFinding{
			{Kind: domain.FindingWriteAllPermissions, Severity: domain.SevHigh, File: "a.yml", Line: 1, Message: "test"},
		},
	}
	log := sarif.ActionsToSARIF(result, "1.0.0", "")
	b, err := sarif.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if raw["version"] != sarif.Version210 {
		t.Errorf("JSON version: got %v", raw["version"])
	}
}

func TestActionsToSARIF_EmptyResult(t *testing.T) {
	log := sarif.ActionsToSARIF(usecase.ActionsScanResult{}, "1.0.0", "")
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("expected no results for empty input")
	}
}

func TestActionsToSARIF_RulesPopulated(t *testing.T) {
	log := sarif.ActionsToSARIF(usecase.ActionsScanResult{}, "1.0.0", "")
	if len(log.Runs[0].Tool.Driver.Rules) == 0 {
		t.Error("rules should be populated even with no findings")
	}
}

func TestActionsToSARIF_RelativeURI(t *testing.T) {
	result := usecase.ActionsScanResult{
		Findings: []domain.WorkflowFinding{{
			Kind:     domain.FindingUnpinnedRef,
			Severity: domain.SevMedium,
			File:     "/home/user/project/.github/workflows/ci.yml",
			Line:     1,
			Message:  "test",
		}},
	}
	log := sarif.ActionsToSARIF(result, "", "/home/user/project")
	uri := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri != ".github/workflows/ci.yml" {
		t.Errorf("relativeURI: got %q want .github/workflows/ci.yml", uri)
	}
}

func TestActionsToSARIF_SeverityLevels(t *testing.T) {
	severities := []struct {
		sev  domain.Severity
		want string
	}{
		{domain.SevCritical, "error"},
		{domain.SevHigh, "error"},
		{domain.SevMedium, "warning"},
		{domain.SevLow, "note"},
	}
	for _, tc := range severities {
		result := usecase.ActionsScanResult{
			Findings: []domain.WorkflowFinding{{
				Kind: domain.FindingUnpinnedRef, Severity: tc.sev,
				File: "a.yml", Line: 1, Message: "x",
			}},
		}
		log := sarif.ActionsToSARIF(result, "", "")
		got := log.Runs[0].Results[0].Level
		if got != tc.want {
			t.Errorf("severity %s → level: got %q want %q", tc.sev, got, tc.want)
		}
	}
}
