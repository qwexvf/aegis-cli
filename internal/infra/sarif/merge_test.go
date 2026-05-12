package sarif_test

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/sarif"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func TestMergedToSARIF(t *testing.T) {
	ciResult := usecase.CIResult{
		Findings: []usecase.CIFinding{{
			Dep:  domain.Dependency{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.20"},
			Risk: domain.RiskAssessment{Flags: []domain.RiskFlag{{Code: "typosquat-risk", Detail: "test", Weight: 40}}},
		}},
	}
	actionsResult := usecase.ActionsScanResult{
		Findings: []domain.WorkflowFinding{{
			Kind:     domain.FindingUnpinnedRef,
			Severity: domain.SevMedium,
			File:     ".github/workflows/ci.yml",
			Line:     10,
			Message:  "unpinned",
		}},
	}
	log := sarif.MergedToSARIF(ciResult, actionsResult, "1.0.0", "")

	if len(log.Runs) != 2 {
		t.Fatalf("want 2 runs, got %d", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "aegis-cli/packages" {
		t.Errorf("run[0] name: got %q", log.Runs[0].Tool.Driver.Name)
	}
	if log.Runs[1].Tool.Driver.Name != "aegis-cli/actions" {
		t.Errorf("run[1] name: got %q", log.Runs[1].Tool.Driver.Name)
	}
	if len(log.Runs[0].Results) != 1 {
		t.Errorf("run[0] results: got %d want 1", len(log.Runs[0].Results))
	}
	if len(log.Runs[1].Results) != 1 {
		t.Errorf("run[1] results: got %d want 1", len(log.Runs[1].Results))
	}

	// Valid JSON
	b, err := sarif.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) == 0 {
		t.Error("empty SARIF output")
	}
}
