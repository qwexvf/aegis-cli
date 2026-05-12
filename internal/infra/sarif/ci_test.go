package sarif_test

import (
	"encoding/json"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/sarif"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func TestCIToSARIF_Structure(t *testing.T) {
	result := usecase.CIResult{
		ProjectName: "my-project",
		Findings: []usecase.CIFinding{
			{
				Dep: domain.Dependency{
					Ecosystem: domain.EcoNpm,
					Name:      "lodash",
					Version:   "4.17.20",
				},
				Risk: domain.RiskAssessment{
					Score: 70,
					Flags: []domain.RiskFlag{
						{Code: "install-hook-suspicious", Detail: "curl|sh in postinstall", Weight: 70},
						{Code: "obfuscated-payload", Detail: "eval(atob(...)) found", Weight: 60},
					},
				},
				Verdict: domain.VerdictBlock,
			},
		},
		Passed: false,
	}
	log := sarif.CIToSARIF(result, "0.1.0-test")

	if log.Version != sarif.Version210 {
		t.Errorf("version: got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs: got %d want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "aegis-cli" {
		t.Errorf("tool name: %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) == 0 {
		t.Error("rules should be populated")
	}
	// 2 flags → 2 results
	if len(run.Results) != 2 {
		t.Fatalf("results: got %d want 2", len(run.Results))
	}
	r := run.Results[0]
	if r.RuleID != "install-hook-suspicious" {
		t.Errorf("ruleId: got %q", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("weight 70 → level: got %q want error", r.Level)
	}
	// LogicalLocation carries ecosystem:name@version
	if len(r.Locations) == 0 {
		t.Fatal("no locations")
	}
	lls := r.Locations[0].LogicalLocations
	if len(lls) == 0 || lls[0].FullyQualifiedName != "npm:lodash@4.17.20" {
		t.Errorf("logicalLocation: got %v", lls)
	}
}

func TestCIToSARIF_SuppressedFlag(t *testing.T) {
	result := usecase.CIResult{
		Findings: []usecase.CIFinding{
			{
				Dep: domain.Dependency{Ecosystem: domain.EcoNpm, Name: "pkg", Version: "1.0.0"},
				Risk: domain.RiskAssessment{
					Flags: []domain.RiskFlag{
						{Code: "typosquat-risk", Detail: "lodash variant", Weight: 40,
							Suppressed: true, SuppressBy: "known safe fork"},
					},
				},
				Verdict: domain.VerdictSafe,
			},
		},
	}
	log := sarif.CIToSARIF(result, "")
	r := log.Runs[0].Results[0]
	if len(r.Suppressions) == 0 {
		t.Error("want suppressions for suppressed flag")
	}
	if r.Suppressions[0].Justification != "known safe fork" {
		t.Errorf("justification: %q", r.Suppressions[0].Justification)
	}
}

func TestCIToSARIF_ValidJSON(t *testing.T) {
	log := sarif.CIToSARIF(usecase.CIResult{}, "1.0.0")
	b, err := sarif.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestCIToSARIF_WeightToLevel(t *testing.T) {
	cases := []struct {
		weight int
		want   string
	}{
		{100, "error"},
		{60, "error"},
		{59, "warning"},
		{30, "warning"},
		{29, "note"},
		{0, "note"},
	}
	for _, tc := range cases {
		result := usecase.CIResult{
			Findings: []usecase.CIFinding{{
				Dep:  domain.Dependency{Ecosystem: domain.EcoNpm, Name: "x", Version: "1.0"},
				Risk: domain.RiskAssessment{Flags: []domain.RiskFlag{{Code: "c", Detail: "d", Weight: tc.weight}}},
			}},
		}
		log := sarif.CIToSARIF(result, "")
		got := log.Runs[0].Results[0].Level
		if got != tc.want {
			t.Errorf("weight %d → level: got %q want %q", tc.weight, got, tc.want)
		}
	}
}
