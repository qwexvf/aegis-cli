package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// presenterTest builds a Presenter pointed at a buffer with NO_COLOR
// set so output is deterministic for snapshot-style assertions.
func presenterTest(t *testing.T) (*Presenter, *bytes.Buffer) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	buf := &bytes.Buffer{}
	return NewWith(buf), buf
}

func decision(name, ver string, kind domain.DecisionKind) domain.Decision {
	return domain.Decision{
		Spec:     domain.PackageSpec{Ecosystem: domain.EcoNpm, Name: name, Version: ver},
		Resolved: ver,
		Kind:     kind,
		Severity: domain.SevCritical,
		Source:   domain.SourceAPI,
	}
}

func TestPresenter_AllowLine(t *testing.T) {
	p, buf := presenterTest(t)
	d := decision("lodash", "4.17.21", domain.DecisionAllow)
	d.Severity = domain.SevInfo
	p.OnDecision(d)
	if !strings.Contains(buf.String(), "lodash@4.17.21") || !strings.Contains(buf.String(), "✓ allowed") {
		t.Errorf("missing allow markers:\n%s", buf.String())
	}
}

func TestPresenter_BlockShowsAdvisoryAndRefs(t *testing.T) {
	p, buf := presenterTest(t)
	d := decision("ua-parser-js", "0.7.29", domain.DecisionBlock)
	d.Reasons = []domain.Reason{{Category: "credential-theft", Detail: "reads /etc/shadow"}}
	d.Incident = &domain.Incident{
		AdvisoryID: "GHSA-pjwm-rvh2-c87w",
		Date:       "2021-10",
		Summary:    "ua-parser-js compromise",
		References: []string{"https://github.com/advisories/GHSA-pjwm-rvh2-c87w"},
	}
	p.OnDecision(d)
	out := buf.String()
	for _, want := range []string{
		"BLOCKED (CRITICAL)",
		"advisory: GHSA-pjwm-rvh2-c87w",
		"incident: 2021-10",
		"summary:  ua-parser-js compromise",
		"credential-theft — reads /etc/shadow",
		"refs:",
		"https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPresenter_OutcomeBlockShowsOverrideHint(t *testing.T) {
	p, buf := presenterTest(t)
	o := domain.Outcome{
		Decision: decision("p", "1.0.0", domain.DecisionBlock),
		Action:   domain.ActionBlock,
	}
	p.OnOutcome(o, "npm", "install")
	if !strings.Contains(buf.String(), "AEGIS_OVERRIDE=allow AEGIS_OVERRIDE_REASON=<reason> aegis npm install p@1.0.0") {
		t.Errorf("missing override hint:\n%s", buf.String())
	}
}

func TestPresenter_OutcomeBlockOnPromptPromotionHidesOverrideHint(t *testing.T) {
	p, buf := presenterTest(t)
	o := domain.Outcome{
		Decision:           decision("p", "1.0.0", domain.DecisionPrompt),
		Action:             domain.ActionBlock,
		PromotedFromPrompt: true,
	}
	p.OnOutcome(o, "npm", "install")
	if strings.Contains(buf.String(), "override:") {
		t.Errorf("override hint should not appear on promoted prompt:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "promoted to block") {
		t.Errorf("expected promotion message:\n%s", buf.String())
	}
}

func TestPresenter_OutcomeOverrideUsedAudited(t *testing.T) {
	p, buf := presenterTest(t)
	o := domain.Outcome{
		Decision:       decision("p", "1.0.0", domain.DecisionBlock),
		Action:         domain.ActionProceed,
		OverrideUsed:   true,
		OverrideReason: "hotfix",
	}
	p.OnOutcome(o, "npm", "install")
	if !strings.Contains(buf.String(), "AEGIS_OVERRIDE=allow set") || !strings.Contains(buf.String(), `"hotfix"`) {
		t.Errorf("missing override audit line:\n%s", buf.String())
	}
}

func TestPresenter_OutcomeUserAllowed(t *testing.T) {
	p, buf := presenterTest(t)
	o := domain.Outcome{
		Decision:       decision("p", "1.0.0", domain.DecisionPrompt),
		Action:         domain.ActionProceed,
		OverrideUsed:   true,
		OverrideReason: "user-allowed",
	}
	p.OnOutcome(o, "npm", "install")
	if !strings.Contains(buf.String(), "user allowed") {
		t.Errorf("missing user-allowed line:\n%s", buf.String())
	}
}

func TestPresenter_ResolveStartCachedSuffix(t *testing.T) {
	p, buf := presenterTest(t)
	p.OnResolveStart(domain.PackageSpec{Name: "lodash"}, "4.17.21", true)
	if !strings.Contains(buf.String(), "(cached)") {
		t.Errorf("expected cached marker:\n%s", buf.String())
	}
}

func TestPresenter_Skipped(t *testing.T) {
	p, buf := presenterTest(t)
	p.OnSkipped(domain.PackageSpec{Raw: "./local"})
	if !strings.Contains(buf.String(), "passthrough: ./local") {
		t.Errorf("missing passthrough message:\n%s", buf.String())
	}
}
