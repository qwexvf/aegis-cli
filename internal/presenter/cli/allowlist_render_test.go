package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

func allowlistPresenterTest(t *testing.T) (*AllowlistPresenter, *bytes.Buffer) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	buf := &bytes.Buffer{}
	return NewAllowlistPresenter(NewWith(buf)), buf
}

func TestAllowlistPresenter_ListEmpty(t *testing.T) {
	ap, buf := allowlistPresenterTest(t)
	ap.OnList(nil)
	if !strings.Contains(buf.String(), "no rules") {
		t.Errorf("expected 'no rules', got:\n%s", buf.String())
	}
}

func TestAllowlistPresenter_ListShowsTable(t *testing.T) {
	ap, buf := allowlistPresenterTest(t)
	ap.OnList([]domain.AllowRule{
		{Ecosystem: domain.EcoNpm, Name: "lodash", VersionRange: "^4",
			Capability: domain.CapDynamicEval, Source: "builtin", Reason: "tpl"},
		{Ecosystem: domain.EcoNpm, Name: "*", Source: "user", Reason: "team-trusted"},
	})
	out := buf.String()
	for _, want := range []string{
		"ECO", "NAME", "VERSION", "CAPABILITY", "SOURCE", "REASON",
		"npm", "lodash", "^4", "dynamic-eval", "builtin", "tpl",
		"team-trusted", "user", "*",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAllowlistPresenter_TestNoMatches(t *testing.T) {
	ap, buf := allowlistPresenterTest(t)
	ap.OnTest(domain.EcoNpm, "lodash", "4.17.21", nil)
	out := buf.String()
	if !strings.Contains(out, "lodash@4.17.21") || !strings.Contains(out, "no allowlist rules apply") {
		t.Errorf("missing test output:\n%s", out)
	}
}

func TestAllowlistPresenter_TestShowsMatches(t *testing.T) {
	ap, buf := allowlistPresenterTest(t)
	ap.OnTest(domain.EcoNpm, "lodash", "4.17.21", []MatchedRule{
		{
			Capability: domain.CapDynamicEval,
			Rule: domain.AllowRule{
				Ecosystem: domain.EcoNpm, Name: "lodash", Capability: domain.CapDynamicEval,
				Reason: "tpl compiler", Source: "builtin",
			},
		},
	})
	out := buf.String()
	for _, want := range []string{"lodash@4.17.21", "dynamic-eval", "tpl compiler", "builtin"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestAllowlistPresenter_RuleAdded(t *testing.T) {
	ap, buf := allowlistPresenterTest(t)
	ap.OnRuleAdded("user", domain.AllowRule{
		Ecosystem: domain.EcoNpm, Name: "x", Capability: domain.CapShellSpawn, Reason: "ok",
	})
	if !strings.Contains(buf.String(), "added user rule") || !strings.Contains(buf.String(), "shell-spawn") {
		t.Errorf("missing add line:\n%s", buf.String())
	}
}

func TestAllowlistPresenter_RuleRemoved(t *testing.T) {
	ap, buf := allowlistPresenterTest(t)
	ap.OnRuleRemoved("user", 3)
	if !strings.Contains(buf.String(), "removed 3") || !strings.Contains(buf.String(), "user") {
		t.Errorf("missing removed line:\n%s", buf.String())
	}
}

func TestSnapshotPresenter_SuppressedFlagShownWithMarker(t *testing.T) {
	// Suppressed flags must use ~ marker and show
	// "(suppressed +N, allowlisted: ...)".
	sp, buf := snapshotPresenterTest(t)
	old := domain.Dependency{Name: "lodash", Version: "4.17.20"}
	new_ := domain.Dependency{Name: "lodash", Version: "4.17.21"}
	sp.OnSnapshotDiff(diffReportFromUpgrade(old, new_, domain.VerdictSafe,
		domain.RiskAssessment{
			Score: 0,
			Flags: []domain.RiskFlag{{
				Code:       "dynamic-eval",
				Detail:     "constructs and runs code dynamically",
				Weight:     domain.WeightDynamicEval,
				Suppressed: true,
				SuppressBy: "lodash._.template compiles via Function()",
			}},
		},
		domain.RiskAssessment{},
	))
	out := buf.String()
	if !strings.Contains(out, "~ dynamic-eval") {
		t.Errorf("expected ~ marker on suppressed flag:\n%s", out)
	}
	if !strings.Contains(out, "(suppressed +25, allowlisted: lodash._.template") {
		t.Errorf("expected (suppressed +N, allowlisted: ...) suffix:\n%s", out)
	}
}

func TestSnapshotPresenter_SuppressedFlagAccompaniedByActiveFlag(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	old := domain.Dependency{Name: "p", Version: "1.0.0"}
	new_ := domain.Dependency{Name: "p", Version: "1.0.1"}
	sp.OnSnapshotDiff(diffReportFromUpgrade(old, new_, domain.VerdictReview,
		domain.RiskAssessment{
			Score: domain.WeightShellSpawn, // shell-spawn active
			Flags: []domain.RiskFlag{
				{Code: "dynamic-eval", Weight: domain.WeightDynamicEval, Suppressed: true, SuppressBy: "x"},
				{Code: "shell-spawn", Weight: domain.WeightShellSpawn},
			},
		},
		domain.RiskAssessment{},
	))
	out := buf.String()
	if !strings.Contains(out, "~ dynamic-eval") {
		t.Error("suppressed flag should use ~")
	}
	if !strings.Contains(out, "+ shell-spawn") {
		t.Error("active flag should still use +")
	}
}
