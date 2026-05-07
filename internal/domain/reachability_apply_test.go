package domain

import (
	"testing"
)

func TestDowngradeUnused_SuppressesNonInstallFlags(t *testing.T) {
	ra := RiskAssessment{
		Score: 50,
		Flags: []RiskFlag{
			{Code: "shell-spawn", Detail: "spawns subprocess", Weight: 20},
			{Code: "install-hook", Detail: "postinstall", Weight: 30},
		},
	}
	out := ra.DowngradeUnused(ReachabilityUnused, true)
	if out.Score != 30 {
		t.Errorf("want score 30 (only install-hook contributing), got %d", out.Score)
	}
	if !out.Flags[0].Suppressed {
		t.Error("shell-spawn should be suppressed")
	}
	if out.Flags[1].Suppressed {
		t.Error("install-hook should NOT be suppressed (install-phase exempt)")
	}
	if out.Flags[0].SuppressBy != unreachableSuppressReason {
		t.Errorf("SuppressBy = %q, want %q", out.Flags[0].SuppressBy, unreachableSuppressReason)
	}
}

func TestDowngradeUnused_NoopWhenSuppressFalse(t *testing.T) {
	ra := RiskAssessment{
		Score: 20,
		Flags: []RiskFlag{{Code: "shell-spawn", Weight: 20}},
	}
	out := ra.DowngradeUnused(ReachabilityUnused, false)
	if out.Score != 20 || out.Flags[0].Suppressed {
		t.Errorf("suppress=false should be noop, got %+v", out)
	}
}

func TestDowngradeUnused_NoopWhenReachable(t *testing.T) {
	ra := RiskAssessment{
		Score: 20,
		Flags: []RiskFlag{{Code: "shell-spawn", Weight: 20}},
	}
	out := ra.DowngradeUnused(ReachabilityUsed, true)
	if out.Score != 20 || out.Flags[0].Suppressed {
		t.Errorf("Used should be noop, got %+v", out)
	}
}

func TestDowngradeUnused_SkipsAlreadySuppressed(t *testing.T) {
	ra := RiskAssessment{
		Score: 0,
		Flags: []RiskFlag{
			{Code: "shell-spawn", Weight: 20, Suppressed: true, SuppressBy: "allowlist"},
		},
	}
	out := ra.DowngradeUnused(ReachabilityUnused, true)
	if out.Flags[0].SuppressBy != "allowlist" {
		t.Error("already-suppressed flag must keep its allowlist reason")
	}
	if out.Score != 0 {
		t.Errorf("score should remain 0, got %d", out.Score)
	}
}
