package domain

import "testing"

// helper: a "lodash dynamic-eval" risk assessment.
func lodashEvalAssessment() RiskAssessment {
	return RiskAssessment{
		Score: WeightDynamicEval,
		Flags: []RiskFlag{
			{Code: "dynamic-eval", Detail: "constructs and runs code dynamically (eval/Function)", Weight: WeightDynamicEval},
		},
	}
}

func TestApplyAllowlist_EmptySetReturnsUnchanged(t *testing.T) {
	in := lodashEvalAssessment()
	out := in.ApplyAllowlist(EcoNpm, "lodash", "4.17.21", EmptyAllowSet())
	if out.Score != in.Score || out.Flags[0].Suppressed {
		t.Errorf("empty set must not alter assessment: %+v", out)
	}
}

func TestApplyAllowlist_NonMatchingRuleNoChange(t *testing.T) {
	set := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "react", Capability: CapDynamicEval, Reason: "x"})
	in := lodashEvalAssessment()
	out := in.ApplyAllowlist(EcoNpm, "lodash", "4.17.21", set)
	if out.Score != in.Score || out.Flags[0].Suppressed {
		t.Errorf("non-matching rule must not alter assessment: %+v", out)
	}
}

func TestApplyAllowlist_MatchingRuleSuppressesAndZerosScore(t *testing.T) {
	set := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval, Reason: "tpl"})
	in := lodashEvalAssessment()
	out := in.ApplyAllowlist(EcoNpm, "lodash", "4.17.21", set)

	if out.Score != 0 {
		t.Errorf("expected score 0 after suppression, got %d", out.Score)
	}
	if !out.Flags[0].Suppressed {
		t.Error("flag should be marked Suppressed")
	}
	if out.Flags[0].SuppressBy != "tpl" {
		t.Errorf("SuppressBy = %q, want %q", out.Flags[0].SuppressBy, "tpl")
	}
	// Original is untouched.
	if in.Score == 0 || in.Flags[0].Suppressed {
		t.Error("original assessment must not be mutated")
	}
}

func TestApplyAllowlist_PartialSuppressionLeavesOtherFlags(t *testing.T) {
	in := RiskAssessment{
		Score: WeightShellSpawn + WeightDynamicEval,
		Flags: []RiskFlag{
			{Code: "shell-spawn", Detail: "x", Weight: WeightShellSpawn},
			{Code: "dynamic-eval", Detail: "y", Weight: WeightDynamicEval},
		},
	}
	set := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval, Reason: "tpl"})
	out := in.ApplyAllowlist(EcoNpm, "lodash", "4.17.21", set)

	if out.Score != WeightShellSpawn {
		t.Errorf("score = %d, want %d (only dynamic-eval suppressed)", out.Score, WeightShellSpawn)
	}
	if out.Flags[0].Suppressed {
		t.Error("shell-spawn should NOT be suppressed")
	}
	if !out.Flags[1].Suppressed {
		t.Error("dynamic-eval should be suppressed")
	}
}

func TestApplyAllowlist_AllSuppressedPushesVerdictToSafe(t *testing.T) {
	// Realistic full lodash payload would otherwise reach review/prompt.
	in := RiskAssessment{
		Score: WeightDynamicEval + WeightInstallHook,
		Flags: []RiskFlag{
			{Code: "dynamic-eval", Weight: WeightDynamicEval},
			{Code: "install-hook", Weight: WeightInstallHook},
		},
	}
	set := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "*", Capability: CapDynamicEval, Reason: "tpl"},
		AllowRule{Ecosystem: EcoNpm, Name: "*", Capability: CapInstallHookExec, Reason: "build"},
	)
	out := in.ApplyAllowlist(EcoNpm, "lodash", "4.17.21", set)
	if out.Score != 0 {
		t.Errorf("score should be 0 after suppressing all flags, got %d", out.Score)
	}
	if Verdict(out, RiskAssessment{}) != VerdictSafe {
		t.Error("verdict should drop to safe after allowlist")
	}
}

func TestApplyAllowlist_DriftCapabilityAddedFlagSuppressed(t *testing.T) {
	// "capability-added" is a drift flag; the Capability is encoded
	// in Detail. Allowlist must still match it.
	in := RiskAssessment{
		Score: WeightCapabilityAdd,
		Flags: []RiskFlag{
			{Code: "capability-added",
				Detail: "new capability since prior version: shell-spawn",
				Weight: WeightCapabilityAdd},
		},
	}
	set := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "esbuild", Capability: CapShellSpawn, Reason: "build tool"})
	out := in.ApplyAllowlist(EcoNpm, "esbuild", "0.20.0", set)
	if out.Score != 0 || !out.Flags[0].Suppressed {
		t.Errorf("capability-added should match via Detail parse: %+v", out)
	}
}

func TestApplyAllowlist_SizeAnomalyNeverSuppressed(t *testing.T) {
	in := RiskAssessment{
		Score: WeightSizeAnomaly,
		Flags: []RiskFlag{
			{Code: "size-anomaly", Detail: "doubled", Weight: WeightSizeAnomaly},
		},
	}
	// Wide-open allow rule shouldn't touch size-anomaly (it's a drift
	// signal not tied to any Capability).
	set := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "*", Reason: "wide-open"})
	out := in.ApplyAllowlist(EcoNpm, "p", "1.0.0", set)
	if out.Score != WeightSizeAnomaly || out.Flags[0].Suppressed {
		t.Errorf("size-anomaly should not be allowlist-able: %+v", out)
	}
}

func TestApplyAllowlist_EnvCredReadCode(t *testing.T) {
	in := RiskAssessment{
		Score: WeightEnvCredRead,
		Flags: []RiskFlag{
			{Code: "env-cred-read", Detail: "AWS_ACCESS_KEY_ID", Weight: WeightEnvCredRead},
		},
	}
	set := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "deploy-tool", Capability: CapEnvRead, Reason: "uses AWS creds"})
	out := in.ApplyAllowlist(EcoNpm, "deploy-tool", "1.0.0", set)
	if out.Score != 0 || !out.Flags[0].Suppressed {
		t.Errorf("env-cred-read should map to CapEnvRead: %+v", out)
	}
}

func TestApplyAllowlist_AlreadySuppressedNotDoubleCounted(t *testing.T) {
	in := RiskAssessment{
		Score: 0, // already deducted
		Flags: []RiskFlag{
			{Code: "dynamic-eval", Weight: WeightDynamicEval, Suppressed: true, SuppressBy: "previous"},
		},
	}
	set := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval, Reason: "redundant"})
	out := in.ApplyAllowlist(EcoNpm, "lodash", "4.17.21", set)
	if out.Score != 0 {
		t.Errorf("already-suppressed flag must not deduct again, got Score=%d", out.Score)
	}
	if out.Flags[0].SuppressBy != "previous" {
		t.Errorf("first suppression should win, got SuppressBy=%q", out.Flags[0].SuppressBy)
	}
}

func TestApplyAllowlist_VersionConstraintHonored(t *testing.T) {
	set := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", VersionRange: "^4",
			Capability: CapDynamicEval, Reason: "v4 only"})

	// 4.17.21 — within constraint, suppressed.
	if out := lodashEvalAssessment().ApplyAllowlist(EcoNpm, "lodash", "4.17.21", set); out.Score != 0 {
		t.Errorf("4.17.21 should suppress, score=%d", out.Score)
	}
	// 5.0.0 — outside constraint, not suppressed.
	if out := lodashEvalAssessment().ApplyAllowlist(EcoNpm, "lodash", "5.0.0", set); out.Score == 0 {
		t.Error("5.0.0 outside ^4 should NOT suppress")
	}
}
