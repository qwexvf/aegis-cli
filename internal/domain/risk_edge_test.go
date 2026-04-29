package domain

import (
	"strings"
	"testing"
)

// --- RiskScore edge cases ---------------------------------------------

func TestRiskScore_EmptyCapsButHookScored(t *testing.T) {
	// Hook by itself is enough to register on the risk side even
	// without any AST-derived capabilities.
	fp := analyzed(withHook(PhasePostInstall, "scripts.postinstall", "x"))
	r := RiskScore(fp)
	if r.Score != WeightInstallHook {
		t.Errorf("expected hook-only score %d, got %d", WeightInstallHook, r.Score)
	}
	if len(r.Flags) != 1 {
		t.Errorf("expected 1 flag, got %+v", r.Flags)
	}
}

func TestRiskScore_MultipleHooksScoredIndependently(t *testing.T) {
	fp := analyzed(
		withHook(PhasePreInstall, "scripts.preinstall", "a"),
		withHook(PhasePostInstall, "scripts.postinstall", "b"),
	)
	r := RiskScore(fp)
	if r.Score != 2*WeightInstallHook {
		t.Errorf("expected 2*hook, got %d (flags=%+v)", r.Score, r.Flags)
	}
	if len(r.Flags) != 2 {
		t.Errorf("expected 2 flags, got %d", len(r.Flags))
	}
}

func TestRiskScore_EnvReadWithoutCapabilityIgnored(t *testing.T) {
	// EnvReads are listed but the AST scanner didn't add CapEnvRead
	// to the capability set. RiskScore should not flag.
	fp := analyzed(withEnv("AWS_ACCESS_KEY_ID"))
	r := RiskScore(fp)
	if r.Score != 0 {
		t.Errorf("env reads without CapEnvRead should be 0, got %d", r.Score)
	}
}

func TestRiskScore_EnvReadCapabilityWithoutCredentialNamesNoFlag(t *testing.T) {
	// Common config-style names shouldn't trip credential heuristic.
	for _, name := range []string{"NODE_ENV", "DEBUG", "LOG_LEVEL", "PATH", "HOME"} {
		fp := analyzed(withCaps(CapEnvRead), withEnv(name))
		r := RiskScore(fp)
		if r.Score != 0 {
			t.Errorf("benign env var %q raised score: %+v", name, r)
		}
	}
}

func TestRiskScore_CredentialEnvNamesAreCaseInsensitive(t *testing.T) {
	for _, name := range []string{"aws_access_key_id", "Aws_Secret", "github_token"} {
		fp := analyzed(withCaps(CapEnvRead), withEnv(name))
		r := RiskScore(fp)
		if r.Score == 0 {
			t.Errorf("credential-shaped %q should fire env-cred-read flag", name)
		}
	}
}

func TestRiskScore_FlagDetailMentionsAllEnvNamesUpToFive(t *testing.T) {
	names := []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_REGION", "AWS_PROFILE", "AWS_DEFAULT_OUTPUT", "AWS_PAGER",
	}
	fp := analyzed(withCaps(CapEnvRead), withEnv(names...))
	r := RiskScore(fp)
	if len(r.Flags) != 1 {
		t.Fatalf("expected 1 env flag, got %+v", r.Flags)
	}
	// joinNames caps at 5; AWS_PAGER (last) must not appear.
	if strings.Contains(r.Flags[0].Detail, "AWS_PAGER") {
		t.Errorf("env flag should truncate after 5 names: %q", r.Flags[0].Detail)
	}
}

func TestRiskScore_UnknownCapabilityIsNoOp(t *testing.T) {
	// A future capability not in the switch table should be ignored,
	// not crash. Use a deliberately-out-of-range value.
	fp := &Fingerprint{Analyzed: true, Capabilities: CapabilitySet{Capability(9999)}}
	r := RiskScore(fp)
	if r.Score != 0 {
		t.Errorf("unknown capability should score 0, got %d", r.Score)
	}
}

// --- DriftScore edge cases ---------------------------------------------

func TestDriftScore_HookContentChangeRequiresBothShas(t *testing.T) {
	// If either side's sha is empty (e.g. lockfile-only metadata) we
	// can't reliably say content changed; don't flag.
	old := analyzed(withHook(PhasePostInstall, "scripts.postinstall", ""))
	new_ := analyzed(withHook(PhasePostInstall, "scripts.postinstall", "abc"))
	d := DriftScore(old, new_)
	if d.Score != 0 {
		t.Errorf("missing sha on either side should not flag: %+v", d)
	}
}

func TestDriftScore_OnlyCapabilityRemovalNoFlag(t *testing.T) {
	// Removing capabilities shrinks attack surface; don't penalize.
	old := analyzed(withCaps(CapShellSpawn, CapNetEgress))
	new_ := analyzed()
	d := DriftScore(old, new_)
	if d.Score != 0 {
		t.Errorf("pure removal should be 0, got %d (flags=%+v)", d.Score, d.Flags)
	}
}

func TestDriftScore_SizeAnomalyZeroEitherSide(t *testing.T) {
	// If one side has size 0 (not measured), don't compute anomaly.
	d1 := DriftScore(analyzed(), analyzed(withSize(10000)))
	d2 := DriftScore(analyzed(withSize(10000)), analyzed())
	if d1.Score != 0 || d2.Score != 0 {
		t.Errorf("size-anomaly with 0 side: d1=%d d2=%d", d1.Score, d2.Score)
	}
}

func TestDriftScore_SizeRangeNeitherDoublingNorHalving(t *testing.T) {
	// 50% growth → no flag (under 2x threshold, over 1/2 threshold).
	d := DriftScore(analyzed(withSize(1000)), analyzed(withSize(1500)))
	if d.Score != 0 {
		t.Errorf("50%% growth should not flag, got %d", d.Score)
	}
}

func TestDriftScore_FlagDetailIncludesCapabilityName(t *testing.T) {
	old := analyzed()
	new_ := analyzed(withCaps(CapDynamicEval))
	d := DriftScore(old, new_)
	if len(d.Flags) != 1 || !strings.Contains(d.Flags[0].Detail, "dynamic-eval") {
		t.Errorf("expected detail to mention capability name: %+v", d.Flags)
	}
}

func TestDriftScore_NewInstallHookExecCapabilityNotDoubleCounted(t *testing.T) {
	// CapInstallHookExec appearing in next.Capabilities should NOT
	// produce its own capability-added flag because hookDiff already
	// emitted install-hook-added.
	old := analyzed()
	new_ := analyzed(
		withHook(PhasePostInstall, "scripts.postinstall", "x"),
		withCaps(CapInstallHookExec),
	)
	d := DriftScore(old, new_)
	if len(d.Flags) != 1 {
		t.Errorf("expected exactly 1 drift flag (install-hook-added), got %+v", d.Flags)
	}
	if d.Flags[0].Code != "install-hook-added" {
		t.Errorf("expected install-hook-added, got %s", d.Flags[0].Code)
	}
}

// --- Verdict edge cases ------------------------------------------------

func TestVerdict_BothZeroIsSafe(t *testing.T) {
	if v := Verdict(RiskAssessment{}, RiskAssessment{}); v != VerdictSafe {
		t.Errorf("got %s, want safe", v)
	}
}

func TestVerdict_String(t *testing.T) {
	want := map[VerdictKind]string{
		VerdictSafe: "safe", VerdictReview: "review",
		VerdictPrompt: "prompt", VerdictBlock: "block",
	}
	for v, s := range want {
		if v.String() != s {
			t.Errorf("%d.String() = %q, want %q", v, v.String(), s)
		}
	}
	if VerdictKind(99).String() != "unknown" {
		t.Errorf("unknown verdict should stringify to 'unknown'")
	}
}

// --- credentialLikeEnvReads helper -------------------------------------

func TestCredentialLikeEnvReads_Empty(t *testing.T) {
	if got := credentialLikeEnvReads(nil); got != nil {
		t.Errorf("nil input should yield nil, got %v", got)
	}
	if got := credentialLikeEnvReads([]string{}); got != nil {
		t.Errorf("empty input should yield nil, got %v", got)
	}
}

func TestCredentialLikeEnvReads_PartialMatches(t *testing.T) {
	got := credentialLikeEnvReads([]string{
		"NODE_ENV", "DEBUG",
		"AWS_ACCESS_KEY_ID", "MY_PASS",
		"GITHUB_TOKEN_OLD", "github_token", // case-insensitive
	})
	if len(got) < 3 {
		t.Errorf("expected at least 3 matches, got %v", got)
	}
}
