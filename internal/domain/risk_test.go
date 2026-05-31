package domain

import (
	"strings"
	"testing"
)

func analyzed(opts ...func(*Fingerprint)) *Fingerprint {
	fp := &Fingerprint{Analyzed: true}
	for _, o := range opts {
		o(fp)
	}
	return fp
}

func withCaps(c ...Capability) func(*Fingerprint) {
	return func(fp *Fingerprint) { fp.Capabilities = NewCapabilitySet(c...) }
}
func withHook(phase HookPhase, source, sha string) func(*Fingerprint) {
	return func(fp *Fingerprint) {
		fp.Hooks = append(fp.Hooks, InstallHook{Phase: phase, Source: source, Sha256: sha})
	}
}
func withEnv(names ...string) func(*Fingerprint) {
	return func(fp *Fingerprint) { fp.EnvReads = names }
}
func withSize(n int) func(*Fingerprint) {
	return func(fp *Fingerprint) { fp.SourceSizeBytes = n }
}

// --- RiskScore ----------------------------------------------------------

func TestRiskScore_NilOrUnanalyzedReturnsZero(t *testing.T) {
	if RiskScore(nil).Score != 0 {
		t.Error("nil should be 0")
	}
	if RiskScore(&Fingerprint{}).Score != 0 {
		t.Error("unanalyzed should be 0")
	}
}

func TestRiskScore_EmptyAnalyzedReturnsZero(t *testing.T) {
	if RiskScore(analyzed()).Score != 0 {
		t.Error("analyzed-but-empty should be 0")
	}
}

// Heuristic-only ecosystems (no AST scanner) merge capabilities onto a
// fingerprint that was never marked Analyzed. Those caps MUST still score —
// otherwise install-hook/curl|sh/typosquat malware on CRAN/CPAN/SwiftURL
// rates safe with risk 0. Regression for the no-AST-ecosystem scoring gap.
func TestRiskScore_UnanalyzedWithCapabilitiesStillScores(t *testing.T) {
	fp := &Fingerprint{
		Analyzed:     false,
		Capabilities: NewCapabilitySet(CapInstallHookSuspicious, CapTyposquatRisk),
	}
	r := RiskScore(fp)
	if r.Score == 0 {
		t.Fatal("unanalyzed fingerprint with heuristic capabilities must score > 0")
	}
	if r.Score != WeightInstallHookSuspicious+WeightTyposquatRisk {
		t.Errorf("score = %d, want %d", r.Score, WeightInstallHookSuspicious+WeightTyposquatRisk)
	}
	// A truly empty, unanalyzed fingerprint must still score 0.
	if RiskScore(&Fingerprint{Analyzed: false}).Score != 0 {
		t.Error("empty unanalyzed fingerprint should be 0")
	}
}

func TestRiskScore_InstallHookAlone(t *testing.T) {
	r := RiskScore(analyzed(withHook(PhasePostInstall, "scripts.postinstall", "sha-x")))
	if r.Score != WeightInstallHook {
		t.Errorf("score = %d, want %d", r.Score, WeightInstallHook)
	}
	if len(r.Flags) != 1 || r.Flags[0].Code != "install-hook" {
		t.Errorf("flags: %+v", r.Flags)
	}
}

func TestRiskScore_ShellSpawnPlusBase64IsModerate(t *testing.T) {
	r := RiskScore(analyzed(withCaps(CapShellSpawn, CapBase64Decode)))
	want := WeightShellSpawn + WeightBase64Decode
	if r.Score != want {
		t.Errorf("score = %d, want %d", r.Score, want)
	}
}

func TestRiskScore_FullPostinstallExecPattern(t *testing.T) {
	// What a typical "ua-parser-js style" payload looks like:
	// install hook + shell spawn + base64 decode + net egress.
	r := RiskScore(analyzed(
		withHook(PhasePostInstall, "scripts.postinstall", ""),
		withCaps(CapShellSpawn, CapBase64Decode, CapNetEgress),
	))
	want := WeightInstallHook + WeightShellSpawn + WeightBase64Decode + WeightNetEgress
	if r.Score != want {
		t.Errorf("score = %d, want %d", r.Score, want)
	}
	// Should reach the prompt threshold but not block on its own —
	// product policy requires drift OR a hook+content change to BLOCK.
	if got := Verdict(r, RiskAssessment{}); got != VerdictPrompt {
		t.Errorf("verdict = %s, want prompt", got)
	}
}

func TestRiskScore_EnvReadOnlyFlaggedForCredentialNames(t *testing.T) {
	// Random env vars don't escalate.
	r1 := RiskScore(analyzed(withCaps(CapEnvRead), withEnv("NODE_ENV", "DEBUG")))
	if r1.Score != 0 {
		t.Errorf("non-credential env reads should be 0, got %d", r1.Score)
	}

	// Credential-shaped names do.
	r2 := RiskScore(analyzed(withCaps(CapEnvRead), withEnv("AWS_ACCESS_KEY_ID")))
	if r2.Score != WeightEnvCredRead {
		t.Errorf("credential env read = %d, want %d", r2.Score, WeightEnvCredRead)
	}
	if len(r2.Flags) != 1 || !strings.Contains(r2.Flags[0].Detail, "AWS_ACCESS_KEY_ID") {
		t.Errorf("flag should mention env name: %+v", r2.Flags)
	}
}

func TestRiskScore_InstallHookExecCapabilityNotDoubleCounted(t *testing.T) {
	// CapInstallHookExec exists for completeness but Hooks already
	// counted; risk shouldn't add WeightInstallHook twice.
	r := RiskScore(analyzed(
		withHook(PhasePostInstall, "scripts.postinstall", ""),
		withCaps(CapInstallHookExec),
	))
	if r.Score != WeightInstallHook {
		t.Errorf("expected hook counted once: got %d", r.Score)
	}
}

// --- DriftScore ---------------------------------------------------------

func TestDriftScore_NilEitherSideReturnsZero(t *testing.T) {
	a := analyzed()
	if DriftScore(nil, a).Score != 0 || DriftScore(a, nil).Score != 0 {
		t.Error("nil side should be 0")
	}
}

func TestDriftScore_NewInstallHookFlagged(t *testing.T) {
	old := analyzed()
	new_ := analyzed(withHook(PhasePostInstall, "scripts.postinstall", "sha-x"))
	d := DriftScore(old, new_)
	if d.Score != WeightInstallHook {
		t.Errorf("expected new-hook score %d, got %d", WeightInstallHook, d.Score)
	}
	if len(d.Flags) != 1 || d.Flags[0].Code != "install-hook-added" {
		t.Errorf("flag: %+v", d.Flags)
	}
}

func TestDriftScore_HookContentChangeFlagged(t *testing.T) {
	old := analyzed(withHook(PhasePostInstall, "scripts.postinstall", "old-sha"))
	new_ := analyzed(withHook(PhasePostInstall, "scripts.postinstall", "new-sha"))
	d := DriftScore(old, new_)
	if d.Score != WeightHookContent {
		t.Errorf("expected hook-changed score %d, got %d", WeightHookContent, d.Score)
	}
}

func TestDriftScore_HookUnchangedNotFlagged(t *testing.T) {
	old := analyzed(withHook(PhasePostInstall, "scripts.postinstall", "same-sha"))
	new_ := analyzed(withHook(PhasePostInstall, "scripts.postinstall", "same-sha"))
	d := DriftScore(old, new_)
	if d.Score != 0 {
		t.Errorf("identical hooks should be 0, got %d (flags=%+v)", d.Score, d.Flags)
	}
}

func TestDriftScore_NewCapabilityFlagged(t *testing.T) {
	old := analyzed(withCaps(CapNetEgress))
	new_ := analyzed(withCaps(CapNetEgress, CapShellSpawn))
	d := DriftScore(old, new_)
	if d.Score != WeightCapabilityAdd {
		t.Errorf("score = %d, want %d", d.Score, WeightCapabilityAdd)
	}
}

func TestDriftScore_RemovedCapabilityNotFlagged(t *testing.T) {
	// Losing a capability is not concerning (attack surface shrank).
	old := analyzed(withCaps(CapShellSpawn, CapNetEgress))
	new_ := analyzed(withCaps(CapNetEgress))
	d := DriftScore(old, new_)
	if d.Score != 0 {
		t.Errorf("removal should be 0, got %d", d.Score)
	}
}

func TestDriftScore_SizeDoubledFlagged(t *testing.T) {
	d := DriftScore(analyzed(withSize(1000)), analyzed(withSize(5000)))
	if d.Score != WeightSizeAnomaly {
		t.Errorf("score = %d, want %d", d.Score, WeightSizeAnomaly)
	}
}

func TestDriftScore_SizeDroppedFlagged(t *testing.T) {
	// faker@6.6.6 sabotage pattern: source got wiped.
	d := DriftScore(analyzed(withSize(10000)), analyzed(withSize(100)))
	if d.Score != WeightSizeAnomaly {
		t.Errorf("score = %d, want %d", d.Score, WeightSizeAnomaly)
	}
}

func TestDriftScore_SmallSizeChangeNotFlagged(t *testing.T) {
	d := DriftScore(analyzed(withSize(1000)), analyzed(withSize(1300)))
	if d.Score != 0 {
		t.Errorf("30%% growth should be 0, got %d", d.Score)
	}
}

func TestDriftScore_UAParserJSStylePattern(t *testing.T) {
	// 0.7.28 (clean, just a parser library) → 0.7.29 (compromised:
	// added postinstall, three new dangerous capabilities, source 2.5x).
	// Drift alone reaches PROMPT (drift+risk together reach BLOCK —
	// see the combined test below). Pure drift should not BLOCK
	// because legitimate refactors can also add capabilities; we want
	// the user prompted, not surprised.
	old := analyzed(withSize(8000))
	new_ := analyzed(
		withHook(PhasePostInstall, "scripts.postinstall", "evil"),
		withCaps(CapShellSpawn, CapBase64Decode, CapNetEgress, CapInstallHookExec),
		withSize(20000),
	)
	d := DriftScore(old, new_)
	want := WeightInstallHook + 3*WeightCapabilityAdd + WeightSizeAnomaly // 30+45+5=80
	if d.Score != want {
		t.Errorf("drift score = %d, want %d (flags=%+v)", d.Score, want, d.Flags)
	}
	if got := Verdict(RiskAssessment{}, d); got != VerdictPrompt {
		t.Errorf("drift-alone verdict = %s, want prompt (BLOCK requires combined)", got)
	}
}

func TestVerdict_RiskAndDriftCombineForUAParserJSPattern(t *testing.T) {
	// The full compromise scenario hits BLOCK because BOTH the new
	// version is dangerous on its own AND the drift from the previous
	// version is alarming. Either signal alone gives prompt; together
	// they pass the BLOCK threshold via the combined max.
	risk := RiskScore(analyzed(
		withHook(PhasePostInstall, "scripts.postinstall", "evil"),
		withCaps(CapShellSpawn, CapBase64Decode, CapNetEgress),
	))
	drift := DriftScore(
		analyzed(withSize(8000)),
		analyzed(
			withHook(PhasePostInstall, "scripts.postinstall", "evil"),
			withCaps(CapShellSpawn, CapBase64Decode, CapNetEgress, CapInstallHookExec),
			withSize(20000),
		),
	)
	// Risk alone:  hook(30) + shell(20) + b64(20) + net(10) = 80  → prompt
	// Drift alone: hook-add(30) + 3*cap-add(45) + size(5) = 80  → prompt
	// max() = 80 → prompt; we still want this to reach prompt UX.
	if got := Verdict(risk, drift); got != VerdictPrompt {
		t.Errorf("risk+drift compromise pattern verdict = %s; expected prompt UX", got)
	}
}

// --- Verdict ------------------------------------------------------------

func TestVerdict_BoundariesAreInclusiveLowerExclusiveUpper(t *testing.T) {
	cases := []struct {
		score int
		want  VerdictKind
	}{
		{0, VerdictSafe},
		{20, VerdictSafe},
		{21, VerdictReview},
		{60, VerdictReview},
		{61, VerdictPrompt},
		{99, VerdictPrompt},
		{100, VerdictBlock},
		{500, VerdictBlock},
	}
	for _, c := range cases {
		got := Verdict(RiskAssessment{Score: c.score}, RiskAssessment{})
		if got != c.want {
			t.Errorf("score %d: got %s, want %s", c.score, got, c.want)
		}
	}
}

func TestVerdict_TakesMaxOfRiskAndDrift(t *testing.T) {
	// Risk low, drift high → drift wins.
	v := Verdict(RiskAssessment{Score: 10}, RiskAssessment{Score: 80})
	if v != VerdictPrompt {
		t.Errorf("expected drift to dominate; got %s", v)
	}
	// Reverse.
	v = Verdict(RiskAssessment{Score: 110}, RiskAssessment{Score: 5})
	if v != VerdictBlock {
		t.Errorf("expected risk to dominate; got %s", v)
	}
}
