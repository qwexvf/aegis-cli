package domain

import "testing"

func dec(k DecisionKind) Decision { return Decision{Kind: k, Severity: SevInfo} }

func TestEvaluate_AllowAndWarnAlwaysProceed(t *testing.T) {
	for _, k := range []DecisionKind{DecisionAllow, DecisionWarn} {
		for _, ci := range []bool{false, true} {
			for _, tty := range []bool{false, true} {
				pc := PolicyContext{InCI: ci, HasInteractiveTTY: tty}
				if got := Evaluate(dec(k), pc).Action; got != ActionProceed {
					t.Errorf("Evaluate(%s, %+v).Action = %d, want Proceed", k, pc, got)
				}
			}
		}
	}
}

func TestEvaluate_BlockBlocksWithoutOverride(t *testing.T) {
	o := Evaluate(dec(DecisionBlock), PolicyContext{HasInteractiveTTY: true})
	if o.Action != ActionBlock {
		t.Errorf("block w/o override: Action = %d, want Block", o.Action)
	}
	if o.OverrideUsed {
		t.Error("block w/o override: OverrideUsed should be false")
	}
}

func TestEvaluate_BlockProceedsWithValidOverride(t *testing.T) {
	pc := PolicyContext{OverrideAllow: true, OverrideReason: "hotfix"}
	o := Evaluate(dec(DecisionBlock), pc)
	if o.Action != ActionProceed || !o.OverrideUsed || o.OverrideReason != "hotfix" {
		t.Errorf("block w/ override: %+v", o)
	}
}

func TestEvaluate_BlockOverrideWithoutReasonStillBlocks(t *testing.T) {
	pc := PolicyContext{OverrideAllow: true, OverrideReason: ""}
	o := Evaluate(dec(DecisionBlock), pc)
	if o.Action != ActionBlock {
		t.Errorf("override w/o reason must still block; got %+v", o)
	}
}

func TestEvaluate_PromptInCIPromotesToBlock(t *testing.T) {
	pc := PolicyContext{InCI: true, HasInteractiveTTY: false}
	o := Evaluate(dec(DecisionPrompt), pc)
	if o.Action != ActionBlock || !o.PromotedFromPrompt {
		t.Errorf("prompt in CI: %+v", o)
	}
}

func TestEvaluate_PromptNoTTYPromotesToBlock(t *testing.T) {
	pc := PolicyContext{InCI: false, HasInteractiveTTY: false}
	o := Evaluate(dec(DecisionPrompt), pc)
	if o.Action != ActionBlock || !o.PromotedFromPrompt {
		t.Errorf("prompt no TTY: %+v", o)
	}
}

func TestEvaluate_PromptWithTTYAsksUser(t *testing.T) {
	pc := PolicyContext{InCI: false, HasInteractiveTTY: true}
	o := Evaluate(dec(DecisionPrompt), pc)
	if o.Action != ActionAskUser {
		t.Errorf("prompt + TTY: Action = %d, want AskUser", o.Action)
	}
}

func TestEvaluate_PromptOverrideShortCircuits(t *testing.T) {
	// Even in CI, a valid override beats prompt promotion.
	pc := PolicyContext{InCI: true, OverrideAllow: true, OverrideReason: "hotfix"}
	o := Evaluate(dec(DecisionPrompt), pc)
	if o.Action != ActionProceed || !o.OverrideUsed {
		t.Errorf("prompt + valid override should proceed; got %+v", o)
	}
}

func TestResolvePrompt_AllowedProceeds(t *testing.T) {
	o := Outcome{Action: ActionAskUser}
	got := ResolvePrompt(o, true)
	if got.Action != ActionProceed || !got.OverrideUsed || got.OverrideReason != "user-allowed" {
		t.Errorf("resolve allowed: %+v", got)
	}
}

func TestResolvePrompt_DeniedBlocks(t *testing.T) {
	o := Outcome{Action: ActionAskUser}
	got := ResolvePrompt(o, false)
	if got.Action != ActionBlock {
		t.Errorf("resolve denied: %+v", got)
	}
}

func TestResolvePrompt_NoOpWhenNotAskUser(t *testing.T) {
	o := Outcome{Action: ActionBlock}
	if got := ResolvePrompt(o, true); got.Action != ActionBlock {
		t.Errorf("resolve on non-AskUser: %+v", got)
	}
}

func TestPackageSpec_IsExactVersion(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"", false},
		{"4.17.21", true},
		{"1.0.0-rc.1", true},
		{"1.2.3+build.45", true},
		{"^4.17.0", false},
		{"latest", false},
		{"4", false},
	}
	for _, c := range cases {
		got := PackageSpec{Version: c.v}.IsExactVersion()
		if got != c.want {
			t.Errorf("IsExactVersion(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}
