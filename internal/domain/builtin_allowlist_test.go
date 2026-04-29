package domain

import "testing"

func TestBuiltinAllowRules_NonEmpty(t *testing.T) {
	rules := BuiltinAllowRules()
	if len(rules) < 10 {
		t.Errorf("expected at least 10 builtin rules, got %d", len(rules))
	}
}

func TestBuiltinAllowRules_AllValid(t *testing.T) {
	// NewAllowSet validates each rule; if any is malformed we'd panic
	// at composition root. Catch that early here.
	if _, err := NewAllowSet(BuiltinAllowRules()); err != nil {
		t.Fatalf("builtin rules failed validation: %v", err)
	}
}

func TestBuiltinAllowRules_HaveSourceBuiltin(t *testing.T) {
	for _, r := range BuiltinAllowRules() {
		if r.Source != "builtin" {
			t.Errorf("%s/%s missing Source=builtin (got %q)", r.Ecosystem, r.Name, r.Source)
		}
	}
}

func TestBuiltinAllowRules_HaveReason(t *testing.T) {
	// Every rule must explain *why* it's there. No empty reasons.
	for _, r := range BuiltinAllowRules() {
		if r.Reason == "" {
			t.Errorf("%s/%s has empty Reason", r.Ecosystem, r.Name)
		}
	}
}

func TestBuiltinAllowRules_LodashDynamicEvalCovered(t *testing.T) {
	// Spot-check: the canonical "we should ship this" example must work.
	set, err := NewAllowSet(BuiltinAllowRules())
	if err != nil {
		t.Fatal(err)
	}
	ok, rule := set.Suppresses(EcoNpm, "lodash", "4.17.21", CapDynamicEval)
	if !ok {
		t.Fatal("lodash dynamic-eval should be suppressed by builtin set")
	}
	if rule.Source != "builtin" {
		t.Errorf("lodash rule should have builtin source, got %q", rule.Source)
	}
}

func TestBuiltinAllowRules_DoesNotMatchUnrelatedPackage(t *testing.T) {
	set, err := NewAllowSet(BuiltinAllowRules())
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := set.Suppresses(EcoNpm, "totally-random", "1.0.0", CapDynamicEval); ok {
		t.Error("builtin set should not match unrelated packages")
	}
}
