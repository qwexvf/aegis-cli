package domain

import "testing"

func TestMatchAll_Empty(t *testing.T) {
	if got := EmptyAllowSet().MatchAll(EcoNpm, "lodash", "1.0.0"); got != nil {
		t.Errorf("empty set MatchAll = %v, want nil", got)
	}
}

func TestMatchAll_NoMatch(t *testing.T) {
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "react", Capability: CapDynamicEval, Reason: "x"})
	if got := s.MatchAll(EcoNpm, "lodash", "1.0.0"); len(got) != 0 {
		t.Errorf("expected no matches, got %v", got)
	}
}

func TestMatchAll_SpecificCapability(t *testing.T) {
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval, Reason: "tpl"})
	matches := s.MatchAll(EcoNpm, "lodash", "1.0.0")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.Kind != MatchSpecific || m.Capability != CapDynamicEval {
		t.Errorf("unexpected match: %+v", m)
	}
}

func TestMatchAll_AnyCapabilityCollapsedToSingleEntry(t *testing.T) {
	// A Capability=0 rule covers all caps; MatchAll must return ONE
	// Match (Kind=MatchAny), not one per Capability.
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "deploy-tool", Reason: "trusted"})
	matches := s.MatchAll(EcoNpm, "deploy-tool", "1.0.0")
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match (collapsed), got %d", len(matches))
	}
	if matches[0].Kind != MatchAny {
		t.Errorf("expected MatchAny, got %v", matches[0].Kind)
	}
}

func TestMatchAll_MixesSpecificAndAny(t *testing.T) {
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval, Reason: "tpl"},
		AllowRule{Ecosystem: EcoNpm, Name: "*", Reason: "wildcard"},
	)
	matches := s.MatchAll(EcoNpm, "lodash", "4.17.21")
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	// Specific (lodash) first, wildcard second.
	if matches[0].Kind != MatchSpecific || matches[0].Capability != CapDynamicEval {
		t.Errorf("first should be specific lodash: %+v", matches[0])
	}
	if matches[1].Kind != MatchAny || matches[1].Rule.Name != "*" {
		t.Errorf("second should be wildcard: %+v", matches[1])
	}
}

func TestMatchAll_VersionConstraintHonoured(t *testing.T) {
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", VersionRange: "^4", Capability: CapDynamicEval, Reason: "v4"})
	if got := s.MatchAll(EcoNpm, "lodash", "5.0.0"); len(got) != 0 {
		t.Errorf("v5 should NOT match ^4 rule, got %v", got)
	}
}
