package domain

import (
	"strings"
	"testing"
)

func mustSet(t *testing.T, rules ...AllowRule) AllowSet {
	t.Helper()
	s, err := NewAllowSet(rules)
	if err != nil {
		t.Fatalf("NewAllowSet: %v", err)
	}
	return s
}

func TestNewAllowSet_RejectsMissingEcosystem(t *testing.T) {
	_, err := NewAllowSet([]AllowRule{{Name: "lodash"}})
	if err == nil || !strings.Contains(err.Error(), "ecosystem") {
		t.Errorf("expected ecosystem-required error, got %v", err)
	}
}

func TestNewAllowSet_RejectsMissingName(t *testing.T) {
	_, err := NewAllowSet([]AllowRule{{Ecosystem: EcoNpm}})
	if err == nil || !strings.Contains(err.Error(), "name") {
		t.Errorf("expected name-required error, got %v", err)
	}
}

func TestNewAllowSet_RejectsBadSemverConstraint(t *testing.T) {
	_, err := NewAllowSet([]AllowRule{
		{Ecosystem: EcoNpm, Name: "lodash", VersionRange: "not-a-range"},
	})
	if err == nil || !strings.Contains(err.Error(), "version range") {
		t.Errorf("expected version-range error, got %v", err)
	}
}

func TestEmptyAllowSet_NeverMatches(t *testing.T) {
	s := EmptyAllowSet()
	if ok, _ := s.Suppresses(EcoNpm, "lodash", "4.17.21", CapDynamicEval); ok {
		t.Error("empty set must never match")
	}
}

func TestAllowSet_ExactNameMatchesOnlyThatName(t *testing.T) {
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval, Reason: "tpl"})
	if ok, _ := s.Suppresses(EcoNpm, "lodash", "4.17.21", CapDynamicEval); !ok {
		t.Error("lodash should match")
	}
	if ok, _ := s.Suppresses(EcoNpm, "react", "18.0.0", CapDynamicEval); ok {
		t.Error("react should not match a lodash-only rule")
	}
}

func TestAllowSet_WildcardNameMatchesAny(t *testing.T) {
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "*", Capability: CapNetEgress, Reason: "demo"})
	for _, name := range []string{"axios", "got", "node-fetch", "really-anything"} {
		if ok, _ := s.Suppresses(EcoNpm, name, "1.0.0", CapNetEgress); !ok {
			t.Errorf("name=* should match %q", name)
		}
	}
}

func TestAllowSet_WildcardCapabilityMatchesAny(t *testing.T) {
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "demo", Reason: "trusted entirely"})
	for _, c := range []Capability{CapShellSpawn, CapDynamicEval, CapNetEgress} {
		if ok, _ := s.Suppresses(EcoNpm, "demo", "1.0.0", c); !ok {
			t.Errorf("Capability=0 should match %s", c)
		}
	}
}

func TestAllowSet_EcosystemMustEqual(t *testing.T) {
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval, Reason: "tpl"})
	if ok, _ := s.Suppresses(EcoPyPI, "lodash", "1.0.0", CapDynamicEval); ok {
		t.Error("npm rule must not match pypi lookup")
	}
}

func TestAllowSet_VersionConstraint(t *testing.T) {
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", VersionRange: "^4", Capability: CapDynamicEval, Reason: "tpl"})

	if ok, _ := s.Suppresses(EcoNpm, "lodash", "4.17.21", CapDynamicEval); !ok {
		t.Error("4.17.21 should satisfy ^4")
	}
	if ok, _ := s.Suppresses(EcoNpm, "lodash", "5.0.0", CapDynamicEval); ok {
		t.Error("5.0.0 should not satisfy ^4")
	}
	if ok, _ := s.Suppresses(EcoNpm, "lodash", "3.10.0", CapDynamicEval); ok {
		t.Error("3.10.0 should not satisfy ^4")
	}
}

func TestAllowSet_VersionWildcardEquivToEmpty(t *testing.T) {
	for _, vr := range []string{"", "*"} {
		s := mustSet(t,
			AllowRule{Ecosystem: EcoNpm, Name: "lodash", VersionRange: vr, Capability: CapDynamicEval, Reason: "x"})
		for _, ver := range []string{"1.0.0", "4.17.21", "999.999.999", "0.0.1-rc.1"} {
			if ok, _ := s.Suppresses(EcoNpm, "lodash", ver, CapDynamicEval); !ok {
				t.Errorf("VersionRange=%q should match version %q", vr, ver)
			}
		}
	}
}

func TestAllowSet_EmptyVersionInputAndConstrainedRule(t *testing.T) {
	// If the lookup has no version (e.g. pre-resolution), a rule with
	// a non-wildcard constraint cannot match.
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", VersionRange: "^4", Capability: CapDynamicEval, Reason: "tpl"})
	if ok, _ := s.Suppresses(EcoNpm, "lodash", "", CapDynamicEval); ok {
		t.Error("empty version + constrained rule should NOT match")
	}
}

func TestAllowSet_MatchReturnsRuleReason(t *testing.T) {
	want := AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval,
		Reason: "lodash._.template compiles via Function()", Source: "builtin"}
	s := mustSet(t, want)
	ok, got := s.Suppresses(EcoNpm, "lodash", "4.17.21", CapDynamicEval)
	if !ok {
		t.Fatal("expected match")
	}
	if got.Reason != want.Reason || got.Source != want.Source {
		t.Errorf("rule lost on match: got %+v, want %+v", got, want)
	}
}

func TestAllowSet_SpecificNameWinsOverWildcard(t *testing.T) {
	// Both match; the exact-name rule should win regardless of
	// input order (it sits in the per-name index, walked first).
	// Documented behavior: specific > wildcard.
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "*", Capability: CapDynamicEval, Reason: "wide", Source: "user"},
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval, Reason: "narrow", Source: "builtin"},
	)
	_, got := s.Suppresses(EcoNpm, "lodash", "4.17.21", CapDynamicEval)
	if got.Source != "builtin" {
		t.Errorf("specific-name rule should win over wildcard; got Source=%q", got.Source)
	}
}

func TestAllowSet_MultipleSpecificRulesFirstWins(t *testing.T) {
	// When two exact-name rules both match (e.g. one with version
	// constraint, one without), input order decides — first wins
	// inside the per-name bucket.
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", VersionRange: "^4", Capability: CapDynamicEval, Reason: "narrow", Source: "builtin"},
		AllowRule{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval, Reason: "broad", Source: "user"},
	)
	_, got := s.Suppresses(EcoNpm, "lodash", "4.17.21", CapDynamicEval)
	if got.Source != "builtin" {
		t.Errorf("first matching specific rule should win; got Source=%q", got.Source)
	}
}

func TestAllowSet_Rules_PreservesInputOrder(t *testing.T) {
	in := []AllowRule{
		{Ecosystem: EcoNpm, Name: "a", Reason: "1"},
		{Ecosystem: EcoNpm, Name: "b", Reason: "2"},
		{Ecosystem: EcoNpm, Name: "c", Reason: "3"},
	}
	s := mustSet(t, in...)
	out := s.Rules()
	for i := range in {
		if out[i].Name != in[i].Name {
			t.Errorf("Rules() order changed at %d: got %q, want %q", i, out[i].Name, in[i].Name)
		}
	}
}

func TestAllowSet_Len(t *testing.T) {
	if EmptyAllowSet().Len() != 0 {
		t.Error("empty set Len != 0")
	}
	s := mustSet(t,
		AllowRule{Ecosystem: EcoNpm, Name: "a"},
		AllowRule{Ecosystem: EcoNpm, Name: "b"},
	)
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
}
