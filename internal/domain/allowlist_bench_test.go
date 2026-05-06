package domain

import (
	"strconv"
	"testing"
)

// BenchmarkAllowSet_Suppresses measures the lookup cost on a
// realistic ruleset (20 builtin + 480 synthetic project rules,
// = 500 total). The index should make per-call cost essentially
// independent of ruleset size for non-wildcard lookups.
func BenchmarkAllowSet_Suppresses(b *testing.B) {
	rules := make([]AllowRule, 0, 500)
	rules = append(rules, BuiltinAllowRules()...)
	for i := range 480 {
		rules = append(rules, AllowRule{
			Ecosystem:  EcoNpm,
			Name:       "synthetic-pkg-" + strconv.Itoa(i),
			Capability: CapShellSpawn,
			Reason:     "bench",
			Source:     "synthetic",
		})
	}
	set, err := NewAllowSet(rules)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("hit-specific", func(b *testing.B) {
		for b.Loop() {
			_, _ = set.Suppresses(EcoNpm, "lodash", "4.17.21", CapDynamicEval)
		}
	})
	b.Run("miss", func(b *testing.B) {
		for b.Loop() {
			_, _ = set.Suppresses(EcoNpm, "no-such-package-anywhere", "1.0.0", CapShellSpawn)
		}
	})
}

func BenchmarkAllowSet_MatchAll(b *testing.B) {
	rules := append([]AllowRule{}, BuiltinAllowRules()...)
	rules = append(rules,
		AllowRule{Ecosystem: EcoNpm, Name: "*", Capability: CapNetEgress, Reason: "wide", Source: "user"})
	set, _ := NewAllowSet(rules)
	for b.Loop() {
		_ = set.MatchAll(EcoNpm, "lodash", "4.17.21")
	}
}
