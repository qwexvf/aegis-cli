package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestDetectTyposquat(t *testing.T) {
	tests := []struct {
		name string
		eco  domain.Ecosystem
		pkg  string
		want domain.Capability
	}{
		// --- positive cases (known real-world squat shapes) ---
		{"distance-1 of lodash → flag", domain.EcoNpm, "lodahs", domain.CapTyposquatRisk},
		{"distance-1 of express → flag", domain.EcoNpm, "expresss", domain.CapTyposquatRisk},
		{"distance-1 of react → flag", domain.EcoNpm, "raect", domain.CapTyposquatRisk},
		{"distance-2 of axios → flag", domain.EcoNpm, "axoiis", domain.CapTyposquatRisk},
		{"scoped attacker @atk/lodash flags too (bare-name match)", domain.EcoNpm, "@atk/lodash", 0}, // exact name 'lodash' is in top list, so the bare match excludes it
		{"distance-1 of lodash, scoped → flag", domain.EcoNpm, "@atk/lodahs", domain.CapTyposquatRisk},

		// --- negative cases ---
		{"itself a top package — no flag", domain.EcoNpm, "lodash", 0},
		{"completely unrelated name — no flag", domain.EcoNpm, "totally-unique-package-name-xyz123", 0},
		{"non-npm — heuristic doesn't apply yet", domain.EcoPyPI, "lodahs", 0},
		{"empty name — no flag", domain.EcoNpm, "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectTyposquat(tc.eco, tc.pkg)
			if got != tc.want {
				t.Errorf("DetectTyposquat(%q) = %v, want %v", tc.pkg, got, tc.want)
			}
		})
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "abc", 3},
		{"lodash", "lodash", 0},
		{"lodash", "lodahs", 2}, // swap = 2 edits in plain Levenshtein
		{"react", "raect", 2},
		{"kitten", "sitting", 3},
	}
	for _, tc := range tests {
		got := levenshtein(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
