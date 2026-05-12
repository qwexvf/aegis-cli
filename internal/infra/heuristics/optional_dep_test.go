package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestDetectGitDepInOptional(t *testing.T) {
	t.Run("tanstack-router-2026 — github: shorthand with commit SHA", func(t *testing.T) {
		manifest := []byte(`{
			"name": "@tanstack/react-router",
			"version": "1.169.5",
			"optionalDependencies": {
				"@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
			}
		}`)
		got := DetectGitDepInOptional(manifest)
		if got != domain.CapGitDepInOptionalDep {
			t.Fatalf("want CapGitDepInOptionalDep, got %v", got)
		}
	})

	t.Run("git+https URL in optionalDependencies", func(t *testing.T) {
		manifest := []byte(`{
			"optionalDependencies": {
				"evil": "git+https://github.com/attacker/evil.git#aabbcc1122334455667788990011223344556677"
			}
		}`)
		got := DetectGitDepInOptional(manifest)
		if got != domain.CapGitDepInOptionalDep {
			t.Fatalf("want CapGitDepInOptionalDep, got %v", got)
		}
	})

	t.Run("git+ssh URL in optionalDependencies", func(t *testing.T) {
		manifest := []byte(`{
			"optionalDependencies": {
				"priv": "git+ssh://git@github.com/org/repo.git#aabbcc1122334455667788990011223344556677"
			}
		}`)
		got := DetectGitDepInOptional(manifest)
		if got != domain.CapGitDepInOptionalDep {
			t.Fatalf("want CapGitDepInOptionalDep, got %v", got)
		}
	})

	t.Run("gitlab: shorthand with commit SHA", func(t *testing.T) {
		manifest := []byte(`{
			"optionalDependencies": {
				"x": "gitlab:org/repo#aabbcc1122334455667788990011223344556677"
			}
		}`)
		got := DetectGitDepInOptional(manifest)
		if got != domain.CapGitDepInOptionalDep {
			t.Fatalf("want CapGitDepInOptionalDep, got %v", got)
		}
	})

	t.Run("bitbucket: shorthand with commit SHA", func(t *testing.T) {
		manifest := []byte(`{
			"optionalDependencies": {
				"x": "bitbucket:org/repo#aabbcc1122334455667788990011223344556677"
			}
		}`)
		got := DetectGitDepInOptional(manifest)
		if got != domain.CapGitDepInOptionalDep {
			t.Fatalf("want CapGitDepInOptionalDep, got %v", got)
		}
	})

	// --- Negative cases (legitimate) ---

	t.Run("clean — semver range", func(t *testing.T) {
		manifest := []byte(`{
			"optionalDependencies": {
				"fsevents": "^2.3.2"
			}
		}`)
		got := DetectGitDepInOptional(manifest)
		if got != 0 {
			t.Errorf("want 0 (no signal), got %v", got)
		}
	})

	t.Run("clean — no optionalDependencies field", func(t *testing.T) {
		manifest := []byte(`{
			"name": "clean-pkg",
			"version": "1.0.0",
			"dependencies": { "lodash": "^4.17.21" }
		}`)
		got := DetectGitDepInOptional(manifest)
		if got != 0 {
			t.Errorf("want 0 (no signal), got %v", got)
		}
	})

	t.Run("clean — tag pin (not a 40-hex SHA)", func(t *testing.T) {
		manifest := []byte(`{
			"optionalDependencies": {
				"some-pkg": "org/repo#v1.2.3"
			}
		}`)
		got := DetectGitDepInOptional(manifest)
		if got != 0 {
			t.Errorf("want 0 (tag pin is not flagged), got %v", got)
		}
	})

	t.Run("clean — empty manifest", func(t *testing.T) {
		got := DetectGitDepInOptional(nil)
		if got != 0 {
			t.Errorf("want 0 on empty input, got %v", got)
		}
	})

	t.Run("clean — malformed JSON", func(t *testing.T) {
		got := DetectGitDepInOptional([]byte(`{not json`))
		if got != 0 {
			t.Errorf("want 0 on malformed JSON, got %v", got)
		}
	})
}

func TestIsCommitSHA(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"79ac49eedf774dd4b0cfa308722bc463cfe5885c", true},
		{"aabbcc1122334455667788990011223344556677", true},
		{"AABBCC1122334455667788990011223344556677", true}, // uppercase OK
		{"v1.2.3", false},
		{"main", false},
		{"79ac49eedf774dd4b0cfa308722bc463cfe5885", false},   // 39 chars
		{"79ac49eedf774dd4b0cfa308722bc463cfe5885cc", false}, // 41 chars
		{"79ac49eedf774dd4b0cfa308722bc463cfe5885g", false},  // non-hex char
		{"", false},
	}
	for _, tc := range cases {
		got := isCommitSHA(tc.s)
		if got != tc.want {
			t.Errorf("isCommitSHA(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}
