package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseMixLock_HexPackages(t *testing.T) {
	raw := []byte(`%{
  "cowboy": {:hex, :cowboy, "2.10.0", "abc123", [:rebar3], [{:cowlib, "~> 2.12", [hex: :cowlib, repo: "hexpm", optional: false]}, {:ranch, "~> 1.8", [hex: :ranch, repo: "hexpm", optional: false]}], "hexpm", "def456"},
  "plug": {:hex, :plug, "1.15.3", "ghi789", [:mix], [], "hexpm", "jkl012"},
}
`)

	deps, err := parseMixLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 hex deps, got %d: %v", len(deps), deps)
	}

	byName := make(map[string]domain.Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	cowboy, ok := byName["cowboy"]
	if !ok {
		t.Fatal("missing cowboy dep")
	}
	if cowboy.Version != "2.10.0" {
		t.Errorf("cowboy version = %q; want 2.10.0", cowboy.Version)
	}
	if cowboy.Ecosystem != domain.EcoGleam {
		t.Errorf("ecosystem = %v; want hex (EcoGleam)", cowboy.Ecosystem)
	}
	if _, ok := byName["plug"]; !ok {
		t.Error("missing plug dep")
	}
}

func TestParseMixLock_GitPackage(t *testing.T) {
	raw := []byte(`%{
  "phoenix": {:git, "https://github.com/phoenixframework/phoenix.git", "abc123sha", [branch: "main"]},
  "normal": {:hex, :normal, "1.0.0", "hash", [:mix], [], "hexpm", "hash2"},
}
`)

	deps, err := parseMixLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 deps, got %d: %v", len(deps), deps)
	}

	byName := make(map[string]domain.Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	// Git dep uses package name (map key), not URL.
	phoenix, ok := byName["phoenix"]
	if !ok {
		t.Fatal("missing phoenix dep")
	}
	if phoenix.Version != "" {
		t.Errorf("git dep version = %q; want empty (no OSV lookup for git deps)", phoenix.Version)
	}
}

func TestParseMixLock_Empty(t *testing.T) {
	deps, err := parseMixLock([]byte("%{\n}\n"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("want 0 deps, got %d", len(deps))
	}
}

func TestParseMixLock_IgnoresNonHexNonGit(t *testing.T) {
	// path dependencies and other exotic sources should be ignored.
	raw := []byte(`%{
  "local": {:path, "../local", []},
}
`)
	deps, err := parseMixLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("path dep should be ignored, got %v", deps)
	}
}
