package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestGleamParser(t *testing.T) {
	t.Run("git dep in gleam.toml", func(t *testing.T) {
		toml := []byte(`name = "myapp"
version = "1.0.0"

[dependencies]
gleam_stdlib = ">= 0.18.0 and < 2.0.0"
evil_lib = { git = "https://github.com/attacker/evil_lib" }
`)
		p := &gleamParser{}
		pkg := p.Parse("myapp", nil, domain.PackageSource{
			Files: map[string][]byte{"gleam.toml": toml},
		})
		if len(pkg.Deps) == 0 {
			t.Fatal("want VCS dep, got none")
		}
		if pkg.Deps[0].Source != DepSourceVCS {
			t.Errorf("source: got %v want DepSourceVCS", pkg.Deps[0].Source)
		}
	})

	t.Run("clean gleam.toml no git deps", func(t *testing.T) {
		toml := []byte(`name = "myapp"
version = "1.0.0"

[dependencies]
gleam_stdlib = ">= 0.18.0 and < 2.0.0"
`)
		p := &gleamParser{}
		pkg := p.Parse("myapp", nil, domain.PackageSource{
			Files: map[string][]byte{"gleam.toml": toml},
		})
		if len(pkg.Deps) != 0 {
			t.Errorf("unexpected deps: %v", pkg.Deps)
		}
	})

	t.Run("elixir mix.exs git dep", func(t *testing.T) {
		mixExs := []byte(`defmodule MyApp.MixProject do
  def deps do
    [
      {:phoenix, "~> 1.7"},
      {:evil_dep, git: "https://github.com/attacker/evil", branch: "main"},
      {:local_dep, path: "../local"},
    ]
  end
end
`)
		p := &gleamParser{}
		pkg := p.Parse("my_app", nil, domain.PackageSource{
			Files: map[string][]byte{"mix.exs": mixExs},
		})

		gitDeps := filterBySource(pkg.Deps, DepSourceVCS)
		if len(gitDeps) != 1 {
			t.Fatalf("want 1 git dep from mix.exs, got %d: %v", len(gitDeps), pkg.Deps)
		}
		if gitDeps[0].Name != "evil_dep" {
			t.Errorf("dep name = %q; want evil_dep", gitDeps[0].Name)
		}

		localDeps := filterBySource(pkg.Deps, DepSourceLocal)
		if len(localDeps) != 1 {
			t.Fatalf("want 1 local dep from mix.exs, got %d: %v", len(localDeps), pkg.Deps)
		}
	})
}
