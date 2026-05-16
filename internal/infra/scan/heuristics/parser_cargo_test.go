package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestCargoParser_Ecosystems(t *testing.T) {
	p := &cargoParser{}
	ecos := p.Ecosystems()
	if len(ecos) != 1 || ecos[0] != domain.EcoCrates {
		t.Fatalf("Ecosystems() = %v; want [crates]", ecos)
	}
}

func TestCargoParser_GitDep_InlineTable(t *testing.T) {
	cargoToml := []byte(`
[package]
name = "my-crate"
version = "0.1.0"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
evil-crate = { git = "https://github.com/attacker/evil" }
local-crate = { path = "../local" }
`)

	p := &cargoParser{}
	pkg := p.Parse("my-crate", nil, domain.PackageSource{
		Files: map[string][]byte{"Cargo.toml": cargoToml},
	})

	gitDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(gitDeps) != 1 {
		t.Fatalf("want 1 git dep, got %d: %v", len(gitDeps), pkg.Deps)
	}
	if gitDeps[0].Name != "evil-crate" {
		t.Errorf("dep name = %q; want evil-crate", gitDeps[0].Name)
	}
}

func TestCargoParser_PathDep(t *testing.T) {
	cargoToml := []byte(`
[dependencies]
my-local = { path = "../my-local" }
`)

	p := &cargoParser{}
	pkg := p.Parse("app", nil, domain.PackageSource{
		Files: map[string][]byte{"Cargo.toml": cargoToml},
	})

	localDeps := filterBySource(pkg.Deps, DepSourceLocal)
	if len(localDeps) != 1 {
		t.Fatalf("want 1 local dep, got %d: %v", len(localDeps), pkg.Deps)
	}
}

func TestCargoParser_GitDep_ExplicitTable(t *testing.T) {
	// Explicit table form: [dependencies.evil-crate]\ngit = "..."
	cargoToml := []byte(`
[dependencies.evil-crate]
git = "https://github.com/attacker/evil"
branch = "main"
`)

	p := &cargoParser{}
	pkg := p.Parse("app", nil, domain.PackageSource{
		Files: map[string][]byte{"Cargo.toml": cargoToml},
	})

	gitDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(gitDeps) != 1 {
		t.Fatalf("want 1 git dep (explicit table form), got %d: %v", len(gitDeps), pkg.Deps)
	}
}

func TestCargoParser_BuildRs_PopulatesHook(t *testing.T) {
	buildRs := []byte(`fn main() { println!("cargo:rerun-if-changed=build.rs"); }`)

	p := &cargoParser{}
	pkg := p.Parse("crate", nil, domain.PackageSource{
		Files: map[string][]byte{"build.rs": buildRs},
	})

	if len(pkg.Hooks) != 1 {
		t.Fatalf("want 1 hook for build.rs, got %d", len(pkg.Hooks))
	}
	if pkg.Hooks[0].Phase != "build" {
		t.Errorf("phase = %q; want build", pkg.Hooks[0].Phase)
	}
}

func TestCargoParser_NoFiles(t *testing.T) {
	p := &cargoParser{}
	pkg := p.Parse("empty", nil, domain.PackageSource{})
	if len(pkg.Deps) != 0 || len(pkg.Hooks) != 0 {
		t.Errorf("expected empty result for no files, got deps=%v hooks=%v", pkg.Deps, pkg.Hooks)
	}
}
