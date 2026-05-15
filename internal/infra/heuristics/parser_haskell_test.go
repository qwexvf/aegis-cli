package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestHaskellParser_Ecosystems(t *testing.T) {
	p := &haskellParser{}
	ecos := p.Ecosystems()
	if len(ecos) != 1 || ecos[0] != domain.EcoHackage {
		t.Fatalf("Ecosystems() = %v; want [hackage]", ecos)
	}
}

func TestHaskellParser_CabalProjectGitDep(t *testing.T) {
	cabalProject := []byte(`packages: .

source-repository-package
  type: git
  location: https://github.com/haskell/aeson
  tag: v2.1.2.1

source-repository-package
  type: git
  location: https://github.com/example/private-lib
  branch: main
`)

	p := &haskellParser{}
	pkg := p.Parse("myapp", nil, domain.PackageSource{
		Files: map[string][]byte{"cabal.project": cabalProject},
	})

	vcsDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(vcsDeps) != 2 {
		t.Fatalf("want 2 VCS deps, got %d: %v", len(vcsDeps), pkg.Deps)
	}

	urls := make(map[string]bool)
	for _, d := range vcsDeps {
		urls[d.Spec] = true
	}
	if !urls["https://github.com/haskell/aeson"] {
		t.Error("missing aeson git dep")
	}
	if !urls["https://github.com/example/private-lib"] {
		t.Error("missing private-lib git dep")
	}
}

func TestHaskellParser_PackageYamlGitDep(t *testing.T) {
	packageYaml := []byte(`name: myapp
version: 0.1.0.0
dependencies:
  - base >= 4.7 && < 5
  - name: custom-pkg
    git: https://github.com/example/custom-pkg
    commit: abc123
`)

	p := &haskellParser{}
	pkg := p.Parse("myapp", nil, domain.PackageSource{
		Files: map[string][]byte{"package.yaml": packageYaml},
	})

	vcsDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(vcsDeps) != 1 {
		t.Fatalf("want 1 VCS dep, got %d: %v", len(vcsDeps), pkg.Deps)
	}
	if vcsDeps[0].Spec != "https://github.com/example/custom-pkg" {
		t.Errorf("spec = %q; want github URL", vcsDeps[0].Spec)
	}
}

func TestHaskellParser_NoGitDeps(t *testing.T) {
	cabalProject := []byte(`packages: .
`)
	p := &haskellParser{}
	pkg := p.Parse("myapp", nil, domain.PackageSource{
		Files: map[string][]byte{"cabal.project": cabalProject},
	})
	if len(pkg.Deps) != 0 {
		t.Errorf("want no deps, got %v", pkg.Deps)
	}
}
