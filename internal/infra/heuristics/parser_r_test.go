package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestRParser_Ecosystems(t *testing.T) {
	p := &rParser{}
	ecos := p.Ecosystems()
	if len(ecos) != 1 || ecos[0] != domain.EcoCRAN {
		t.Fatalf("Ecosystems() = %v; want [cran]", ecos)
	}
}

func TestRParser_RemotesGitHub(t *testing.T) {
	desc := []byte(`Package: myapp
Version: 0.1.0
Imports:
    ggplot2,
    dplyr
Remotes:
    hadley/ggplot2,
    tidyverse/dplyr@main
`)

	p := &rParser{}
	pkg := p.Parse("myapp", nil, domain.PackageSource{
		Files: map[string][]byte{"DESCRIPTION": desc},
	})

	vcsDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(vcsDeps) != 2 {
		t.Fatalf("want 2 VCS deps, got %d: %v", len(vcsDeps), pkg.Deps)
	}

	specs := make(map[string]bool)
	for _, d := range vcsDeps {
		specs[d.Spec] = true
	}
	if !specs["hadley/ggplot2"] {
		t.Error("missing hadley/ggplot2")
	}
	if !specs["tidyverse/dplyr@main"] {
		t.Error("missing tidyverse/dplyr@main")
	}
}

func TestRParser_RemotesLocal(t *testing.T) {
	desc := []byte(`Package: myapp
Remotes:
    local::./local_package
`)

	p := &rParser{}
	pkg := p.Parse("myapp", nil, domain.PackageSource{
		Files: map[string][]byte{"DESCRIPTION": desc},
	})

	localDeps := filterBySource(pkg.Deps, DepSourceLocal)
	if len(localDeps) != 1 {
		t.Fatalf("want 1 local dep, got %d: %v", len(localDeps), pkg.Deps)
	}
}

func TestRParser_NoRemotes(t *testing.T) {
	desc := []byte(`Package: myapp
Version: 0.1.0
Imports: ggplot2, dplyr
`)

	p := &rParser{}
	pkg := p.Parse("myapp", nil, domain.PackageSource{
		Files: map[string][]byte{"DESCRIPTION": desc},
	})

	if len(pkg.Deps) != 0 {
		t.Errorf("want no deps without Remotes, got %v", pkg.Deps)
	}
}
