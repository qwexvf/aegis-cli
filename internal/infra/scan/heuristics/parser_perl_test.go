package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestPerlParser_Ecosystems(t *testing.T) {
	p := &perlParser{}
	ecos := p.Ecosystems()
	if len(ecos) != 1 || ecos[0] != domain.EcoCPAN {
		t.Fatalf("Ecosystems() = %v; want [cpan]", ecos)
	}
}

func TestPerlParser_GitDep(t *testing.T) {
	cpanfile := []byte(`requires 'Moose', '2.0';
requires 'MyPrivate::Module', git => 'https://github.com/example/private-module';
requires 'Another::Git', '0', git => 'https://github.com/example/other', ref => 'main';
`)

	p := &perlParser{}
	pkg := p.Parse("myapp", nil, domain.PackageSource{
		Files: map[string][]byte{"cpanfile": cpanfile},
	})

	vcsDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(vcsDeps) != 2 {
		t.Fatalf("want 2 VCS deps, got %d: %v", len(vcsDeps), pkg.Deps)
	}

	names := make(map[string]bool)
	for _, d := range vcsDeps {
		names[d.Name] = true
	}
	if !names["MyPrivate::Module"] {
		t.Error("missing MyPrivate::Module")
	}
	if !names["Another::Git"] {
		t.Error("missing Another::Git")
	}
}

func TestPerlParser_PathDep(t *testing.T) {
	cpanfile := []byte(`requires 'Local::Module', path => './local_lib';
`)

	p := &perlParser{}
	pkg := p.Parse("myapp", nil, domain.PackageSource{
		Files: map[string][]byte{"cpanfile": cpanfile},
	})

	localDeps := filterBySource(pkg.Deps, DepSourceLocal)
	if len(localDeps) != 1 {
		t.Fatalf("want 1 local dep, got %d: %v", len(localDeps), pkg.Deps)
	}
	if localDeps[0].Name != "Local::Module" {
		t.Errorf("name = %q; want Local::Module", localDeps[0].Name)
	}
}

func TestPerlParser_RegistryOnly_NoVCSDeps(t *testing.T) {
	cpanfile := []byte(`requires 'Moose', '2.0';
requires 'DBI', '1.643';
requires 'Plack', '1.0';
`)

	p := &perlParser{}
	pkg := p.Parse("myapp", nil, domain.PackageSource{
		Files: map[string][]byte{"cpanfile": cpanfile},
	})

	if len(pkg.Deps) != 0 {
		t.Errorf("registry-only cpanfile should produce no deps, got %v", pkg.Deps)
	}
}
