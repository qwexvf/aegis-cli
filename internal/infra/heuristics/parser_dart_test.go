package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestDartParser_Ecosystems(t *testing.T) {
	p := &dartParser{}
	ecos := p.Ecosystems()
	if len(ecos) != 1 || ecos[0] != domain.EcoPub {
		t.Fatalf("Ecosystems() = %v; want [pub]", ecos)
	}
}

func TestDartParser_GitDep(t *testing.T) {
	pubspec := []byte(`
name: my_app
dependencies:
  flutter:
    sdk: flutter
  http:
    git:
      url: https://github.com/dart-lang/http
      ref: main
  path_dep:
    path: ../local_package
  normal: ^1.0.0
dev_dependencies:
  test: ^1.0.0
  dev_git:
    git:
      url: https://github.com/example/dev_pkg
`)

	p := &dartParser{}
	pkg := p.Parse("my_app", nil, domain.PackageSource{
		Files: map[string][]byte{"pubspec.yaml": pubspec},
	})

	gitDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(gitDeps) != 2 {
		t.Fatalf("want 2 git deps, got %d: %v", len(gitDeps), pkg.Deps)
	}

	urls := make(map[string]bool)
	for _, d := range gitDeps {
		urls[d.Spec] = true
	}
	if !urls["https://github.com/dart-lang/http"] {
		t.Error("missing git dep: dart-lang/http")
	}
	if !urls["https://github.com/example/dev_pkg"] {
		t.Error("missing git dep: example/dev_pkg")
	}
}

func TestDartParser_PathDep(t *testing.T) {
	pubspec := []byte(`
name: my_app
dependencies:
  local_pkg:
    path: ../local_pkg
`)

	p := &dartParser{}
	pkg := p.Parse("my_app", nil, domain.PackageSource{
		Files: map[string][]byte{"pubspec.yaml": pubspec},
	})

	localDeps := filterBySource(pkg.Deps, DepSourceLocal)
	if len(localDeps) != 1 {
		t.Fatalf("want 1 local dep, got %d", len(localDeps))
	}
	if localDeps[0].Spec != "../local_pkg" {
		t.Errorf("spec = %q; want ../local_pkg", localDeps[0].Spec)
	}
}

func TestDartParser_NoManifest(t *testing.T) {
	p := &dartParser{}
	pkg := p.Parse("empty", nil, domain.PackageSource{})
	if len(pkg.Deps) != 0 {
		t.Errorf("expected no deps for empty source, got %v", pkg.Deps)
	}
}

func filterBySource(deps []Dep, src DepSource) []Dep {
	var out []Dep
	for _, d := range deps {
		if d.Source == src {
			out = append(out, d)
		}
	}
	return out
}
