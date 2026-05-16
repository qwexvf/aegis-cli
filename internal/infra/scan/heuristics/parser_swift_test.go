package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestSwiftParser_Ecosystems(t *testing.T) {
	p := &swiftParser{}
	ecos := p.Ecosystems()
	if len(ecos) != 1 || ecos[0] != domain.EcoSwiftPM {
		t.Fatalf("Ecosystems() = %v; want [swifturl]", ecos)
	}
}

func TestSwiftParser_BranchDep_IsVCS(t *testing.T) {
	packageSwift := []byte(`
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/apple/swift-algorithms", from: "1.0.0"),
        .package(url: "https://github.com/example/unstable", branch: "main"),
        .package(url: "https://github.com/example/pinned", revision: "abc123def"),
    ]
)
`)

	p := &swiftParser{}
	pkg := p.Parse("MyApp", nil, domain.PackageSource{
		Files: map[string][]byte{"Package.swift": packageSwift},
	})

	vcsDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(vcsDeps) != 2 {
		t.Fatalf("want 2 VCS deps (branch + revision), got %d: %v", len(vcsDeps), pkg.Deps)
	}

	urls := make(map[string]bool)
	for _, d := range vcsDeps {
		urls[d.Spec] = true
	}
	if !urls["https://github.com/example/unstable"] {
		t.Error("missing branch dep")
	}
	if !urls["https://github.com/example/pinned"] {
		t.Error("missing revision dep")
	}
}

func TestSwiftParser_RegistryDep(t *testing.T) {
	packageSwift := []byte(`
let package = Package(
    dependencies: [
        .package(url: "https://github.com/apple/swift-algorithms", from: "1.0.0"),
    ]
)
`)

	p := &swiftParser{}
	pkg := p.Parse("MyApp", nil, domain.PackageSource{
		Files: map[string][]byte{"Package.swift": packageSwift},
	})

	regDeps := filterBySource(pkg.Deps, DepSourceRegistry)
	if len(regDeps) != 1 {
		t.Fatalf("want 1 registry dep, got %d: %v", len(regDeps), pkg.Deps)
	}
	if regDeps[0].Name != "https://github.com/apple/swift-algorithms" {
		t.Errorf("name = %q", regDeps[0].Name)
	}
}

func TestSwiftParser_NoDuplicates(t *testing.T) {
	// A URL that matches both branch and from patterns should not be doubled.
	packageSwift := []byte(`
let package = Package(
    dependencies: [
        .package(url: "https://github.com/example/pkg", branch: "main"),
    ]
)
`)

	p := &swiftParser{}
	pkg := p.Parse("MyApp", nil, domain.PackageSource{
		Files: map[string][]byte{"Package.swift": packageSwift},
	})

	if len(pkg.Deps) != 1 {
		t.Errorf("want 1 dep (no duplicates), got %d: %v", len(pkg.Deps), pkg.Deps)
	}
}
