package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type swiftParser struct{}

func (p *swiftParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoSwiftPM} }

func (p *swiftParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoSwiftPM,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		if strings.ToLower(path.Base(filename)) == "package.swift" {
			pkg.Deps = append(pkg.Deps, parsePackageSwiftDeps(body)...)
		}
	}
	return pkg
}

// swiftBranchDepPattern matches `.package(url: "...", branch: "...")`.
// Branch pins are VCS deps — they resolve to a mutable git ref, not a
// pinned version, so the exact code can change between installs.
var swiftBranchDepPattern = regexp.MustCompile(`(?i)\.package\s*\(\s*url\s*:\s*"([^"]+)"[^)]*branch\s*:\s*"[^"]*"`)

// swiftRevisionDepPattern matches `.package(url: "...", revision: "...")`.
// Revision pins are locked by commit hash, not by a registry tag.
var swiftRevisionDepPattern = regexp.MustCompile(`(?i)\.package\s*\(\s*url\s*:\s*"([^"]+)"[^)]*revision\s*:\s*"[^"]*"`)

// swiftFromDepPattern matches `.package(url: "...", from: "X.Y.Z")` — registry dep.
var swiftFromDepPattern = regexp.MustCompile(`(?i)\.package\s*\(\s*url\s*:\s*"([^"]+)"`)

func parsePackageSwiftDeps(body []byte) []Dep {
	var deps []Dep
	src := string(body)

	// Track which URLs we've already emitted to avoid double-counting.
	seen := make(map[string]bool)

	addIfNew := func(url string, source DepSource) {
		if seen[url] {
			return
		}
		seen[url] = true
		deps = append(deps, Dep{
			Name:   url,
			Spec:   url,
			Source: source,
		})
	}

	for _, m := range swiftBranchDepPattern.FindAllStringSubmatch(src, -1) {
		addIfNew(m[1], DepSourceVCS)
	}
	for _, m := range swiftRevisionDepPattern.FindAllStringSubmatch(src, -1) {
		addIfNew(m[1], DepSourceVCS)
	}
	// Registry deps (.from, .upToNextMajor, .exact) — flag as registry.
	for _, m := range swiftFromDepPattern.FindAllStringSubmatch(src, -1) {
		addIfNew(m[1], DepSourceRegistry)
	}

	return deps
}
