package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type perlParser struct{}

func (p *perlParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoCPAN} }

func (p *perlParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoCPAN,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		if strings.ToLower(path.Base(filename)) == "cpanfile" {
			pkg.Deps = append(pkg.Deps, parseCpanfileDeps(body)...)
		}
	}
	return pkg
}

// cpanfileGitPattern matches git-sourced deps in cpanfile (Carton DSL).
// Carton supports:
//
//	requires 'Foo', git => 'https://github.com/...';
//	requires 'Foo::Bar', git => { url => 'https://...', ref => 'main' };
var cpanfileGitPattern = regexp.MustCompile(`(?i)requires\s+['"]([^'"]+)['"][^;]*git\s*=>`)

// cpanfilePathPattern matches path-local deps.
//
//	requires 'Foo', path => './local';
var cpanfilePathPattern = regexp.MustCompile(`(?i)requires\s+['"]([^'"]+)['"][^;]*path\s*=>`)

func parseCpanfileDeps(body []byte) []Dep {
	var deps []Dep
	src := string(body)

	for _, m := range cpanfileGitPattern.FindAllStringSubmatch(src, -1) {
		deps = append(deps, Dep{
			Name:   m[1],
			Spec:   m[1],
			Source: DepSourceVCS,
		})
	}
	for _, m := range cpanfilePathPattern.FindAllStringSubmatch(src, -1) {
		deps = append(deps, Dep{
			Name:   m[1],
			Spec:   m[1],
			Source: DepSourceLocal,
		})
	}
	return deps
}
