package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type goParser struct{}

func (p *goParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoGo} }

func (p *goParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoGo,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		if strings.ToLower(path.Base(filename)) == "go.mod" {
			pkg.Deps = append(pkg.Deps, parseGoMod(body)...)
			pkg.RetractedVersions = append(pkg.RetractedVersions, parseGoRetract(body)...)
		}
	}
	return pkg
}

// parseGoRetract extracts explicitly retracted versions from go.mod bytes.
// A retract directive signals that the module author considers that version
// unsafe or broken; consumers pinned to it should upgrade.
func parseGoRetract(body []byte) []string {
	var versions []string
	for _, m := range goRetractVersionPattern.FindAllSubmatch(body, -1) {
		if len(m) > 1 {
			versions = append(versions, string(m[1]))
		}
	}
	return versions
}

// goReplaceTargetPattern captures the replacement module path (after =>) in a
// go.mod replace directive. The => operator only appears in replace stanzas.
var goReplaceTargetPattern = regexp.MustCompile(`=>\s+(\S+)`)

// goRetractVersionPattern matches single-version retract directives:
//
//	retract v1.0.0
//	retract v1.0.0 // reason comment
var goRetractVersionPattern = regexp.MustCompile(`(?m)^\s*retract\s+(v[\w.+-]+)`)

// parseGoMod extracts replace directives from go.mod bytes.
// External replaces (not ./ or ../) are flagged as DepSourceVCS because
// published modules must not redirect dependencies to external paths —
// any such redirect bypasses the module proxy's immutability guarantee.
func parseGoMod(body []byte) []Dep {
	var deps []Dep
	for _, m := range goReplaceTargetPattern.FindAllSubmatchIndex(body, -1) {
		target := strings.TrimSpace(string(body[m[2]:m[3]]))
		if target == "" {
			continue
		}
		source := DepSourceVCS
		if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
			source = DepSourceLocal
		}
		deps = append(deps, Dep{
			Name:   target,
			Spec:   "replace",
			Source: source,
		})
	}
	return deps
}
