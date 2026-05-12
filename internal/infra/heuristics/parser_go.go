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
			pkg.RetractedVersions = append(pkg.RetractedVersions, parseGoRetractSingle(body)...)
			pkg.RetractedRanges = append(pkg.RetractedRanges, parseGoRetractRanges(body)...)
		}
	}
	return pkg
}

// goRetractRangePattern matches range-form retract directives:
//
//	retract [v1.0.0, v1.1.0]
var goRetractRangePattern = regexp.MustCompile(`(?m)^\s*retract\s+\[\s*(v[\w.+-]+)\s*,\s*(v[\w.+-]+)\s*\]`)

// parseGoRetractSingle extracts exact single-version retracts from go.mod.
func parseGoRetractSingle(body []byte) []string {
	var versions []string
	for _, m := range goRetractVersionPattern.FindAllSubmatch(body, -1) {
		if len(m) > 1 {
			versions = append(versions, string(m[1]))
		}
	}
	return versions
}

// parseGoRetractRanges extracts inclusive [Low, High] retract ranges from go.mod.
func parseGoRetractRanges(body []byte) []RetractRange {
	var ranges []RetractRange
	for _, m := range goRetractRangePattern.FindAllSubmatch(body, -1) {
		if len(m) > 2 {
			ranges = append(ranges, RetractRange{
				Low:  string(m[1]),
				High: string(m[2]),
			})
		}
	}
	return ranges
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
