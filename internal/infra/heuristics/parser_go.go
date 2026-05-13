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
			bv, br := parseGoRetractBlock(body)
			pkg.RetractedVersions = append(pkg.RetractedVersions, bv...)
			pkg.RetractedRanges = append(pkg.RetractedRanges, br...)
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

// goRetractBlockBodyPattern captures the inner body of a block-form retract:
//
//	retract (
//	    v1.0.0
//	    [v1.2.0, v1.3.0]
//	)
var goRetractBlockBodyPattern = regexp.MustCompile(`(?ms)^\s*retract\s*\(([^)]+)\)`)

// goRetractBlockVersionPattern matches a bare version token on a line inside a block.
var goRetractBlockVersionPattern = regexp.MustCompile(`(?m)^\s*(v[\w.+-]+)`)

// goRetractBlockRangePattern matches a range token inside a block body.
var goRetractBlockRangePattern = regexp.MustCompile(`(?m)^\s*\[\s*(v[\w.+-]+)\s*,\s*(v[\w.+-]+)\s*\]`)

// parseGoRetractBlock extracts versions and ranges from block-form retract stanzas:
//
//	retract (
//	    v1.0.0         // single version
//	    [v1.2.0, v1.3.0] // range
//	)
func parseGoRetractBlock(body []byte) (versions []string, ranges []RetractRange) {
	for _, block := range goRetractBlockBodyPattern.FindAllSubmatch(body, -1) {
		if len(block) < 2 {
			continue
		}
		blockBody := block[1]
		// Extract ranges first, then remove them so their version tokens
		// don't get picked up by the single-version pass below.
		for _, m := range goRetractBlockRangePattern.FindAllSubmatch(blockBody, -1) {
			if len(m) > 2 {
				ranges = append(ranges, RetractRange{Low: string(m[1]), High: string(m[2])})
			}
		}
		cleaned := goRetractBlockRangePattern.ReplaceAll(blockBody, nil)
		for _, m := range goRetractBlockVersionPattern.FindAllSubmatch(cleaned, -1) {
			if len(m) > 1 {
				// Skip comment-only lines that happen to start with a v-like token.
				line := strings.TrimSpace(string(m[0]))
				if strings.HasPrefix(line, "//") {
					continue
				}
				versions = append(versions, string(m[1]))
			}
		}
	}
	return
}

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
