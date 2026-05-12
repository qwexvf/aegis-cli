package heuristics

import (
	"github.com/qwexvf/aegis-cli/internal/domain"
)

// EcosystemParser normalizes a raw package manifest and source tree into
// a NormalizedPackage for universal checks.
//
// Adding a new ecosystem:
//  1. Implement this interface in a new parser_<eco>.go file.
//  2. Add the parser to defaultPipeline in heuristics.go.
//  3. No check files need to change.
type EcosystemParser interface {
	// Ecosystems returns the set of ecosystems this parser handles.
	Ecosystems() []domain.Ecosystem
	// Parse extracts the normalized representation. Returns a partial
	// result on error — callers use what they get.
	Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage
}

// Check is a pure function that detects one or more malicious capabilities
// in a normalized package. Returns detected capabilities; nil = clean.
//
// Checks must be pure: no I/O, no global state mutation, same input → same output.
type Check func(pkg NormalizedPackage) []domain.Capability

// Pipeline wires parsers and checks together. Construct via NewPipeline.
type Pipeline struct {
	parsers map[domain.Ecosystem]EcosystemParser
	checks  []Check
}

// NewPipeline builds a Pipeline from a list of parsers and checks.
// If multiple parsers claim the same ecosystem, the last one wins.
func NewPipeline(parsers []EcosystemParser, checks []Check) *Pipeline {
	pm := make(map[domain.Ecosystem]EcosystemParser, len(parsers))
	for _, p := range parsers {
		for _, eco := range p.Ecosystems() {
			pm[eco] = p
		}
	}
	return &Pipeline{parsers: pm, checks: checks}
}

// Run normalizes the input with the registered parser (or a fallback
// if none is registered for eco), executes every check, and returns
// the deduplicated union of all detected capabilities.
func (p *Pipeline) Run(eco domain.Ecosystem, name, version string, manifestRaw []byte, src domain.PackageSource) []domain.Capability {
	var pkg NormalizedPackage
	if parser, ok := p.parsers[eco]; ok {
		pkg = parser.Parse(name, manifestRaw, src)
	} else {
		pkg = NormalizedPackage{
			Eco:         eco,
			Name:        name,
			Files:       src.Files,
			ManifestRaw: manifestRaw,
		}
	}
	pkg.Version = version

	seen := make(map[domain.Capability]struct{})
	var caps []domain.Capability
	for _, check := range p.checks {
		for _, c := range check(pkg) {
			if c == 0 {
				continue
			}
			if _, dup := seen[c]; !dup {
				seen[c] = struct{}{}
				caps = append(caps, c)
			}
		}
	}
	return caps
}
