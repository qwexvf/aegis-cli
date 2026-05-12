// Package heuristics implements behavior-based malware detectors that
// run alongside the AST capability scanner and the OSV.dev advisory
// lookup.
//
// # Architecture
//
// Input flows through a two-stage pipeline:
//
//  1. EcosystemParser.Parse() normalises a raw manifest + source tree
//     into a NormalizedPackage (ecosystem-agnostic intermediate form).
//
//  2. A fixed set of Check functions each receive the same NormalizedPackage
//     and return any capabilities they detect. Checks are pure functions:
//     no I/O, no global state mutation.
//
// Adding a new ecosystem requires only a new EcosystemParser implementation
// (parser_<eco>.go) + registration in defaultPipeline. No check files change.
//
// Adding a new detection requires only a new Check function (check_*.go) +
// registration in defaultPipeline. No parser files change.
package heuristics

import (
	"github.com/qwexvf/aegis-cli/internal/domain"
)

// defaultPipeline is the production pipeline. Extend by adding parsers or
// checks here; all callers pick up the new behaviour automatically.
var defaultPipeline = NewPipeline(
	[]EcosystemParser{
		&npmParser{},
		&pypiParser{},
		&cargoParser{},
		&rubyParser{},
		&goParser{},
		&mavenParser{},
		&composerParser{},
		&nugetParser{},
		&gleamParser{},
	},
	[]Check{
		checkInstallHooks,    // hook body × malware patterns → CapInstallHookSuspicious
		checkBinaryDropper,   // suspicious binary outside expected paths → CapBinaryDropper
		checkTyposquat,       // name × levenshtein × top-N list → CapTyposquatRisk
		checkSourcePatterns,  // source files × obfuscation/URL/IOC → multiple caps
		checkOptionalGitDep,  // optional VCS dep → CapGitDepInOptionalDep (worm vector)
		checkUnlistedPayload, // large unlisted file → CapUnlistedLargeFile
		checkVCSDeps,         // any VCS dep → CapVCSDependency
		checkGoRetract,       // Go retract directive + version match → CapVersionUnpublished
	},
)

// Run is the backward-compatible entry point. Parses the package with the
// registered ecosystem parser and runs all checks. Callers (snapshot.Enrich,
// analyze.Analyze) don't need to change.
func Run(eco domain.Ecosystem, name, version string, manifestRaw []byte, src domain.PackageSource) []domain.Capability {
	return defaultPipeline.Run(eco, name, version, manifestRaw, src)
}

// RunMaintainerSignal runs the registry-side hijack detectors. Separated
// from Run because the input shape is different (registry metadata vs source).
func RunMaintainerSignal(sig domain.MaintainerSignal) []domain.Capability {
	var caps []domain.Capability
	if c := DetectMaintainerHijackRisk(sig); c != 0 {
		caps = append(caps, c)
	}
	if c := DetectMaintainerChanged(sig); c != 0 {
		caps = append(caps, c)
	}
	if c := DetectVersionUnpublished(sig); c != 0 {
		caps = append(caps, c)
	}
	return caps
}

// RunTarballDrift runs the upstream repo drift detector. Separated for the
// same reason as RunMaintainerSignal. repoFiles=nil means no upstream tree
// was available; the detector returns 0 (no signal).
func RunTarballDrift(manifestRaw []byte, src domain.PackageSource, repoFiles []string, repoSubdir string) domain.Capability {
	c, _ := DetectTarballDriftFromSources(manifestRaw, src, repoFiles, repoSubdir)
	return c
}
