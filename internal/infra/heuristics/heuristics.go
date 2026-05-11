// Package heuristics implements behavior-based malware detectors that
// run alongside the AST capability scanner and the OSV.dev advisory
// lookup. Where AST detection answers "what does this code do?" and
// OSV answers "is this version known-bad?", the heuristics here
// answer "does this look like malware even though nobody has reported
// it yet?" — closing the zero-day window.
//
// Each detector is a small pure function over the input artefacts:
//
//   - Manifest text (package.json scripts, etc.)
//   - PackageSource (extracted file map, file paths, source bytes)
//   - Package metadata (name, version, ecosystem)
//
// Detectors return additional Capability values that are merged into
// the AST scanner's Fingerprint, so they ride for free through the
// existing scoring / allowlist / presenter pipeline. No new top-level
// concept needed in domain.
package heuristics

import (
	"slices"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// Run executes every package-source-based heuristic over the given
// package and returns the extra capabilities that fired. Order is
// stable. Idempotent — same input always produces the same output.
//
// Caller (Snapshot.Enrich) merges these into the AST-derived
// Fingerprint.Capabilities; from there the existing risk scorer
// picks them up via the heuristic Weight branches in domain.RiskScore.
//
// The maintainer-hijack heuristic is NOT included here because it
// needs registry-side metadata not present in the package source —
// see RunMaintainerSignal.
func Run(eco domain.Ecosystem, name string, manifestRaw []byte, src usecase.PackageSource) []domain.Capability {
	var caps []domain.Capability

	if c := DetectSuspiciousInstallHook(manifestRaw); c != 0 {
		caps = append(caps, c)
	}
	// Cargo's install-time arbitrary-code surface is build.rs, not the
	// manifest. We dedupe so a crate that has both manifest-side and
	// build.rs-side hooks doesn't double-flag.
	if eco == domain.EcoCrates {
		if body, ok := src.Files["build.rs"]; ok {
			if c := DetectCargoBuildHook(body); c != 0 && !hasCapability(caps, c) {
				caps = append(caps, c)
			}
		}
	}
	if c := DetectBinaryDropper(eco, src); c != 0 {
		caps = append(caps, c)
	}
	if c := DetectTyposquat(eco, name); c != 0 {
		caps = append(caps, c)
	}
	if cs := DetectSourcePatterns(src); len(cs) > 0 {
		caps = append(caps, cs...)
	}

	return caps
}

func hasCapability(caps []domain.Capability, want domain.Capability) bool {
	return slices.Contains(caps, want)
}

// RunMaintainerSignal is the second entry point — separated from
// Run because the input shape is different (registry metadata vs
// package source). Snapshot.Enrich calls it after fetching
// MaintainerSignal via the dedicated port. Returns the slice of
// capabilities that fired: hijack-shape, publisher-change, or both.
func RunMaintainerSignal(sig domain.MaintainerSignal) []domain.Capability {
	var caps []domain.Capability
	if c := DetectMaintainerHijackRisk(sig); c != 0 {
		caps = append(caps, c)
	}
	if c := DetectMaintainerChanged(sig); c != 0 {
		caps = append(caps, c)
	}
	return caps
}

// RunTarballDrift is the third entry point — separated for the same
// reason as RunMaintainerSignal (different input shape and optional
// I/O). Snapshot.Enrich calls it after fetching the upstream repo
// tree for the dep's version tag via RepoTreeFetcher. repoFiles=nil
// means the fetch was skipped or failed; the detector treats that as
// "no signal", not "no drift".
func RunTarballDrift(manifestRaw []byte, src usecase.PackageSource, repoFiles []string, repoSubdir string) domain.Capability {
	c, _ := DetectTarballDriftFromSources(manifestRaw, src, repoFiles, repoSubdir)
	return c
}
