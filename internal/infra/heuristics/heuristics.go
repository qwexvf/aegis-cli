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
	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// Run executes every heuristic over the given package and returns the
// extra capabilities that fired. Order is stable. Idempotent — same
// input always produces the same output.
//
// Caller (Snapshot.Enrich) merges these into the AST-derived
// Fingerprint.Capabilities; from there the existing risk scorer
// picks them up via the new WeightInstallHookSuspicious /
// WeightObfuscatedPayload / WeightSuspiciousURL / WeightBinaryDropper /
// WeightTyposquatRisk branches in domain.RiskScore.
func Run(eco domain.Ecosystem, name string, manifestRaw []byte, src usecase.PackageSource) []domain.Capability {
	var caps []domain.Capability

	if c := DetectSuspiciousInstallHook(manifestRaw); c != 0 {
		caps = append(caps, c)
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
