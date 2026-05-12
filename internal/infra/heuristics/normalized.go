package heuristics

import "github.com/qwexvf/aegis-cli/internal/domain"

// NormalizedPackage is the ecosystem-agnostic representation of a published
// package, produced by an EcosystemParser from the raw manifest and source
// tree. All Check functions operate on this type — no ecosystem switches needed.
type NormalizedPackage struct {
	// Identity
	Name    string
	Version string // semver string of the installed version, e.g. "v1.2.3"
	Eco     domain.Ecosystem

	// Deps is the full dependency list across all groups/scopes.
	// Parsers classify each dep as Registry, VCS, or Local.
	Deps []Dep

	// Hooks are install-time or build-time lifecycle scripts declared
	// in the manifest or source tree (e.g. build.rs for Cargo).
	Hooks []Hook

	// Files is the raw tarball file map (relative path → content).
	// Checks that need raw source access read from here.
	Files map[string][]byte

	// ManifestRaw is the unparsed manifest (package.json, Cargo.toml,
	// pyproject.toml, etc.) for checks that need ecosystem-specific
	// raw parsing (e.g. unlisted payload detection).
	ManifestRaw []byte

	// RetractedVersions lists versions this module has explicitly retracted
	// in its go.mod. Populated by goParser; empty for other ecosystems.
	// checkGoRetract compares pkg.Version against this list.
	RetractedVersions []string
}

// Dep is one entry from a package manifest's dependency list.
type Dep struct {
	Name   string    // package name (best-effort; may be "" for some ecosystems)
	Spec   string    // raw version spec or VCS URL
	Source DepSource // Registry | VCS | Local
	Groups []string  // e.g. "optional", "dev", "test", "peer", "direct"
}

// DepSource classifies how a dependency is resolved.
type DepSource int

const (
	// DepSourceRegistry — resolved from the ecosystem registry by version.
	DepSourceRegistry DepSource = iota
	// DepSourceVCS — resolved from a VCS URL (git+https://, :git =>, git = "...").
	// Bypasses registry immutability; the exact code is unpredictable across installs.
	DepSourceVCS
	// DepSourceLocal — resolved from a local file path (file:, ./path, ../path).
	DepSourceLocal
)

// Hook is one install-time or build-time lifecycle script.
type Hook struct {
	Phase string // "preinstall", "install", "postinstall", "prepare", "build"
	Body  string // full script or file content
}
