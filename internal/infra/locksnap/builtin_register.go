package locksnap

import "github.com/qwexvf/aegis-cli/internal/domain"

// init wires the built-in lockfile parsers into the package-level
// registry at startup. The order here defines per-ecosystem priority
// when multiple lockfiles for the same ecosystem coexist (pnpm wins
// over npm; poetry wins over plain requirements.txt). External code
// calling locksnap.Register() appends after these and therefore has
// lower priority unless it replaces an existing filename.
//
// Adding a new built-in parser:
//  1. Drop a lockfile_<eco>.go file with parseXxx(raw, direct).
//  2. Add one Register call below in the right per-ecosystem slot.
//
// External (out-of-tree) parsers don't need to touch this file —
// see the "Extending" guide in the project docs.
func init() {
	// JavaScript — pnpm/yarn/bun are stricter than npm; if both
	// are present, the stricter one wins.
	Register(newFuncParser("pnpm-lock.yaml", domain.EcoNpm, parsePnpmLock))
	Register(newFuncParser("yarn.lock", domain.EcoNpm, parseYarnLock))
	Register(newFuncParser("bun.lock", domain.EcoNpm, parseBunLock))
	Register(newFuncParser("package-lock.json", domain.EcoNpm, parseNpmLock))

	// Python — Poetry/uv/pipenv lockfiles are authoritative; the
	// plain requirements.txt is the last-resort fallback.
	Register(newFuncParser("poetry.lock", domain.EcoPyPI, parsePoetryLock))
	Register(newFuncParser("uv.lock", domain.EcoPyPI, parseUvLock))
	Register(newFuncParser("Pipfile.lock", domain.EcoPyPI, parsePipfileLock))
	Register(newFuncParser("requirements.txt", domain.EcoPyPI, parseRequirementsTxt))

	// Rust
	Register(newFuncParser("Cargo.lock", domain.EcoCrates, parseCargoLock))

	// Go — go.sum is comprehensive (every module in the build graph)
	Register(newFuncParser("go.sum", domain.EcoGo, parseGoSum))

	// Ruby
	Register(newFuncParser("Gemfile.lock", domain.EcoRubyGems, parseGemfileLock))
}
