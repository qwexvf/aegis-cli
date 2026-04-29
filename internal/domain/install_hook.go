package domain

// HookPhase distinguishes when a package-manager-invoked script runs.
// Different ecosystems use different phase names; we map them onto
// these neutral buckets:
//
//	npm:     preinstall   → PhasePreInstall
//	         postinstall  → PhasePostInstall
//	         install      → PhasePostInstall (npm runs both)
//	pip:     setup.py     → PhaseBuild
//	cargo:   build.rs     → PhaseBuild
//	gem:     extconf.rb   → PhaseBuild
//
// Phases are ordered by when-they-fire so policy can reason about
// "anything that runs at install-time" via Phase >= PhasePreInstall.
type HookPhase int

const (
	// PhasePreInstall fires before the package files are placed.
	PhasePreInstall HookPhase = iota + 1
	// PhasePostInstall fires after files are placed.
	PhasePostInstall
	// PhaseBuild fires during compilation/build steps. Distinct from
	// install scripts because some ecosystems (cargo, pip) effectively
	// blur the line.
	PhaseBuild
)

// String returns the canonical name for serialization / display.
func (p HookPhase) String() string {
	switch p {
	case PhasePreInstall:
		return "preinstall"
	case PhasePostInstall:
		return "postinstall"
	case PhaseBuild:
		return "build"
	}
	return "unknown"
}

// InstallHook is one declared script the package manager will run
// automatically at install time. Across ecosystems this maps to the
// concrete sources noted in HookPhase. We carry the source body's
// SHA-256 so version-over-version drift detection can flag a hook
// whose content changed even when its filename didn't.
type InstallHook struct {
	Phase HookPhase
	// Source is a human-readable identifier of where the hook lives,
	// e.g. "scripts.postinstall" / "setup.py" / "build.rs".
	Source string
	// Sha256 is the hex-encoded sha256 of the hook script body. Empty
	// when the body could not be read (e.g. lockfile-only metadata).
	Sha256 string
}
