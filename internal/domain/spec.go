// Package domain holds entities and policy rules for the Aegis CLI
// install gate. Everything here is pure: no I/O, no env, no logging.
//
// Layering:
//
//	cmd/aegis             ─ composition root
//	  └─ interface/cli    ─ Cobra commands
//	       └─ usecase     ─ orchestration; depends on ports
//	            └─ domain ─ entities + policy (this package)
//	                  ▲
//	            ports ──┘
//	                  ▲
//	            infra ─┘ (concrete adapters)
//
// Domain types are deliberately small and immutable; mutation is the
// use case's job.
package domain

// Ecosystem identifies the package registry universe a spec belongs to.
// Multiple package managers may share an ecosystem (npm + bun + yarn +
// pnpm all sit in EcoNpm; pip + poetry + uv sit in EcoPyPI).
type Ecosystem string

const (
	EcoNpm       Ecosystem = "npm"
	EcoPyPI      Ecosystem = "pypi"
	EcoCrates    Ecosystem = "crates"
	EcoGo        Ecosystem = "go"
	EcoMaven     Ecosystem = "maven"
	EcoRubyGems  Ecosystem = "rubygems"
	EcoPackagist Ecosystem = "packagist"
	EcoNuGet     Ecosystem = "nuget"
	EcoGleam     Ecosystem = "hex"
	EcoPub       Ecosystem = "pub"
	EcoSwiftPM   Ecosystem = "swifturl"
)

// AllEcosystems returns every ecosystem the CLI recognises.
func AllEcosystems() []Ecosystem {
	return []Ecosystem{
		EcoNpm, EcoPyPI, EcoCrates, EcoGo, EcoMaven,
		EcoRubyGems, EcoPackagist, EcoNuGet, EcoGleam,
		EcoPub, EcoSwiftPM,
	}
}

// PackageSpec is one parsed install target. Version is the literal
// string the user wrote (exact pin, range, tag, or empty); the use case
// resolves it to a concrete version through the registry adapter.
type PackageSpec struct {
	Ecosystem   Ecosystem
	Name        string
	Version     string
	Raw         string
	NonRegistry bool
}

// IsExactVersion reports whether Version is a fully-pinned semver
// like "4.17.21". Exact pins skip registry resolution.
func (s PackageSpec) IsExactVersion() bool {
	v := s.Version
	if v == "" {
		return false
	}
	for _, c := range v {
		switch c {
		case '^', '~', '>', '<', '=', ' ', '|', '*', 'x', 'X':
			return false
		}
	}
	dotCount := 0
	hasDigit := false
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '.':
			dotCount++
		case c == '-' || c == '+':
			return hasDigit && dotCount >= 1
		default:
			return false
		}
	}
	return hasDigit && dotCount >= 1
}
