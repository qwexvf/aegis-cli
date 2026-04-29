// Package pm models a package manager (npm, bun, yarn, ...) for the Aegis
// CLI install gate. Each supported manager implements PackageManager;
// Runner provides the PM-agnostic decide/render/block/exec orchestration.
package pm

import "strings"

// PackageSpec is a parsed install target. Version is the literal
// version-or-range string the user wrote (e.g. "4.17.21", "^4.17.0",
// "latest", "" when unspecified). Raw preserves the original argv token
// so non-registry installs pass through unchanged.
type PackageSpec struct {
	Name        string
	Version     string
	Raw         string
	NonRegistry bool
}

// IsExactVersion reports whether Version is a fully-pinned semver
// (e.g. "4.17.21"). Exact pins skip registry resolution.
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

// PackageManager describes a single CLI tool the gate wraps.
type PackageManager interface {
	// Name is the canonical CLI name ("npm", "bun", "yarn").
	Name() string
	// Ecosystem is the registry ecosystem string passed to the API
	// ("npm" for npm/bun/yarn, "pypi" for pip/poetry/uv, ...).
	Ecosystem() string
	// IsInstallCommand returns true when argv represents an install/add
	// invocation that should be gated. argv is the full sub-argv as
	// received by the wrapper (subcommand at argv[0]).
	IsInstallCommand(argv []string) bool
	// ParseInstallArgs extracts package specs from the install argv.
	// argv here is the FULL install argv including the leading
	// subcommand token(s) — implementations strip what they need.
	// (yarn strips "global add"; npm/bun strip a single token.)
	ParseInstallArgs(argv []string) []PackageSpec
	// Exec delegates to the real package-manager binary with the
	// original argv. It is responsible for stdio pass-through and
	// propagating the child's exit code.
	Exec(args []string) error
}

// parseSpec splits an install token into name+version. Used by every PM.
func parseSpec(token string) PackageSpec {
	spec := PackageSpec{Raw: token}

	if isNonRegistry(token) {
		spec.NonRegistry = true
		return spec
	}

	// Scoped: @scope/name[@version]
	if strings.HasPrefix(token, "@") {
		rest := token[1:]
		if idx := strings.Index(rest, "@"); idx >= 0 {
			spec.Name = "@" + rest[:idx]
			spec.Version = rest[idx+1:]
		} else {
			spec.Name = token
		}
		return spec
	}

	// Unscoped: name[@version]
	if idx := strings.Index(token, "@"); idx > 0 {
		spec.Name = token[:idx]
		spec.Version = token[idx+1:]
	} else {
		spec.Name = token
	}
	return spec
}

// isNonRegistry covers prefixes/suffixes shared across npm/bun/yarn:
// local paths, tarballs, http(s), git, github, file:, link:, workspace:,
// and yarn-berry protocols (patch:, portal:, exec:, npm:).
func isNonRegistry(token string) bool {
	switch {
	case strings.HasPrefix(token, "./"),
		strings.HasPrefix(token, "../"),
		strings.HasPrefix(token, "/"),
		strings.HasPrefix(token, "~"),
		strings.HasPrefix(token, "http://"),
		strings.HasPrefix(token, "https://"),
		strings.HasPrefix(token, "git://"),
		strings.HasPrefix(token, "git+"),
		strings.HasPrefix(token, "file:"),
		strings.HasPrefix(token, "github:"),
		strings.HasPrefix(token, "link:"),
		strings.HasPrefix(token, "workspace:"),
		strings.HasPrefix(token, "patch:"),
		strings.HasPrefix(token, "portal:"),
		strings.HasPrefix(token, "exec:"),
		strings.HasPrefix(token, "npm:"),
		strings.HasSuffix(token, ".tgz"),
		strings.HasSuffix(token, ".tar.gz"):
		return true
	}
	return false
}
