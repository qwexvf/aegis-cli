package wrap

import "strings"

// PackageSpec is a parsed npm install target. Version is the literal
// version-or-range string the user wrote (e.g. "4.17.21", "^4.17.0", "latest",
// "" when unspecified). The Raw field preserves the original argv token so we
// can pass non-registry installs through unchanged.
type PackageSpec struct {
	Name    string
	Version string
	Raw     string
	// NonRegistry is true when the install target is a tarball URL, git URL,
	// local path, or anything else we shouldn't try to resolve via the npm
	// registry. We pass these through without checking.
	NonRegistry bool
}

// IsExactVersion reports whether Version is a fully-pinned semver
// (e.g. "4.17.21"). Exact pins don't need registry resolution — we already
// know which version to check. Ranges (^4, ~1.2), tags (latest, next), and
// the empty string return false.
func (s PackageSpec) IsExactVersion() bool {
	v := s.Version
	if v == "" {
		return false
	}
	// Range / comparator characters
	for _, c := range v {
		switch c {
		case '^', '~', '>', '<', '=', ' ', '|', '*', 'x', 'X':
			return false
		}
	}
	// Must look like N.N.N (digits + dots, allowing prerelease/build).
	// Pure digits.dots prefix at minimum.
	dotCount := 0
	hasDigit := false
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '.':
			dotCount++
		case c == '-' || c == '+':
			// prerelease (-rc.1) or build (+sha.abc) — break out, the prefix
			// up to here is what we judge.
			return hasDigit && dotCount >= 1
		default:
			return false
		}
	}
	return hasDigit && dotCount >= 1
}

// IsInstallSubcommand returns true if argv[0] is one of npm's install aliases.
func IsInstallSubcommand(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch argv[0] {
	case "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add":
		return true
	}
	return false
}

// ParseInstallArgs extracts package specs from an `npm install` argv. It
// ignores npm's own flags and only returns positional package arguments. The
// argv passed in must NOT include the leading "install" subcommand token.
func ParseInstallArgs(argv []string) []PackageSpec {
	specs := make([]PackageSpec, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "" {
			continue
		}
		// Skip flags. Long form: --save-dev, --no-fund. Short form: -D.
		// Some npm flags consume a value (e.g. --workspace foo) — handle the
		// common ones explicitly; conservatively skip standalone flag tokens.
		if strings.HasPrefix(a, "-") {
			if takesValue(a) && i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				i++
			}
			continue
		}
		specs = append(specs, parseSpec(a))
	}
	return specs
}

func takesValue(flag string) bool {
	// npm flags that take a separate value token. "--flag=value" form is
	// already handled because the value is glued to the flag.
	switch flag {
	case "--workspace", "-w",
		"--workspaces",
		"--prefix",
		"--registry",
		"--tag",
		"--access":
		return true
	}
	return false
}

func parseSpec(token string) PackageSpec {
	spec := PackageSpec{Raw: token}

	// Non-registry forms we pass through:
	//   tarball:   foo.tgz, https://..., http://..., file:./foo
	//   git:       git+https://..., git://..., github:owner/repo
	//   local:     ./foo, ../foo, /abs/path, ~/foo
	if isNonRegistry(token) {
		spec.NonRegistry = true
		return spec
	}

	// Scoped: @scope/name[@version]
	if strings.HasPrefix(token, "@") {
		// Find the SECOND '@' — the first is the scope marker.
		rest := token[1:]
		idx := strings.Index(rest, "@")
		if idx >= 0 {
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
		strings.HasSuffix(token, ".tgz"),
		strings.HasSuffix(token, ".tar.gz"):
		return true
	}
	return false
}
