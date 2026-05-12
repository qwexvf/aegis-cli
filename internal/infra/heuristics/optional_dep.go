package heuristics

import (
	"strings"
)

// isGitDepSpec returns true when a dependency version spec resolves to
// a git source rather than a semver range. Covers all forms npm accepts:
//
//   - github:org/repo            (GitHub shorthand)
//   - github:org/repo#SHA        (GitHub shorthand + commit pin)
//   - gitlab:org/repo#SHA
//   - bitbucket:org/repo#SHA
//   - git+https://...            (full git URL)
//   - git+ssh://...
//   - git://...
//   - org/repo#<40-hex>          (bare GitHub shorthand, npm resolves as git)
//
// Semver ranges (^, ~, *, x.y.z, workspace:) are explicitly excluded.
func isGitDepSpec(spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return false
	}
	// Explicit git protocol prefixes.
	for _, prefix := range []string{
		"github:", "gitlab:", "bitbucket:", "sourcehut:",
		"git+https://", "git+ssh://", "git+http://", "git://",
	} {
		if strings.HasPrefix(spec, prefix) {
			return true
		}
	}
	// Bare "user/repo" or "user/repo#ref" — npm treats this as GitHub
	// shorthand. A SHA pin (#<40 hex chars>) is the attack-specific shape;
	// we flag it specifically to avoid false-positives on legitimate
	// "user/repo#v1.2.3" tag pins (extremely rare in optionalDeps anyway,
	// but we stay conservative: only flag on 40-hex commit SHAs).
	if _, ref, ok := strings.Cut(spec, "#"); ok {
		if isCommitSHA(ref) {
			return true
		}
	}
	return false
}

// isCommitSHA returns true when s looks like a full 40-character hex SHA1.
func isCommitSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
