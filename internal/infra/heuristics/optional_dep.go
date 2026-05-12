package heuristics

import (
	"encoding/json"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// DetectGitDepInOptional parses a package.json manifest and fires
// when any optionalDependencies entry resolves to a git commit rather
// than a semver range.
//
// No legitimate published npm package ships with git-SHA pins in
// optionalDependencies. This is the canonical worm-propagation
// injection vector: the 2026 Mini Shai-Hulud campaign injected
//
//	"optionalDependencies": {
//	  "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
//	}
//
// into 84 @tanstack/* packages. npm resolves such deps by fetching the
// orphan commit at install time, which then runs its prepare lifecycle
// hook — executing the payload. The && exit 1 trick makes the optional
// dep "fail" silently so no error appears in install output.
//
// The heuristic also catches worm-spread packages: the worm's
// updateTarball() routine injects the same entry into any package
// published from an infected CI environment.
//
// Returns CapGitDepInOptionalDep when any entry fires; 0 otherwise.
// Gracefully returns 0 on malformed or absent manifest.
func DetectGitDepInOptional(manifestRaw []byte) domain.Capability {
	if len(manifestRaw) == 0 {
		return 0
	}
	var pkg struct {
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(manifestRaw, &pkg); err != nil {
		return 0
	}
	for _, spec := range pkg.OptionalDependencies {
		if isGitDepSpec(spec) {
			return domain.CapGitDepInOptionalDep
		}
	}
	return 0
}

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
