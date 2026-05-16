package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type cargoParser struct{}

func (p *cargoParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoCrates} }

func (p *cargoParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoCrates,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		base := strings.ToLower(path.Base(filename))
		switch base {
		case "cargo.toml":
			pkg.Deps = append(pkg.Deps, parseCargoTOMLDeps(body)...)
		case "build.rs":
			if len(body) > 0 {
				pkg.Hooks = append(pkg.Hooks, Hook{Phase: "build", Body: string(body)})
			}
		}
	}
	return pkg
}

// cargoGitDepPattern matches git = "..." in Cargo.toml in two forms:
//   - Explicit table:  git = "https://..." at line start
//   - Inline table:    pkg = { git = "https://..." } (after { or ,)
var cargoGitDepPattern = regexp.MustCompile("(?im)(?:^\\s*git\\s*=\\s*\"https?://|[{,]\\s*git\\s*=\\s*\"https?://)")

// cargoPathDepPattern matches path = "../..." local dependencies.
var cargoPathDepPattern = regexp.MustCompile("(?im)(?:^\\s*path\\s*=\\s*\"|[{,]\\s*path\\s*=\\s*\")")

// parseCargoTOMLDeps extracts dependency specs from Cargo.toml bytes.
// Full TOML parsing is avoided; regex is sufficient for detecting
// git and path dependency forms.
func parseCargoTOMLDeps(body []byte) []Dep {
	var deps []Dep
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if cargoGitDepPattern.MatchString(line) {
			deps = append(deps, Dep{
				Name:   extractCargoDepName(line),
				Spec:   "git",
				Source: DepSourceVCS,
			})
		} else if cargoPathDepPattern.MatchString(line) {
			deps = append(deps, Dep{
				Name:   extractCargoDepName(line),
				Spec:   "path",
				Source: DepSourceLocal,
			})
		}
	}
	return deps
}

// extractCargoDepName attempts to parse the crate name from an inline
// Cargo.toml dep line: `serde = { git = "..." }` → "serde".
// Returns "" when the name cannot be determined (e.g. explicit table form).
func extractCargoDepName(line string) string {
	// Inline form: `name = { ... }` — name is before the first `=`
	if idx := strings.Index(line, "="); idx > 0 {
		candidate := strings.TrimSpace(line[:idx])
		// Skip TOML keys that aren't crate names (git, version, path, etc.)
		switch candidate {
		case "git", "path", "version", "branch", "tag", "rev", "features":
			return ""
		}
		return candidate
	}
	return ""
}
