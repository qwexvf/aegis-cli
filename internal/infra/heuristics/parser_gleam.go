package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type gleamParser struct{}

func (p *gleamParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoGleam} }

func (p *gleamParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoGleam,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		if strings.ToLower(path.Base(filename)) == "gleam.toml" {
			pkg.Deps = append(pkg.Deps, parseGleamTOML(body)...)
		}
	}
	return pkg
}

// gleamGitDepPattern matches git dependencies in gleam.toml [dependencies].
// Gleam supports: pkg = { git = "https://github.com/..." }
var gleamGitDepPattern = regexp.MustCompile(`(?im)[{,]\s*git\s*=\s*"(https?://[^"]+)"`)

// gleamDepNamePattern tries to extract the dependency name (key before =).
var gleamDepNamePattern = regexp.MustCompile(`(?m)^\s*(\w[\w_-]*)\s*=\s*\{[^}]*git\s*=`)

func parseGleamTOML(body []byte) []Dep {
	if !gleamGitDepPattern.Match(body) {
		return nil
	}
	// Extract names by matching the key = { git = ... } pattern line by line.
	nameMatches := gleamDepNamePattern.FindAllSubmatch(body, -1)
	names := make([]string, len(nameMatches))
	for i, m := range nameMatches {
		if len(m) > 1 {
			names[i] = string(m[1])
		}
	}
	urlMatches := gleamGitDepPattern.FindAllSubmatch(body, -1)
	var deps []Dep
	for i, m := range urlMatches {
		depName := ""
		if i < len(names) {
			depName = names[i]
		}
		deps = append(deps, Dep{
			Name:   depName,
			Spec:   string(m[1]),
			Source: DepSourceVCS,
		})
	}
	return deps
}
