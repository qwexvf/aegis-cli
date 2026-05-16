package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type nugetParser struct{}

func (p *nugetParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoNuGet} }

func (p *nugetParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoNuGet,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		base := strings.ToLower(path.Base(filename))
		ext := strings.ToLower(path.Ext(filename))
		switch {
		case base == "nuget.config":
			pkg.Deps = append(pkg.Deps, parseNuGetConfig(body)...)
		case ext == ".csproj" || ext == ".vbproj" || ext == ".fsproj":
			pkg.Deps = append(pkg.Deps, parseCsProj(body)...)
		case base == "packages.config":
			// packages.config only has registry deps; no VCS signal.
		}
	}
	return pkg
}

// nugetCustomSourcePattern detects custom package source URLs in NuGet.Config.
// The official NuGet feed is nuget.org; any other source is non-standard.
var nugetCustomSourcePattern = regexp.MustCompile(`(?i)<add\s[^>]*key\s*=\s*["'][^"']+["'][^>]*value\s*=\s*["'](https?://[^"']+)["']`)

// nugetHintPathPattern detects <HintPath> references — local DLL/lib
// paths outside the standard NuGet restore location.
var nugetHintPathPattern = regexp.MustCompile(`(?i)<HintPath>\s*([^<]+?)\s*</HintPath>`)

func parseNuGetConfig(body []byte) []Dep {
	var deps []Dep
	for _, m := range nugetCustomSourcePattern.FindAllSubmatch(body, -1) {
		feedURL := strings.TrimSpace(string(m[1]))
		if strings.Contains(strings.ToLower(feedURL), "nuget.org") {
			continue
		}
		// Non-official feed: treat as a suspicious URL dependency.
		deps = append(deps, Dep{
			Name:   feedURL,
			Spec:   feedURL,
			Source: DepSourceVCS, // non-registry source
		})
	}
	return deps
}

func parseCsProj(body []byte) []Dep {
	var deps []Dep
	for _, m := range nugetHintPathPattern.FindAllSubmatch(body, -1) {
		hintPath := strings.TrimSpace(string(m[1]))
		if hintPath == "" {
			continue
		}
		deps = append(deps, Dep{
			Name:   hintPath,
			Spec:   hintPath,
			Source: DepSourceLocal,
		})
	}
	return deps
}
