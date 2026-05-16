package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type rubyParser struct{}

func (p *rubyParser) Ecosystems() []domain.Ecosystem {
	return []domain.Ecosystem{domain.EcoRubyGems}
}

func (p *rubyParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoRubyGems,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		base := strings.ToLower(path.Base(filename))
		if base == "gemfile" || strings.HasSuffix(base, ".gemspec") {
			pkg.Deps = append(pkg.Deps, parseGemfileDeps(body)...)
		}
	}
	return pkg
}

// rubyGitDepPattern matches both Gemfile git-source forms:
//   - Modern keyword:   gem "foo", git: "https://..."
//   - Hash-rocket:      gem "foo", :git => "https://..."
var rubyGitDepPattern = regexp.MustCompile(`(?i)(?:,\s*git:\s*['"]|:git\s*=>\s*['"])`)

// rubyGemNamePattern extracts the gem name from `gem "name", ...`
var rubyGemNamePattern = regexp.MustCompile(`(?i)^\s*gem\s+['"]([^'"]+)['"]`)

func parseGemfileDeps(body []byte) []Dep {
	var deps []Dep
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !rubyGitDepPattern.MatchString(line) {
			continue
		}
		name := ""
		if m := rubyGemNamePattern.FindStringSubmatch(line); len(m) > 1 {
			name = m[1]
		}
		deps = append(deps, Dep{
			Name:   name,
			Spec:   line,
			Source: DepSourceVCS,
		})
	}
	return deps
}
