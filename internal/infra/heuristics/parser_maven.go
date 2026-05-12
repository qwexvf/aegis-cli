package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type mavenParser struct{}

func (p *mavenParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoMaven} }

func (p *mavenParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoMaven,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		base := strings.ToLower(path.Base(filename))
		if base == "pom.xml" {
			pkg.Deps = append(pkg.Deps, parsePomXMLDeps(body)...)
			pkg.Hooks = append(pkg.Hooks, parsePomXMLHooks(body)...)
		}
	}
	return pkg
}

// mavenSystemPathPattern detects <systemPath> declarations — local jar
// references outside the repository. These bypass Maven's dependency
// resolution and are rare in legitimate published artifacts.
var mavenSystemPathPattern = regexp.MustCompile(`(?i)<systemPath>\s*([^<]+?)\s*</systemPath>`)

// mavenExecPluginPattern detects exec-maven-plugin declarations. This
// plugin can run arbitrary shell commands at build time and is the Maven
// equivalent of npm's postinstall hook.
var mavenExecPluginPattern = regexp.MustCompile(`(?i)<artifactId>\s*exec-maven-plugin\s*</artifactId>`)

// mavenExecutablePattern extracts the <executable> value from exec-maven-plugin config.
var mavenExecutablePattern = regexp.MustCompile(`(?i)<executable>\s*([^<]+?)\s*</executable>`)

func parsePomXMLDeps(body []byte) []Dep {
	var deps []Dep
	for _, m := range mavenSystemPathPattern.FindAllSubmatch(body, -1) {
		deps = append(deps, Dep{
			Name:   string(m[1]),
			Spec:   "systemPath",
			Source: DepSourceLocal,
		})
	}
	return deps
}

func parsePomXMLHooks(body []byte) []Hook {
	if !mavenExecPluginPattern.Match(body) {
		return nil
	}
	// Try to extract the executable for hook body; fall back to sentinel.
	hookBody := "exec-maven-plugin"
	if m := mavenExecutablePattern.FindSubmatch(body); len(m) > 1 {
		hookBody = string(m[1])
	}
	return []Hook{{Phase: "build", Body: hookBody}}
}
