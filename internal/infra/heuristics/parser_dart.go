package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type dartParser struct{}

func (p *dartParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoPub} }

func (p *dartParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoPub,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		if strings.ToLower(path.Base(filename)) == "pubspec.yaml" {
			pkg.Deps = append(pkg.Deps, parsePubspecYAMLDeps(body)...)
		}
	}
	return pkg
}

// pubspecGitURLPattern matches the `url:` line inside a `git:` block.
var pubspecGitURLPattern = regexp.MustCompile(`(?i)^\s+url:\s+(\S+)`)

// pubspecDepNamePattern matches the dependency name line (2-space indent + "name:").
var pubspecDepNamePattern = regexp.MustCompile(`^  (\w[\w_-]*):\s*$`)

func parsePubspecYAMLDeps(body []byte) []Dep {
	var deps []Dep
	lines := strings.Split(string(body), "\n")

	inDepsSection := false
	pendingName := ""
	inGitBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Detect dependencies/dev_dependencies sections.
		if trimmed == "dependencies:" || trimmed == "dev_dependencies:" {
			inDepsSection = true
			pendingName = ""
			inGitBlock = false
			continue
		}

		// Any top-level key (no leading spaces) ends the deps section.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inDepsSection = false
			pendingName = ""
			inGitBlock = false
			continue
		}

		if !inDepsSection {
			continue
		}

		// 2-space indent = dependency name.
		if m := pubspecDepNamePattern.FindStringSubmatch(line); len(m) == 2 {
			pendingName = m[1]
			inGitBlock = false
			continue
		}

		// 4-space indent fields.
		if strings.HasPrefix(line, "    ") {
			if trimmed == "git:" {
				inGitBlock = true
				continue
			}
			if strings.HasPrefix(trimmed, "path:") {
				inGitBlock = false
				if pendingName != "" {
					pathVal := strings.TrimSpace(strings.TrimPrefix(trimmed, "path:"))
					if pathVal != "" {
						deps = append(deps, Dep{
							Name:   pendingName,
							Spec:   pathVal,
							Source: DepSourceLocal,
						})
						pendingName = ""
					}
				}
				continue
			}
		}

		// Inside git: block — look for `url:`.
		if inGitBlock && pendingName != "" {
			if m := pubspecGitURLPattern.FindStringSubmatch(line); len(m) == 2 {
				deps = append(deps, Dep{
					Name:   pendingName,
					Spec:   m[1],
					Source: DepSourceVCS,
				})
				inGitBlock = false
				pendingName = ""
			}
		}
	}
	return deps
}
