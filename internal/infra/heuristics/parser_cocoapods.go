package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type cocoaPodsParser struct{}

func (p *cocoaPodsParser) Ecosystems() []domain.Ecosystem {
	return []domain.Ecosystem{domain.EcoCocoaPods}
}

func (p *cocoaPodsParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoCocoaPods,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		if strings.ToLower(path.Base(filename)) == "podspec" ||
			strings.HasSuffix(strings.ToLower(filename), ".podspec") ||
			strings.HasSuffix(strings.ToLower(filename), ".podspec.json") {
			pkg.Deps = append(pkg.Deps, parsePodspecDeps(body)...)
		}
	}
	return pkg
}

// podspecGitPattern matches git-sourced dependency declarations in .podspec:
//
//	s.dependency 'SomePod', :git => 'https://github.com/...'
//	pod 'SomePod', :git => 'https://github.com/...'
var podspecGitPattern = regexp.MustCompile(`(?i):git\s*=>\s*['"]([^'"]+)['"]`)

// podspecDepNamePattern extracts the pod name from a dependency line.
var podspecDepNamePattern = regexp.MustCompile(`(?i)(?:s\.dependency|dependency|pod)\s+['"]([^'"]+)['"]`)

func parsePodspecDeps(body []byte) []Dep {
	var deps []Dep
	for line := range strings.SplitSeq(string(body), "\n") {
		if !podspecGitPattern.MatchString(line) {
			continue
		}
		name := ""
		if m := podspecDepNamePattern.FindStringSubmatch(line); len(m) == 2 {
			name = m[1]
		}
		urlMatch := podspecGitPattern.FindStringSubmatch(line)
		url := ""
		if len(urlMatch) == 2 {
			url = urlMatch[1]
		}
		deps = append(deps, Dep{
			Name:   name,
			Spec:   url,
			Source: DepSourceVCS,
		})
	}
	return deps
}
