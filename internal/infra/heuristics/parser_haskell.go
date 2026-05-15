package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type haskellParser struct{}

func (p *haskellParser) Ecosystems() []domain.Ecosystem {
	return []domain.Ecosystem{domain.EcoHackage}
}

func (p *haskellParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoHackage,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		switch strings.ToLower(path.Base(filename)) {
		case "cabal.project", "package.yaml":
			pkg.Deps = append(pkg.Deps, parseHaskellProjectDeps(body)...)
		}
	}
	return pkg
}

// haskellPackageYamlGitPattern matches git deps in package.yaml (hpack):
//
//	dependencies:
//	  - name: foo
//	    git: https://github.com/...
var haskellPackageYamlGitPattern = regexp.MustCompile(`(?m)^\s+git:\s+(\S+)`)

func parseHaskellProjectDeps(body []byte) []Dep {
	var deps []Dep

	// cabal.project source-repository-package blocks — parsed line by line.
	// Go regexp has no lookahead, so block regex would consume the first char
	// of the next block; line-by-line avoids that.
	inBlock := false
	for line := range strings.SplitSeq(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "source-repository-package" {
			inBlock = true
			continue
		}
		if inBlock {
			// Non-indented non-empty line ends the block.
			if trimmed != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				inBlock = false
				continue
			}
			if after, ok := strings.CutPrefix(trimmed, "location:"); ok {
				url := strings.TrimSpace(after)
				if url != "" {
					deps = append(deps, Dep{Name: url, Spec: url, Source: DepSourceVCS})
				}
			}
		}
	}

	// package.yaml git deps.
	for _, m := range haskellPackageYamlGitPattern.FindAllStringSubmatch(string(body), -1) {
		deps = append(deps, Dep{
			Name:   m[1],
			Spec:   m[1],
			Source: DepSourceVCS,
		})
	}
	return deps
}
