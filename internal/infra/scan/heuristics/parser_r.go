package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type rParser struct{}

func (p *rParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoCRAN} }

func (p *rParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoCRAN,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		if strings.ToLower(path.Base(filename)) == "description" {
			pkg.Deps = append(pkg.Deps, parseRDESCRIPTION(body)...)
		}
	}
	return pkg
}

// rRemotesKeyPattern detects the `Remotes:` field header in DESCRIPTION.
// The value may be on the same line or on following indented lines.
var rRemotesKeyPattern = regexp.MustCompile(`(?i)^Remotes:\s*(.*)`)

// rRemotesContinuationPattern matches DESCRIPTION continuation lines
// (indented by at least 4 spaces).
var rRemotesContinuationPattern = regexp.MustCompile(`^\s{4,}(.+)`)

func parseRDESCRIPTION(body []byte) []Dep {
	var deps []Dep

	inRemotes := false
	for line := range strings.SplitSeq(string(body), "\n") {
		if m := rRemotesKeyPattern.FindStringSubmatch(line); len(m) == 2 {
			inRemotes = true
			// Value may be on the same line as "Remotes:".
			deps = append(deps, parseRRemoteEntries(m[1])...)
			continue
		}
		if inRemotes {
			if m := rRemotesContinuationPattern.FindStringSubmatch(line); len(m) == 2 {
				deps = append(deps, parseRRemoteEntries(m[1])...)
				continue
			}
			inRemotes = false
		}
	}
	return deps
}

// parseRRemoteEntries splits a comma-separated list of remote specs
// and classifies each as VCS or local.
func parseRRemoteEntries(raw string) []Dep {
	var deps []Dep
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Local paths: "local::./path" or just "./path"
		if strings.HasPrefix(entry, "local::") || strings.HasPrefix(entry, "./") {
			deps = append(deps, Dep{
				Name:   entry,
				Spec:   entry,
				Source: DepSourceLocal,
			})
			continue
		}
		// VCS remotes: "owner/repo", "github::owner/repo", "git::https://...",
		// "gitlab::owner/repo", "bitbucket::owner/repo"
		deps = append(deps, Dep{
			Name:   entry,
			Spec:   entry,
			Source: DepSourceVCS,
		})
	}
	return deps
}
