package heuristics

import "github.com/qwexvf/aegis-cli/internal/domain"

// checkVCSDeps fires when any dependency (in any group) is pinned to a VCS
// URL instead of a registry version. Works across all ecosystems whose parsers
// classify VCS deps as DepSourceVCS.
//
// Distinct from checkOptionalGitDep (which targets the specific Mini Shai-Hulud
// optional-dep worm vector): this check covers all groups and uses the lower-
// weight CapVCSDependency signal, which pushes to Prompt alone and to Block
// when combined with other signals.
func checkVCSDeps(pkg NormalizedPackage) []domain.Capability {
	for _, dep := range pkg.Deps {
		if dep.Source == DepSourceVCS {
			return []domain.Capability{domain.CapVCSDependency}
		}
	}
	return nil
}
