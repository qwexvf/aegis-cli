package heuristics

import (
	"slices"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// checkOptionalGitDep fires when any optional dependency resolves to a VCS
// URL — the canonical Mini Shai-Hulud worm-propagation injection vector.
// npm's `optionalDependencies` is the specific attack surface, but the check
// is expressed as a universal predicate on NormalizedPackage.Deps so it
// generalises to any ecosystem whose parser marks optional VCS deps.
func checkOptionalGitDep(pkg NormalizedPackage) []domain.Capability {
	for _, dep := range pkg.Deps {
		if dep.Source == DepSourceVCS && slices.Contains(dep.Groups, "optional") {
			return []domain.Capability{domain.CapGitDepInOptionalDep}
		}
	}
	return nil
}
