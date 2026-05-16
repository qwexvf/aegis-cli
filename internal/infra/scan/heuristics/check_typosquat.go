package heuristics

import (
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// checkTyposquat flags packages whose name is within Levenshtein distance 2
// of a top package in the same ecosystem but isn't in that list itself.
// For scoped packages (@scope/name), the bare name is compared.
func checkTyposquat(pkg NormalizedPackage) []domain.Capability {
	if pkg.Name == "" {
		return nil
	}
	topList, ok := topPackages[pkg.Eco]
	if !ok {
		return nil
	}
	// For scoped npm packages (@scope/name), extract the bare name.
	// @atk/lodash → compare "lodash" (exact match → not a typosquat)
	// @atk/lodahs → compare "lodahs" (distance-1 of lodash → flag)
	compareName := pkg.Name
	if strings.HasPrefix(compareName, "@") {
		if _, after, ok := strings.Cut(compareName, "/"); ok {
			compareName = after
		}
	}
	if topList[compareName] {
		return nil
	}
	for topName := range topList {
		if levenshtein(compareName, topName) <= 2 {
			return []domain.Capability{domain.CapTyposquatRisk}
		}
	}
	return nil
}
