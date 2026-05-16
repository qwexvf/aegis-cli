package heuristics

import (
	"fmt"
	"slices"

	"github.com/Masterminds/semver/v3"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// checkGoRetract fires CapVersionUnpublished when the installed version of a
// Go module appears in that module's own retract list or retract range.
// A retract directive is the module author's explicit statement that the
// version is unsafe; the Go toolchain warns consumers who have it pinned.
//
// Requires pkg.Version to be set (populated by Pipeline.Run from dep.Version).
// No-op when version is empty — better silent than noisy.
func checkGoRetract(pkg NormalizedPackage) []domain.Capability {
	if pkg.Version == "" {
		return nil
	}
	// Fast path: exact version match.
	if slices.Contains(pkg.RetractedVersions, pkg.Version) {
		return []domain.Capability{domain.CapVersionUnpublished}
	}
	// Range check: retract [vLow, vHigh] — inclusive on both bounds.
	if len(pkg.RetractedRanges) == 0 {
		return nil
	}
	v, err := semver.NewVersion(pkg.Version)
	if err != nil {
		return nil // unparseable version → skip rather than false-positive
	}
	for _, r := range pkg.RetractedRanges {
		constraint, err := semver.NewConstraint(fmt.Sprintf(">= %s, <= %s", r.Low, r.High))
		if err != nil {
			continue
		}
		if constraint.Check(v) {
			return []domain.Capability{domain.CapVersionUnpublished}
		}
	}
	return nil
}
