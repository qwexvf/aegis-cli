package heuristics

import "github.com/qwexvf/aegis-cli/internal/domain"

// checkGoRetract fires when the installed version of a Go module appears in
// that module's own retract list. A retract directive in go.mod is the
// module author's explicit statement that the version is unsafe or broken;
// the Go toolchain warns consumers who have it pinned.
//
// Requires pkg.Version to be set (populated by Pipeline.Run from dep.Version).
// Without a version, the check is a no-op — better silent than noisy.
func checkGoRetract(pkg NormalizedPackage) []domain.Capability {
	if pkg.Version == "" || len(pkg.RetractedVersions) == 0 {
		return nil
	}
	for _, v := range pkg.RetractedVersions {
		if v == pkg.Version {
			return []domain.Capability{domain.CapVersionUnpublished}
		}
	}
	return nil
}
