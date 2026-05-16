package heuristics

import "github.com/qwexvf/aegis-cli/internal/domain"

// checkBinaryDropper flags packages that ship a native executable or
// platform-specific script outside the expected locations for their ecosystem.
func checkBinaryDropper(pkg NormalizedPackage) []domain.Capability {
	for fpath := range pkg.Files {
		if isSuspiciousBinary(fpath) && !isExpectedNativePath(pkg.Eco, fpath) {
			return []domain.Capability{domain.CapBinaryDropper}
		}
	}
	return nil
}
