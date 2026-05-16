package heuristics

import "github.com/qwexvf/aegis-cli/internal/domain"

// checkUnlistedPayload fires when the tarball contains a large (≥512 KB)
// code file that is not declared in the package's files allowlist and is
// not under a standard build-output directory.
func checkUnlistedPayload(pkg NormalizedPackage) []domain.Capability {
	if len(pkg.Files) == 0 {
		return nil
	}
	pkgFiles := extractPackageFilesField(pkg.ManifestRaw)
	whitelist := buildUnlistedWhitelist(pkgFiles)
	for filename, body := range pkg.Files {
		if len(body) < unlistedPayloadSizeThreshold {
			continue
		}
		if !isUnlistedCodeFile(filename) {
			continue
		}
		if whitelist(filename) {
			continue
		}
		return []domain.Capability{domain.CapUnlistedLargeFile}
	}
	return nil
}
