package heuristics

import (
	"maps"
	"path"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// unlistedPayloadSizeThreshold is the minimum file size (bytes) that
// triggers the unlisted-large-file check. 512 KB keeps false-positives
// out of the way of legitimate packages that bundle a single large
// compiled output at root (rare but real). The TanStack router_init.js
// was 2.3 MB — more than 4× the threshold.
const unlistedPayloadSizeThreshold = 512_000

// buildOutputPrefixes lists directory prefixes that are expected to
// contain compiled output not present in the upstream repo. Files under
// these prefixes are whitelisted and never flagged as unlisted payloads.
// Keep in sync with tarballdrift.buildOutputDirs.
var buildOutputPrefixes = []string{
	"dist/", "lib/", "build/", "out/", "cjs/", "mjs/",
	"esm/", "umd/", "types/", "typings/", "dts/",
}

// unlistedMetadataFiles are root-level files whose presence in a tarball
// is always expected regardless of the package.json files field.
var unlistedMetadataFiles = map[string]struct{}{
	"package.json":    {},
	"readme.md":       {},
	"readme":          {},
	"license":         {},
	"license.md":      {},
	"license.txt":     {},
	"changelog.md":    {},
	"changelog":       {},
	"notice":          {},
	"authors":         {},
	"contributors.md": {},
}

// DetectUnlistedPayload reports CapUnlistedLargeFile when the tarball
// contains a code file that is:
//
//  1. At least unlistedPayloadSizeThreshold bytes in size.
//  2. A JS/TS/CJS/MJS source file (the attack-relevant extensions).
//  3. Not declared in the package.json "files" allowlist.
//  4. Not under a build-output directory (dist/, lib/, build/, etc.).
//
// This catches the Mini Shai-Hulud router_init.js (2.3 MB) without
// requiring a GitHub tree comparison. The check is purely local:
// tarball + manifest, no network.
//
// manifestRaw is the raw bytes of the tarball's package.json. src.Files
// is the full extracted file map. Returns 0 on malformed input.
func DetectUnlistedPayload(manifestRaw []byte, src usecase.PackageSource) domain.Capability {
	if len(src.Files) == 0 {
		return 0
	}
	// Parse the "files" allowlist from package.json. Absence means no
	// allowlist (every file is implicitly included), but we still check
	// for large unlisted files — the anomaly is the SIZE + LOCATION,
	// not merely the absence from the files field. If the files field is
	// missing, pkgFiles is nil and the whitelist below only covers the
	// hardcoded build-output dirs.
	pkgFiles := extractPackageFilesField(manifestRaw)
	whitelist := buildUnlistedWhitelist(pkgFiles)

	for filename, body := range src.Files {
		if len(body) < unlistedPayloadSizeThreshold {
			continue
		}
		if !isUnlistedCodeFile(filename) {
			continue
		}
		if whitelist(filename) {
			continue
		}
		return domain.CapUnlistedLargeFile
	}
	return 0
}

// buildUnlistedWhitelist returns a predicate that accepts files which
// are expected in a published tarball. Accepts: build-output prefixes,
// metadata literals, and paths matching the package.json "files" field.
func buildUnlistedWhitelist(pkgFiles []string) func(string) bool {
	// Collect literal entries and prefix entries from the files field.
	prefixes := append([]string(nil), buildOutputPrefixes...)
	literals := make(map[string]struct{}, len(unlistedMetadataFiles)+len(pkgFiles))
	maps.Copy(literals, unlistedMetadataFiles)
	for _, p := range pkgFiles {
		p = strings.TrimSpace(strings.TrimPrefix(strings.Trim(p, "/"), "./"))
		if p == "" {
			continue
		}
		lower := strings.ToLower(p)
		literals[lower] = struct{}{}
		// Directory entries act as prefix whitelist.
		if !strings.Contains(p, ".") || strings.HasSuffix(p, "/") {
			prefixes = append(prefixes, strings.TrimSuffix(lower, "/")+"/")
		}
	}
	return func(p string) bool {
		lp := strings.ToLower(strings.TrimPrefix(p, "./"))
		if _, ok := literals[lp]; ok {
			return true
		}
		if _, ok := literals[strings.ToLower(path.Base(lp))]; ok {
			return true
		}
		for _, pref := range prefixes {
			if strings.HasPrefix(lp, pref) {
				return true
			}
		}
		return false
	}
}

// isUnlistedCodeFile returns true for file extensions that could carry
// an executable payload and are worth checking for size anomalies.
// Intentionally narrow (JS-family only) to keep false-positive rate low.
func isUnlistedCodeFile(filename string) bool {
	switch strings.ToLower(path.Ext(filename)) {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".cts", ".mts":
		return true
	}
	return false
}
