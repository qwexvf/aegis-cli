package heuristics

import (
	"maps"
	"path"
	"strings"
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
