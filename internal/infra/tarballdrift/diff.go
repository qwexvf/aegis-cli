package tarballdrift

import (
	"path"
	"sort"
	"strings"
)

// DriftEvidence is one tarball path that's missing from the upstream
// repo and not covered by the build-output whitelist. Returned by Diff.
type DriftEvidence struct {
	// Path is the tarball-relative file path that doesn't exist in
	// the repo (without the npm "package/" prefix npm prepends).
	Path string

	// Reason explains why this path crossed the threshold. One of:
	//   "script-file"   — install hook references this path
	//   "code-file"     — non-whitelisted .js/.ts/.cjs/.mjs/.json
	//   "binary-file"   — non-whitelisted .so/.node/.dll/.dylib/.wasm
	Reason string
}

// DiffInputs bundles everything Diff needs into one struct so callers
// don't have to thread positional args through three layers. All
// fields are required; an empty TarballFiles or RepoFiles returns an
// empty result.
type DiffInputs struct {
	// TarballFiles is the file list from the npm tarball, with the
	// leading "package/" segment already stripped. Paths use forward
	// slashes regardless of host OS.
	TarballFiles []string

	// RepoFiles is the file list from the GitHub git tree, paths
	// relative to repo root with forward slashes.
	RepoFiles []string

	// PackageJSONFiles is the value of the "files" field from the
	// tarball's package.json. Anything matching one of these globs
	// (or any prefix expansion thereof) is considered an expected
	// shipped artifact and never flagged as drift.
	PackageJSONFiles []string

	// HookScripts maps install-time phase ("preinstall", "install",
	// "postinstall", "prepare") to its raw script command. We extract
	// any *file path* mentioned in these scripts and require those
	// files to exist in the repo — a postinstall referencing a file
	// that only exists in the tarball is the highest-signal shape.
	HookScripts map[string]string

	// RepoSubdir is set when the package lives in a monorepo
	// subdirectory (e.g. "packages/core/"). Repo paths are matched
	// after stripping this prefix. Empty for top-level packages.
	RepoSubdir string
}

// Diff returns the set of tarball paths that don't exist in the
// upstream repo and don't match the build-output / package.json-files
// whitelist. Order is stable (sorted by path) so callers can hash
// the result.
//
// The function is pure: no I/O. Network calls happen in client.go;
// path normalization happens here so the signal is testable in
// isolation.
func Diff(in DiffInputs) []DriftEvidence {
	if len(in.TarballFiles) == 0 || len(in.RepoFiles) == 0 {
		return nil
	}

	repoSet := make(map[string]struct{}, len(in.RepoFiles))
	subdir := strings.Trim(in.RepoSubdir, "/")
	for _, p := range in.RepoFiles {
		p = strings.TrimPrefix(p, "./")
		p = strings.Trim(p, "/")
		if subdir != "" {
			rest, ok := strings.CutPrefix(p, subdir+"/")
			if !ok {
				continue
			}
			p = rest
		}
		repoSet[strings.ToLower(p)] = struct{}{}
	}

	hookFiles := extractHookScriptPaths(in.HookScripts)
	whitelisted := buildWhitelist(in.PackageJSONFiles)

	out := make([]DriftEvidence, 0, 8)
	for _, raw := range in.TarballFiles {
		clean := strings.TrimPrefix(raw, "./")
		clean = strings.Trim(clean, "/")
		if clean == "" || strings.HasSuffix(clean, "/") {
			continue
		}
		if _, ok := repoSet[strings.ToLower(clean)]; ok {
			continue
		}
		// Files referenced in install hooks are highest signal: if
		// the script says `node ./scripts/setup.js` and there's no
		// `scripts/setup.js` in the repo, that script was added at
		// publish-time only.
		if hookFiles[strings.ToLower(clean)] {
			out = append(out, DriftEvidence{Path: clean, Reason: "script-file"})
			continue
		}
		if whitelisted(clean) {
			continue
		}
		if isCodeFile(clean) {
			out = append(out, DriftEvidence{Path: clean, Reason: "code-file"})
			continue
		}
		if isBinaryArtifact(clean) {
			out = append(out, DriftEvidence{Path: clean, Reason: "binary-file"})
			continue
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// buildOutputDirs are the path prefixes we treat as "expected to
// contain compiled output not present in the repo". A package that
// only generates these dirs during `npm publish` (most modern TS
// libraries) is intentional and not a drift signal.
var buildOutputDirs = []string{
	"dist/", "lib/", "build/", "out/", "cjs/", "mjs/", "esm/", "umd/",
	"types/", "typings/", "dts/",
}

// buildWhitelist returns a fast path-predicate that accepts:
//   - anything under a known build-output dir
//   - common publish-time metadata files (LICENSE, README, package.json, ...)
//   - anything matching a path or glob from package.json `files`
//
// We don't implement full glob semantics — npm's `files` field is
// typically directory- or extension-shaped, so prefix matching covers
// real-world cases without pulling a glob library. Asterisks in the
// pattern are honoured as "any chars except slash".
func buildWhitelist(pkgFiles []string) func(string) bool {
	prefixes := append([]string(nil), buildOutputDirs...)
	literals := map[string]struct{}{
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

	// Patterns from package.json "files".
	var globs []string
	for _, p := range pkgFiles {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, "./")
		p = strings.Trim(p, "/")
		if p == "" {
			continue
		}
		if strings.ContainsAny(p, "*?") {
			globs = append(globs, p)
			continue
		}
		// Directory entry — add as prefix.
		prefixes = append(prefixes, strings.ToLower(p)+"/")
		literals[strings.ToLower(p)] = struct{}{}
	}

	return func(p string) bool {
		lp := strings.ToLower(p)
		if _, ok := literals[lp]; ok {
			return true
		}
		// Common publish-time docs in any case.
		base := strings.ToLower(path.Base(lp))
		switch base {
		case "readme.md", "readme", "license", "license.md", "license.txt",
			"changelog.md", "changelog", "notice", "authors", "contributors.md":
			return true
		}
		for _, pref := range prefixes {
			if strings.HasPrefix(lp, pref) {
				return true
			}
		}
		for _, g := range globs {
			if matchSimpleGlob(g, p) {
				return true
			}
		}
		return false
	}
}

// matchSimpleGlob implements a minimal glob: `*` matches any chars
// except `/`, everything else is literal. Sufficient for npm `files`
// patterns like `dist/**/*.js` — we treat `**` as `*` (over-matches,
// which is correct on the whitelist side: false-negatives there
// just mean we'd never flag a drift on a path the maintainer
// explicitly opted in to anyway).
func matchSimpleGlob(pattern, name string) bool {
	pattern = strings.ReplaceAll(pattern, "**", "*")
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)
	return matchGlobSegments(pattern, name)
}

func matchGlobSegments(pat, s string) bool {
	for {
		if pat == "" {
			return s == ""
		}
		if pat[0] == '*' {
			// Try every split of s and recurse.
			rest := pat[1:]
			for i := 0; i <= len(s); i++ {
				if i > 0 && s[i-1] == '/' {
					// '*' doesn't cross path separators.
					break
				}
				if matchGlobSegments(rest, s[i:]) {
					return true
				}
			}
			return false
		}
		if s == "" || pat[0] != s[0] {
			return false
		}
		pat, s = pat[1:], s[1:]
	}
}

// codeExtensions is the set of file extensions that, when found in
// a tarball but not the repo, are worth surfacing. These are the
// shapes used to deliver a payload — keep narrow to avoid noise.
var codeExtensions = map[string]struct{}{
	".js":   {},
	".cjs":  {},
	".mjs":  {},
	".jsx":  {},
	".ts":   {},
	".tsx":  {},
	".json": {}, // includes embedded data + config payloads
	".sh":   {},
	".bat":  {},
	".ps1":  {},
}

// binaryArtifacts are the file shapes that ship runnable code outside
// the JS world: native node addons, shared libs, web-assembly. The
// CapBinaryDropper detector already flags suspicious binaries; this
// keeps the drift signal focused on path-presence specifically.
var binaryArtifacts = map[string]struct{}{
	".node":  {},
	".so":    {},
	".dll":   {},
	".dylib": {},
	".wasm":  {},
	".exe":   {},
}

func isCodeFile(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	_, ok := codeExtensions[ext]
	return ok
}

func isBinaryArtifact(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	_, ok := binaryArtifacts[ext]
	return ok
}

// extractHookScriptPaths pulls the relative file paths mentioned in
// install hook script bodies. We're deliberately lax — any token
// that looks like `./path/to/file.ext` or `path/to/file.ext` is
// considered "referenced". False positives here mean we'd require
// a file to exist that doesn't really matter; that's safe (we'd
// fail to flag, not over-flag) since these only matter when paired
// with absence from the repo.
func extractHookScriptPaths(hooks map[string]string) map[string]bool {
	out := make(map[string]bool, len(hooks))
	for _, body := range hooks {
		for _, tok := range tokenizeShell(body) {
			tok = strings.TrimPrefix(tok, "./")
			if !strings.Contains(tok, "/") && !strings.Contains(tok, ".") {
				continue
			}
			if strings.HasPrefix(tok, "-") || strings.Contains(tok, "://") {
				continue
			}
			// Reject anything that doesn't look like a file path.
			if ext := strings.ToLower(path.Ext(tok)); ext == "" {
				continue
			}
			out[strings.ToLower(tok)] = true
		}
	}
	return out
}

// tokenizeShell does a brain-dead whitespace split — sufficient for
// the install-hook bodies we see in the wild (single-line commands).
// Quoted strings are not unwrapped; that's fine because a path
// inside `"..."` still passes the ext check.
func tokenizeShell(body string) []string {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	fields := strings.FieldsFunc(body, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', ';', '|', '&', '(', ')', '`':
			return true
		}
		return false
	})
	return fields
}
