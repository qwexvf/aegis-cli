package image

import (
	"bytes"
	"encoding/json"
	"strings"
)

// manifestKind tags a per-package manifest discovered inside an image
// outside of any recognised lockfile. The walker captures each file
// then dispatches to a kind-specific synthesizer to derive a
// (name, version) pair.
type manifestKind int

const (
	mkNpm manifestKind = iota
	mkPyPIDistInfo
	mkPyPIEggInfo
	mkPackagist
)

// manifestEntry pairs a captured manifest body with its kind so the
// merge step can build domain.Dependency entries without re-classifying.
type manifestEntry struct {
	kind manifestKind
	body []byte
	// nameHint / versionHint are populated by classifyManifestPath when
	// the path itself encodes them (e.g. PyPI's `<name>-<ver>.dist-info/`
	// pattern). npm package.json has no in-path version, so both stay
	// empty and the synthesizer reads the JSON.
	nameHint    string
	versionHint string
}

// classifyManifestPath identifies a per-package manifest from its
// cleaned path (no leading `/`, forward slashes). Returns the manifest
// kind plus any name/version hints derivable from the path itself.
//
// Recognised shapes:
//
//	<...>/node_modules/<pkg>/package.json              → mkNpm
//	<...>/node_modules/@scope/<pkg>/package.json       → mkNpm (scoped)
//	<...>/site-packages/<name>-<ver>.dist-info/METADATA → mkPyPIDistInfo
//	<...>/site-packages/<name>-<ver>.egg-info/PKG-INFO  → mkPyPIEggInfo
//	<...>/vendor/<vendor>/<pkg>/composer.json          → mkPackagist
//
// Bare `package.json` / `composer.json` outside their ecosystem layout
// markers do NOT match — guards against the app-level manifest being
// mistaken for an installed dep.
func classifyManifestPath(p, base string) (kind manifestKind, nameHint, versionHint string, ok bool) {
	switch base {
	case "package.json":
		// Require node_modules/ ancestor — app-level package.json must not match.
		idx := strings.LastIndex(p, "node_modules/")
		if idx < 0 {
			return 0, "", "", false
		}
		rest := p[idx+len("node_modules/"):]
		// rest = "<pkg>/package.json" or "@scope/<pkg>/package.json"
		// must have exactly one or two path segments before package.json
		first, after, hasMore := strings.Cut(rest, "/")
		if !hasMore || after == "" {
			return 0, "", "", false
		}
		if strings.HasPrefix(first, "@") {
			name, sub, hasSub := strings.Cut(after, "/")
			if !hasSub || sub != "package.json" {
				return 0, "", "", false
			}
			return mkNpm, first + "/" + name, "", true
		}
		if after != "package.json" {
			return 0, "", "", false
		}
		return mkNpm, first, "", true

	case "METADATA":
		// Look for parent ".dist-info" segment.
		dir, _, ok := strings.Cut(p, "/METADATA")
		if !ok {
			return 0, "", "", false
		}
		_ = dir
		// Parent dir basename ends with .dist-info; ensure it's inside site-packages-ish layout
		lastSlash := strings.LastIndex(p, "/")
		if lastSlash < 0 {
			return 0, "", "", false
		}
		parent := p[:lastSlash]
		parentLastSlash := strings.LastIndex(parent, "/")
		parentBase := parent
		if parentLastSlash >= 0 {
			parentBase = parent[parentLastSlash+1:]
		}
		if !strings.HasSuffix(parentBase, ".dist-info") {
			return 0, "", "", false
		}
		nv := strings.TrimSuffix(parentBase, ".dist-info")
		name, version, ok := splitPyPINameVer(nv)
		if !ok {
			return 0, "", "", false
		}
		return mkPyPIDistInfo, name, version, true

	case "PKG-INFO":
		lastSlash := strings.LastIndex(p, "/")
		if lastSlash < 0 {
			return 0, "", "", false
		}
		parent := p[:lastSlash]
		parentLastSlash := strings.LastIndex(parent, "/")
		parentBase := parent
		if parentLastSlash >= 0 {
			parentBase = parent[parentLastSlash+1:]
		}
		if !strings.HasSuffix(parentBase, ".egg-info") {
			return 0, "", "", false
		}
		nv := strings.TrimSuffix(parentBase, ".egg-info")
		// egg-info parent may omit version (e.g. requests.egg-info). Try
		// the dash-version split; on failure fall back to name-only and
		// let synthesizePyPI extract Version: from PKG-INFO body.
		if name, version, ok := splitPyPINameVer(nv); ok {
			return mkPyPIEggInfo, name, version, true
		}
		return mkPyPIEggInfo, nv, "", true

	case "composer.json":
		idx := strings.LastIndex(p, "vendor/")
		if idx < 0 {
			return 0, "", "", false
		}
		rest := p[idx+len("vendor/"):]
		// rest = "<vendor>/<pkg>/composer.json"
		vendor, after, hasMore := strings.Cut(rest, "/")
		if !hasMore || after == "" {
			return 0, "", "", false
		}
		// vendor/composer/ is composer's own metadata dir, not a dep
		if vendor == "composer" || vendor == "bin" {
			return 0, "", "", false
		}
		pkg, sub, hasSub := strings.Cut(after, "/")
		if !hasSub || sub != "composer.json" {
			return 0, "", "", false
		}
		return mkPackagist, vendor + "/" + pkg, "", true
	}
	return 0, "", "", false
}

// splitPyPINameVer splits "requests-2.31.0" into ("requests", "2.31.0").
// Finds the last `-` whose successor starts with [0-9]. Returns ok=false
// when the input doesn't encode a version that way.
func splitPyPINameVer(s string) (name, version string, ok bool) {
	for i := len(s) - 1; i > 0; i-- {
		if s[i] != '-' {
			continue
		}
		if i+1 >= len(s) {
			continue
		}
		c := s[i+1]
		if c >= '0' && c <= '9' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// synthesizeNpm reads name + version from an npm package.json body.
// Decodes only the two fields we need; ignores everything else so a
// 50 KB manifest doesn't allocate a full struct tree.
func synthesizeNpm(body []byte) (name, version string, ok bool) {
	var m struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return "", "", false
	}
	if m.Name == "" || m.Version == "" {
		return "", "", false
	}
	return m.Name, m.Version, true
}

// synthesizePyPI extracts Name/Version from a PyPI METADATA or PKG-INFO
// body. RFC822-ish key:value header block; scan the first ~64 lines,
// abort at first blank line (end of headers).
func synthesizePyPI(body []byte) (name, version string, ok bool) {
	const maxLines = 64
	br := bytes.NewReader(body)
	for range maxLines {
		line, err := readLine(br)
		if err != nil {
			break
		}
		if len(line) == 0 {
			break
		}
		k, v, found := strings.Cut(string(line), ":")
		if !found {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Name":
			name = v
		case "Version":
			version = v
		}
		if name != "" && version != "" {
			return name, version, true
		}
	}
	if name != "" && version != "" {
		return name, version, true
	}
	return "", "", false
}

// synthesizePackagist reads name + version from a composer.json. Note:
// composer.json frequently omits "version" (composer infers from VCS
// tags); when missing we return ok=false rather than synthesize a
// versionless dep that would collide with the lockfile-derived entry.
func synthesizePackagist(body []byte) (name, version string, ok bool) {
	var m struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return "", "", false
	}
	if m.Name == "" || m.Version == "" {
		return "", "", false
	}
	return m.Name, m.Version, true
}

// readLine reads one line (LF-terminated) from r, returning the line
// without the trailing newline. Returns io.EOF when no more data.
func readLine(r *bytes.Reader) ([]byte, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
		if b == '\n' {
			// Trim trailing CR.
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			return line, nil
		}
		line = append(line, b)
	}
}
