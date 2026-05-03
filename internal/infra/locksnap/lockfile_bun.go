package locksnap

import (
	"encoding/json"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseBunLock parses bun.lock. Bun's text lockfile (introduced after
// the bun.lockb bytecode version) is JSONC — JSON with comments and
// trailing commas. Bun's own implementation strips comments before
// parsing; we do the same minimum-viable cleanup.
//
// The shape we care about:
//
//	{
//	  "lockfileVersion": 1,
//	  "packages": {
//	    "lodash": ["lodash@4.17.21", "sha512-..."],
//	    "lodash/sub": ["sub@1.0.0", "sha512-..."]
//	  }
//	}
//
// `packages` is a flat map. Each value is a positional array whose
// first element is "name@version" and second is the integrity hash.
func parseBunLock(raw []byte, direct map[string]bool) ([]domain.Dependency, error) {
	cleaned := stripJSONComments(raw)

	var lf struct {
		Packages map[string][]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(cleaned, &lf); err != nil {
		return nil, err
	}

	var deps []domain.Dependency
	seen := map[string]bool{}

	for _, value := range lf.Packages {
		if len(value) == 0 {
			continue
		}
		var spec string
		if err := json.Unmarshal(value[0], &spec); err != nil {
			continue
		}
		var integrity string
		if len(value) >= 2 {
			_ = json.Unmarshal(value[1], &integrity)
		}
		name, version := splitBunSpec(spec)
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		deps = append(deps, domain.Dependency{
			Ecosystem: domain.EcoNpm,
			Name:      name,
			Version:   version,
			Integrity: integrity,
			Direct:    direct[name],
		})
	}
	return deps, nil
}

// splitBunSpec breaks "name@version" or "@scope/name@version" into
// (name, version), using the LAST '@' as the separator.
func splitBunSpec(spec string) (string, string) {
	if len(spec) == 0 {
		return "", ""
	}
	for i := len(spec) - 1; i > 0; i-- {
		if spec[i] == '@' {
			return spec[:i], spec[i+1:]
		}
	}
	return "", ""
}

// stripJSONComments removes // line and /* block */ comments and
// trailing commas before objects/arrays close. Minimal viable JSONC
// support; not a fully general parser. Strings (incl. escape
// sequences) are respected.
func stripJSONComments(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	i := 0
	inString := false
	for i < len(raw) {
		c := raw[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(raw) {
				out = append(out, raw[i+1])
				i += 2
				continue
			}
			if c == '"' {
				inString = false
			}
			i++
			continue
		}
		// Line comment "//"
		if c == '/' && i+1 < len(raw) && raw[i+1] == '/' {
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			continue
		}
		// Block comment "/* ... */"
		if c == '/' && i+1 < len(raw) && raw[i+1] == '*' {
			i += 2
			for i+1 < len(raw) && !(raw[i] == '*' && raw[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}
		// Trailing comma before } or ].
		if c == ',' {
			j := i + 1
			for j < len(raw) && (raw[j] == ' ' || raw[j] == '\t' || raw[j] == '\n' || raw[j] == '\r') {
				j++
			}
			if j < len(raw) && (raw[j] == '}' || raw[j] == ']') {
				i = j
				continue
			}
		}
		if c == '"' {
			inString = true
		}
		out = append(out, c)
		i++
	}
	return out
}
