package locksnap

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// parseNpmLock parses package-lock.json (npm v1 / v2 / v3). It
// understands both the legacy "dependencies" tree (v1) and the
// flat "packages" map (v2/v3) — v3 only emits "packages" but we
// fall through to "dependencies" for older files.
//
// Direct deps are flagged when they appear in the package.json
// `dependencies`/`devDependencies`/etc. (passed in via `direct`).
func parseNpmLock(raw []byte, direct map[string]bool) ([]domain.Dependency, error) {
	var lf struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2 / v3
		Packages map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
			Resolved  string `json:"resolved"`
			Dev       bool   `json:"dev"`
			Optional  bool   `json:"optional"`
		} `json:"packages"`
		// v1
		Dependencies map[string]npmV1Dep `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("decode package-lock.json: %w", err)
	}

	var deps []domain.Dependency
	seen := map[string]bool{}

	if len(lf.Packages) > 0 {
		// v2/v3: flat map. Keys look like:
		//   ""                           -> the project itself (skip)
		//   "node_modules/lodash"        -> top-level lodash
		//   "node_modules/foo/node_modules/bar" -> nested bar
		for path, p := range lf.Packages {
			if path == "" {
				continue
			}
			if p.Version == "" {
				continue
			}
			name := nameFromNpmPath(path)
			if name == "" {
				continue
			}
			key := name + "@" + p.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			deps = append(deps, domain.Dependency{
				Ecosystem: domain.EcoNpm,
				Name:      name,
				Version:   p.Version,
				Integrity: p.Integrity,
				Direct:    direct[name],
			})
		}
		return deps, nil
	}

	// v1 fallback: recursive "dependencies" tree.
	walkV1(lf.Dependencies, direct, seen, &deps)
	return deps, nil
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Integrity    string              `json:"integrity"`
	Dev          bool                `json:"dev"`
	Optional     bool                `json:"optional"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

func walkV1(node map[string]npmV1Dep, direct, seen map[string]bool, out *[]domain.Dependency) {
	for name, d := range node {
		if d.Version == "" {
			continue
		}
		key := name + "@" + d.Version
		if !seen[key] {
			seen[key] = true
			*out = append(*out, domain.Dependency{
				Ecosystem: domain.EcoNpm,
				Name:      name,
				Version:   d.Version,
				Integrity: d.Integrity,
				Direct:    direct[name],
			})
		}
		if len(d.Dependencies) > 0 {
			walkV1(d.Dependencies, direct, seen, out)
		}
	}
}

// nameFromNpmPath extracts the package name from a v2/v3 packages-key
// path. The package name is everything after the LAST "node_modules/"
// segment. Scoped names (with "/") survive because we keep one slash
// after the @ scope.
//
//	"node_modules/lodash"                  -> "lodash"
//	"node_modules/@scope/pkg"              -> "@scope/pkg"
//	"node_modules/foo/node_modules/bar"    -> "bar"
func nameFromNpmPath(p string) string {
	idx := strings.LastIndex(p, "node_modules/")
	if idx < 0 {
		return ""
	}
	return p[idx+len("node_modules/"):]
}
