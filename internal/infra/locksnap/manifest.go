package locksnap

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// readDirectDeps reads package.json and returns the set of direct
// dependency names (the union of dependencies, devDependencies,
// peerDependencies, optionalDependencies). Used to mark Direct=true
// on the corresponding lockfile entries.
//
// Missing or malformed package.json returns (nil, err). Callers
// should treat this as best-effort — if we can't tell what's direct,
// we still produce a useful snapshot.
func readDirectDeps(projectDir string) (map[string]bool, error) {
	path := filepath.Join(projectDir, "package.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, m := range []map[string]string{
		pj.Dependencies, pj.DevDependencies, pj.PeerDependencies, pj.OptionalDependencies,
	} {
		for k := range m {
			out[k] = true
		}
	}
	return out, nil
}
