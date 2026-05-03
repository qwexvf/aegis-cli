package locksnap

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseGoSum parses Go's go.sum file. Each entry is two lines:
//
//	github.com/foo/bar v1.2.3 h1:<base64-sha>
//	github.com/foo/bar v1.2.3/go.mod h1:<base64-sha>
//
// We dedupe per (module, version) tuple so each module appears once,
// not twice. Versions starting with `v0.0.0-` are pseudo-versions
// (date+commit) — we keep them verbatim because OSV.dev's Go
// ecosystem matches against the same string.
//
// All entries are treated as transitive — go.sum lists everything
// in the module graph. Direct deps live in go.mod's `require ()`
// block; reading that and cross-referencing is a follow-up.
func parseGoSum(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	seen := make(map[string]bool)
	var out []domain.Dependency
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Field 1: module path. Field 2: version (possibly with
		// "/go.mod" suffix on the second line of each pair).
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		module := fields[0]
		version := strings.TrimSuffix(fields[1], "/go.mod")
		key := module + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoGo,
			Name:      module,
			Version:   version,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("go.sum scan: %w", err)
	}
	return out, nil
}
