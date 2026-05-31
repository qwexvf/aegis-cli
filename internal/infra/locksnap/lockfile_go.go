package locksnap

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// goModulePathPattern matches the characters a Go module path may contain.
// Go escapes uppercase letters as "!x", so paths are effectively lowercase
// plus digits and a few separators. This rejects control chars, spaces, and
// other junk that should never appear in a go.sum module field.
var goModulePathPattern = regexp.MustCompile(`^[a-zA-Z0-9._~/!+-]+$`)

func isValidGoModulePath(s string) bool {
	return s != "" && len(s) <= 512 && goModulePathPattern.MatchString(s)
}

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
		// A go.sum line is exactly: "<module> <version> <h1:hash>".
		// Version is a semver ("vX.Y.Z", possibly "/go.mod"-suffixed);
		// the hash is base64 prefixed with "h1:". Anything else is not a
		// go.sum entry — reject it so arbitrary/garbage text (or a
		// control-char-laden module name) can't be smuggled in as a dep.
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		module := fields[0]
		version := strings.TrimSuffix(fields[1], "/go.mod")
		if !strings.HasPrefix(version, "v") || !strings.HasPrefix(fields[2], "h1:") {
			continue
		}
		if !isValidGoModulePath(module) {
			continue
		}
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
