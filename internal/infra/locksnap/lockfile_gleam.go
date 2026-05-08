package locksnap

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseGleamManifest parses Gleam's manifest.toml lockfile. The format
// is an array of inline TOML tables, one per line:
//
//	packages = [
//	  { name = "gleam_stdlib", version = "0.34.0", ... },
//	]
//
// All deps are from hex.pm. The file doesn't distinguish direct vs
// transitive — every entry is scanned for vulnerabilities.
func parseGleamManifest(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var out []domain.Dependency
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	inPackages := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !inPackages {
			if strings.HasPrefix(line, "packages") && strings.Contains(line, "=") {
				inPackages = true
			}
			continue
		}
		if line == "]" {
			break
		}
		// Each package is an inline table: { name = "...", version = "...", ... }
		if !strings.HasPrefix(line, "{") {
			continue
		}
		name := inlineTableField(line, "name")
		version := inlineTableField(line, "version")
		if name == "" || version == "" {
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoGleam,
			Name:      name,
			Version:   version,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("gleam manifest.toml scan: %w", err)
	}
	return out, nil
}

// inlineTableField extracts the quoted string value for key from an
// inline TOML table string, e.g. `{ name = "foo", version = "1.0" }`.
func inlineTableField(line, key string) string {
	needle := key + ` = "`
	idx := strings.Index(line, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := strings.Index(line[start:], `"`)
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}
