package locksnap

import (
	"encoding/xml"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parsePomXml parses a Maven pom.xml's `<dependencies>` block and
// returns the directly-declared dependencies. Maven canonical names
// are formatted as "groupId:artifactId" (matching OSV.dev's expected
// shape for the Maven ecosystem).
//
// Limitations:
//   - Only direct dependencies are extracted. Transitive resolution
//     requires walking Maven Central / a private mirror, which is out
//     of scope for a lockfile parser. For full transitive coverage,
//     point aegis at gradle.lockfile (if present) which lists every
//     resolved coordinate one per line.
//   - Property substitution (`${some.version}`) is left as-is in the
//     Version field. OSV will simply not match those entries; users
//     should resolve via the build tool first.
//   - <scope>test</scope> entries are excluded — they don't end up in
//     a published artifact. <scope>provided</scope> stays in (could
//     bite at runtime).
//   - <dependencyManagement> declarations are skipped — those are
//     version-coordination metadata, not real dependencies.
func parsePomXml(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	type dep struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
	}
	type deps struct {
		Deps []dep `xml:"dependency"`
	}
	type project struct {
		Dependencies deps `xml:"dependencies"`
	}

	var p project
	if err := xml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("pom.xml: %w", err)
	}

	out := make([]domain.Dependency, 0, len(p.Dependencies.Deps))
	for _, d := range p.Dependencies.Deps {
		if d.Scope == "test" {
			continue
		}
		if d.GroupID == "" || d.ArtifactID == "" || d.Version == "" {
			continue // incomplete entry — probably driven by <dependencyManagement>
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoMaven,
			Name:      d.GroupID + ":" + d.ArtifactID,
			Version:   d.Version,
			Direct:    true,
		})
	}
	return out, nil
}

// parseGradleLockfile parses Gradle's gradle.lockfile (introduced in
// Gradle 6.0). Each non-comment, non-empty line is one resolved
// coordinate of the form:
//
//	groupId:artifactId:version=config1,config2,...
//
// We strip the trailing `=configurations` since aegis doesn't track
// per-configuration scoping. Comments start with `#`. The trailing
// `empty=...` marker line (when present) is skipped.
//
// Unlike pom.xml, gradle.lockfile lists every transitive dependency
// already resolved, so it's the preferred Maven-ecosystem source when
// available.
func parseGradleLockfile(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	out := []domain.Dependency{}
	for _, line := range splitLines(raw) {
		line = trimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		// Strip "=configurations" suffix.
		eq := indexByte(line, '=')
		coord := line
		if eq >= 0 {
			coord = line[:eq]
		}
		if coord == "empty" {
			continue
		}
		// coord = "group:artifact:version"
		parts := splitN(coord, ':', 3)
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := parts[0], parts[1], parts[2]
		if group == "" || artifact == "" || version == "" {
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoMaven,
			Name:      group + ":" + artifact,
			Version:   version,
		})
	}
	return out, nil
}

// --- tiny string helpers (kept local to avoid stdlib bloat in this
// file's testing surface; locksnap already has similar idioms). ---

func splitLines(raw []byte) []string {
	out := []string{}
	start := 0
	for i, b := range raw {
		if b == '\n' {
			out = append(out, string(raw[start:i]))
			start = i + 1
		}
	}
	if start < len(raw) {
		out = append(out, string(raw[start:]))
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func splitN(s string, sep byte, n int) []string {
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
