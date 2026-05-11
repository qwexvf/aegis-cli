package locksnap

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parsePnpmLock reads pnpm-lock.yaml. Rather than pulling in a YAML
// dependency, we hand-parse the small subset of the format we need:
// the `packages:` section is keyed by entries that look like
//
//	v9+ (current):  '@scope/name@1.2.3':
//	v9+ unscoped:   'name@1.2.3':
//	v6-v8 legacy:   /@scope/name@1.2.3:
//	v6-v8 legacy:   /name@1.2.3:
//	pre-v6 legacy:  /name/1.2.3:
//
// We don't try to parse the whole document — we sniff lines at exactly
// 2-space indent (entry depth) ending in ':'. Sub-fields like
// `    resolution:` sit at 4-space indent so they're naturally filtered.
//
// Direct deps come from package.json (passed in via `direct`).
func parsePnpmLock(raw []byte, direct map[string]bool) ([]domain.Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var deps []domain.Dependency
	seen := map[string]bool{}

	inPackages := false
	for scanner.Scan() {
		line := scanner.Text()

		// Section detection: top-level `packages:` introduces our table.
		if !inPackages {
			if line == "packages:" {
				inPackages = true
			}
			continue
		}
		// Leaving the section: another top-level key (no leading space)
		// that ends in ':' marks the end.
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") && line != "packages:" {
			break
		}
		// Entry lines sit at exactly 2-space indent. Sub-fields
		// (resolution:, engines:, peerDependencies:) are 4+, blank
		// lines are 0 — both filtered out.
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent != 2 {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, ":") {
			continue
		}
		entry := strings.TrimSuffix(trimmed, ":")
		entry = strings.Trim(entry, "'\"")
		entry = strings.TrimPrefix(entry, "/")

		// Strip pnpm peer-dep suffix: "name@1.2.3(react@18.0.0)" -> "name@1.2.3"
		if i := strings.Index(entry, "("); i > 0 {
			entry = entry[:i]
		}

		name, version := splitPnpmEntry(entry)
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
			Direct:    direct[name],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return deps, nil
}

// splitPnpmEntry parses one packages-section key into (name, version).
// Three formats are accepted, listed by current popularity:
//
//	"@scope/name@1.2.3"   modern pnpm (v6+) with @ separator
//	"name@1.2.3"          modern pnpm, unscoped
//	"@scope/name/1.2.3"   legacy pnpm (slash separator)
//	"name/1.2.3"          legacy pnpm, unscoped
func splitPnpmEntry(entry string) (string, string) {
	// Modern format first: split on the LAST '@' (so scoped names survive).
	if idx := strings.LastIndex(entry, "@"); idx > 0 {
		// Reject the case where the @ is the scope marker (no second @).
		// "@scope/name" with no version is malformed; skip.
		// In a valid entry, @ at idx must be followed by digits/letters.
		name := entry[:idx]
		ver := entry[idx+1:]
		if ver != "" && !strings.Contains(ver, "/") {
			return name, ver
		}
	}
	// Legacy slash format: split on LAST '/'.
	if idx := strings.LastIndex(entry, "/"); idx > 0 {
		return entry[:idx], entry[idx+1:]
	}
	return "", ""
}
