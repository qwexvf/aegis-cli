package locksnap

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseCabalFreeze parses cabal's cabal.project.freeze. cabal-install 3.x
// qualifies almost every constraint with an "any." prefix:
//
//	constraints: any.aeson ==2.1.2.1,
//	             any.base ==4.17.2.0,
//	             aeson -cffi,
//	             any.bytestring ==0.11.5.3
//
// The first package may appear on the same line as "constraints:".
// Subsequent packages are indented continuation lines. Only "=="
// (cabal's exact-version pin) lines yield a dependency; flag lines like
// "aeson -cffi" carry no "==" and are skipped.
var cabalEntryPattern = regexp.MustCompile(`(\S+)\s+==(\S+?),?\s*$`)

func parseCabalFreeze(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var out []domain.Dependency
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		// Strip "constraints:" prefix if present (first package may be inline).
		if after, ok := strings.CutPrefix(strings.TrimSpace(line), "constraints:"); ok {
			line = after
		}
		m := cabalEntryPattern.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		name, ver := m[1], m[2]
		// cabal qualifies constraints with "any." (any.aeson ==1.0.0);
		// strip it to recover the bare Hackage package name. Without
		// this, modern freeze files — which prefix nearly every entry —
		// parse to zero deps.
		name = strings.TrimPrefix(name, "any.")
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoHackage,
			Name:      name,
			Version:   ver,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cabal.project.freeze scan: %w", err)
	}
	return out, nil
}

// parseStackYamlLock parses stack's stack.yaml.lock. Extra-deps are
// listed as `hackage: name-version@sha256:...,size:N`. Snapshot deps
// are not enumerated in the lock file — only extra-deps appear.
//
// Format (relevant parts):
//
//	packages:
//	- completed:
//	    hackage: aeson-2.1.2.1@sha256:abc,size:12345
//	  original:
//	    hackage: aeson-2.1.2.1@sha256:abc,size:12345
var stackHackagePattern = regexp.MustCompile(`^\s+hackage:\s+(\S+)`)

// hackageNameVer splits "name-version@..." into (name, version).
// Hackage uses the convention that the last hyphen before a digit
// separates name from version.
var hackageNameVerPattern = regexp.MustCompile(`^(.*?)-(\d[^@]*)`)

func parseStackYamlLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var out []domain.Dependency
	seen := make(map[string]bool)

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for sc.Scan() {
		m := stackHackagePattern.FindStringSubmatch(sc.Text())
		if len(m) != 2 {
			continue
		}
		spec := m[1] // e.g. "aeson-2.1.2.1@sha256:abc,size:12345"
		// Strip @sha256:... suffix.
		if idx := strings.IndexByte(spec, '@'); idx >= 0 {
			spec = spec[:idx]
		}
		if seen[spec] {
			continue
		}
		seen[spec] = true

		nv := hackageNameVerPattern.FindStringSubmatch(spec)
		if len(nv) != 3 {
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoHackage,
			Name:      nv[1],
			Version:   nv[2],
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("stack.yaml.lock scan: %w", err)
	}
	return out, nil
}
