package locksnap

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parsePubspecLock parses Dart's pubspec.lock. The format is YAML but
// hand-parsed line by line to avoid a YAML dependency. Structure:
//
//	packages:
//	  http:
//	    dependency: "direct main"
//	    description:
//	      name: http
//	      url: "https://pub.dev"
//	    source: hosted
//	    version: "1.2.3"
//
// SDK and path-sourced packages are skipped — they have no pub.dev
// version to query OSV against. Git-sourced packages are included with
// their resolved version (the pinned commit ref) so the VCS heuristic
// can flag them downstream.
func parsePubspecLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var out []domain.Dependency

	type pkgState struct {
		name    string
		source  string
		version string
		direct  bool
	}
	var cur pkgState
	inPackages := false
	inPkg := false

	flush := func() {
		if !inPkg || cur.name == "" || cur.version == "" {
			return
		}
		// sdk and path packages have no pub.dev entry to query.
		if cur.source == "sdk" || cur.source == "path" {
			return
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoPub,
			Name:      cur.name,
			Version:   strings.Trim(cur.version, `"`),
			Direct:    cur.direct,
		})
	}

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Top-level "packages:" section marker.
		if !inPackages {
			if strings.TrimSuffix(trimmed, ":") == "packages" {
				inPackages = true
			}
			continue
		}

		// "sdks:" section ends the packages block.
		if strings.TrimSuffix(trimmed, ":") == "sdks" {
			flush()
			inPkg = false // prevent double-flush after loop exit
			break
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))

		// 2-space indent = new package name (e.g. "  http:").
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			flush()
			cur = pkgState{name: strings.TrimSuffix(trimmed, ":")}
			inPkg = true
			continue
		}

		if !inPkg {
			continue
		}

		// 4-space indent = package fields.
		if indent == 4 {
			key, val, ok := strings.Cut(trimmed, ": ")
			if !ok {
				continue
			}
			val = strings.TrimSpace(val)
			switch key {
			case "dependency":
				cur.direct = strings.Contains(val, "direct")
			case "source":
				cur.source = strings.Trim(val, `"`)
			case "version":
				cur.version = strings.Trim(val, `"`)
			}
		}
	}
	flush()

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("pubspec.lock scan: %w", err)
	}
	return out, nil
}
