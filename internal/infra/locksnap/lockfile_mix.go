package locksnap

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseMixLock parses Elixir's mix.lock. The format is an Elixir term:
//
//	%{
//	  "cowboy": {:hex, :cowboy, "2.10.0", "hash", [:rebar3], [...]},
//	  "phoenix": {:git, "https://github.com/...", "sha", [branch: "main"]},
//	}
//
// Hex packages resolve to OSV ecosystem "Hex" (same as EcoGleam). Git
// packages are included as VCS deps so the git-dep heuristic fires.
var (
	mixHexPattern = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:hex,\s*:\w+,\s*"([^"]+)"`)
	mixGitPattern = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:git,\s*"([^"]+)"`)
)

func parseMixLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var out []domain.Dependency
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := sc.Text()

		if m := mixHexPattern.FindStringSubmatch(line); len(m) == 3 {
			out = append(out, domain.Dependency{
				Ecosystem: domain.EcoGleam, // hex.pm; same OSV ecosystem as Gleam
				Name:      m[1],
				Version:   m[2],
			})
			continue
		}

		if m := mixGitPattern.FindStringSubmatch(line); len(m) == 3 {
			// Git-sourced dep: no registry version. Empty version causes
			// OSV lookup to be skipped (correct — git deps aren't in hex.pm).
			out = append(out, domain.Dependency{
				Ecosystem: domain.EcoGleam,
				Name:      m[1],
				Version:   "",
			})
		}
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("mix.lock scan: %w", err)
	}
	return out, nil
}
