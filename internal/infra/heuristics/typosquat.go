package heuristics

import (
	_ "embed"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// topNpmPackagesRaw is a newline-separated list of the most-downloaded
// packages on the npm registry. Embedded at build time so the
// typosquat detector works fully offline. The list is intentionally
// short (~150 entries covering the most-typo-bait names: lodash,
// express, react, ...) — adding more catches more squats but also
// adds false positives where two real packages happen to have
// similar names (electron / electron-builder / electron-store).
//
// The list lives in top_npm_packages.txt next to this file and is
// curated rather than generated, so we can keep it tight.
//
//go:embed top_npm_packages.txt
var topNpmPackagesRaw string

// topNpmPackages is the parsed set, cached at package init.
var topNpmPackages = parseTopList(topNpmPackagesRaw)

func parseTopList(raw string) map[string]bool {
	out := make(map[string]bool, 200)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out
}

// DetectTyposquat flags packages whose name is within Levenshtein
// distance 2 of a top-1000 npm package — but ISN'T itself in that
// list. Catches `electron-stable` (vs `electron`), `lodahs` (vs
// `lodash`), `expresss` (vs `express`), `cross-env-shell` (vs
// `cross-env`).
//
// Returns 0 (no signal) when:
//
//   - not npm (other ecosystems get the same heuristic in their own
//     follow-up PR with their own top-list)
//   - name is itself a top package (no point flagging React as a typo
//     of itself)
//   - distance to the nearest top package is ≥ 3 (false-positive
//     ceiling — at distance 3 most candidates are unrelated)
//
// Weight (domain.WeightTyposquatRisk = 40) deliberately doesn't push
// to Block on its own — heuristics combine with other signals via
// the existing risk scorer.
func DetectTyposquat(eco domain.Ecosystem, name string) domain.Capability {
	if eco != domain.EcoNpm {
		return 0
	}
	if name == "" {
		return 0
	}
	// Strip scope prefix: @foo/bar → bar. Scoped packages can't typo
	// non-scoped ones at the registry level, but the bare name still
	// participates in the comparison (so @attacker/lodash also fires).
	bare := name
	if strings.HasPrefix(bare, "@") {
		if idx := strings.Index(bare, "/"); idx > 0 {
			bare = bare[idx+1:]
		}
	}
	if topNpmPackages[bare] {
		return 0 // it IS a top package — not a squat candidate
	}
	for top := range topNpmPackages {
		// Cheap pre-filter: lengths must be within 2 to be at
		// Levenshtein ≤ 2. Saves the full DP table on most pairs.
		if abs(len(bare)-len(top)) > 2 {
			continue
		}
		if levenshtein(bare, top) <= 2 {
			return domain.CapTyposquatRisk
		}
	}
	return 0
}

// levenshtein returns the edit distance between a and b. Classic
// dynamic programming, no early exit (distances ≤ 2 are quick to
// compute regardless and the pre-filter culls most pairs anyway).
func levenshtein(a, b string) int {
	la := len(a)
	lb := len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(
				prev[j]+1,      // deletion
				curr[j-1]+1,    // insertion
				prev[j-1]+cost, // substitution
			)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
