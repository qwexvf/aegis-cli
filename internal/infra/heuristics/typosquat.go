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

//go:embed top_pypi_packages.txt
var topPyPIPackagesRaw string

//go:embed top_crates_packages.txt
var topCratesPackagesRaw string

//go:embed top_cran_packages.txt
var topCRANPackagesRaw string

//go:embed top_hackage_packages.txt
var topHackagePackagesRaw string

//go:embed top_cpan_packages.txt
var topCPANPackagesRaw string

// topPackages is the per-ecosystem set of "real" names a typosquat
// candidate is compared against. Adding a new ecosystem is a one-line
// change here plus a top_<ecosystem>_packages.txt file. Ecosystems
// without an entry get DetectTyposquat == 0 (no signal — better silent
// than false-positive).
var topPackages = map[domain.Ecosystem]map[string]bool{
	domain.EcoNpm:     parseTopList(topNpmPackagesRaw),
	domain.EcoPyPI:    parseTopList(topPyPIPackagesRaw),
	domain.EcoCrates:  parseTopList(topCratesPackagesRaw),
	domain.EcoCRAN:    parseTopList(topCRANPackagesRaw),
	domain.EcoHackage: parseTopList(topHackagePackagesRaw),
	domain.EcoCPAN:    parseTopList(topCPANPackagesRaw),
}

func parseTopList(raw string) map[string]bool {
	out := make(map[string]bool, 200)
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out
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
			curr[j] = min(
				prev[j]+1,      // deletion
				curr[j-1]+1,    // insertion
				prev[j-1]+cost, // substitution
			)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
