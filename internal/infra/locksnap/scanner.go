package locksnap

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Scanner satisfies usecase.LockfileScanner. It auto-detects which
// lockfile (across multiple ecosystems) is present in the project
// directory and parses it into a deduplicated, sorted []Dependency.
//
// Multi-ecosystem rule: when more than one lockfile is present —
// e.g. a polyglot monorepo with both package-lock.json and
// poetry.lock — every match is parsed and the results are merged.
// Each Dependency carries its own Ecosystem so OSV.dev queries map
// to the right database.
//
// Within an ecosystem only the FIRST registered match is parsed (a
// project typically commits to one tool: pnpm OR yarn OR npm). The
// per-ecosystem priority is the registration order of the built-in
// parsers; external Register() calls append to the end and therefore
// have lower priority unless they replace an existing filename.
type Scanner struct{}

// NewScanner builds a Scanner that uses the package-level registry
// (built-in parsers + anything Register'd at composition root).
func NewScanner() *Scanner { return &Scanner{} }

// ScanProject implements usecase.LockfileScanner. Walks every
// registered LockfileParser, parses every matching file, merges the
// results. Returns nil (NOT an error) when no lockfile of any
// recognised kind is found — the caller treats that as an empty
// snapshot.
func (s *Scanner) ScanProject(projectDir string) ([]domain.Dependency, error) {
	direct, _ := readDirectDeps(projectDir) // package.json — JS only; nil for non-JS

	var all []domain.Dependency
	seenEco := make(map[domain.Ecosystem]bool, 4)
	for _, p := range registry {
		// Within an ecosystem only the first match is parsed.
		// Across ecosystems every match is parsed.
		if seenEco[p.Ecosystem()] {
			continue
		}
		path := filepath.Join(projectDir, p.Filename())
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p.Filename(), err)
		}
		deps, err := p.Parse(raw, direct)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p.Filename(), err)
		}
		all = append(all, deps...)
		seenEco[p.Ecosystem()] = true
	}

	if len(all) == 0 {
		return nil, nil
	}
	sortDeps(all)
	return all, nil
}

func sortDeps(deps []domain.Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Ecosystem != deps[j].Ecosystem {
			return deps[i].Ecosystem < deps[j].Ecosystem
		}
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
}
