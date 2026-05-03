package locksnap

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Scanner satisfies usecase.LockfileScanner. It auto-detects which JS
// lockfile is present (npm / pnpm / yarn / bun) and parses it into a
// deduplicated, sorted []Dependency.
//
// Detection order: pnpm-lock.yaml > yarn.lock > bun.lock > package-lock.json.
// (pnpm/yarn/bun are stricter; npm's package-lock often coexists with
// other files in monorepos so it's last.)
type Scanner struct{}

// NewScanner builds a Scanner.
func NewScanner() *Scanner { return &Scanner{} }

// ScanProject implements usecase.LockfileScanner.
func (s *Scanner) ScanProject(projectDir string) ([]domain.Dependency, error) {
	for _, fname := range []string{"pnpm-lock.yaml", "yarn.lock", "bun.lock", "package-lock.json"} {
		path := filepath.Join(projectDir, fname)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", fname, err)
		}
		direct, err := readDirectDeps(projectDir)
		if err != nil {
			// package.json read errors aren't fatal — we just won't
			// know which deps are direct.
			direct = nil
		}
		var deps []domain.Dependency
		switch fname {
		case "package-lock.json":
			deps, err = parseNpmLock(raw, direct)
		case "pnpm-lock.yaml":
			deps, err = parsePnpmLock(raw, direct)
		case "yarn.lock":
			deps, err = parseYarnLock(raw, direct)
		case "bun.lock":
			deps, err = parseBunLock(raw, direct)
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", fname, err)
		}
		sortDeps(deps)
		return deps, nil
	}
	return nil, nil // no lockfile = empty scan, NOT an error
}

func sortDeps(deps []domain.Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
}
