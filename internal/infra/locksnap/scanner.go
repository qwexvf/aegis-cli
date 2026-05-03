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
type Scanner struct{}

// NewScanner builds a Scanner.
func NewScanner() *Scanner { return &Scanner{} }

// scanRule pairs a lockfile name with the parser function that
// understands it. Order matters within a single ecosystem (more
// authoritative formats first) but is irrelevant between ecosystems
// since they don't conflict.
type scanRule struct {
	filename string
	parse    func(raw []byte, direct map[string]bool) ([]domain.Dependency, error)
}

// scanRules is the registry. Adding a new lockfile parser is one
// entry here plus one new lockfile_<name>.go file. The ordering
// within an ecosystem (e.g. pnpm > yarn > bun > npm) reflects which
// is most authoritative when multiple JS lockfiles coexist.
var scanRules = []scanRule{
	// JavaScript — pnpm/yarn/bun are stricter than npm; if both
	// are present, the stricter one wins.
	{"pnpm-lock.yaml", parsePnpmLock},
	{"yarn.lock", parseYarnLock},
	{"bun.lock", parseBunLock},
	{"package-lock.json", parseNpmLock},

	// Python — Poetry/pipenv/uv lockfiles are authoritative; the
	// plain requirements.txt is treated as a fallback because many
	// projects ship one without committing to a single tool.
	{"poetry.lock", parsePoetryLock},
	{"uv.lock", parseUvLock},
	{"Pipfile.lock", parsePipfileLock},
	{"requirements.txt", parseRequirementsTxt},

	// Rust
	{"Cargo.lock", parseCargoLock},

	// Go — go.sum is comprehensive (every module in the build graph)
	{"go.sum", parseGoSum},

	// Ruby
	{"Gemfile.lock", parseGemfileLock},
}

// ScanProject implements usecase.LockfileScanner. Walks every
// registered scanRule, parses every matching file, merges the
// results. Returns nil (NOT an error) when no lockfile of any
// recognised kind is found — the caller treats that as an empty
// snapshot.
//
// Within a single ecosystem only the first hit is parsed (e.g. if
// both pnpm-lock.yaml and package-lock.json exist, only the pnpm
// one parses). Across ecosystems every hit is parsed.
func (s *Scanner) ScanProject(projectDir string) ([]domain.Dependency, error) {
	direct, _ := readDirectDeps(projectDir) // package.json — JS only; nil for non-JS

	var all []domain.Dependency
	seenJS := false
	seenPython := false
	for _, rule := range scanRules {
		// Within JS: only first match (the priority order above
		// already encodes which one wins). Same for Python — a
		// project typically commits to one tool.
		if seenJS && isJSLockfile(rule.filename) {
			continue
		}
		if seenPython && isPythonLockfile(rule.filename) {
			continue
		}

		path := filepath.Join(projectDir, rule.filename)
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rule.filename, err)
		}
		deps, err := rule.parse(raw, direct)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", rule.filename, err)
		}
		all = append(all, deps...)
		if isJSLockfile(rule.filename) {
			seenJS = true
		}
		if isPythonLockfile(rule.filename) {
			seenPython = true
		}
	}

	if len(all) == 0 {
		return nil, nil
	}
	sortDeps(all)
	return all, nil
}

// isJSLockfile is the membership test for the JS-ecosystem mutex —
// kept as a function (not a map) because the set is tiny and never
// changes at runtime.
func isJSLockfile(name string) bool {
	switch name {
	case "pnpm-lock.yaml", "yarn.lock", "bun.lock", "package-lock.json":
		return true
	}
	return false
}

// isPythonLockfile is the same idea for Python tooling.
func isPythonLockfile(name string) bool {
	switch name {
	case "poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt":
		return true
	}
	return false
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
