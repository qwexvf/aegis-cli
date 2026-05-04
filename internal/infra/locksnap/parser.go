// LockfileParser is the plugin interface for ecosystem extension.
// Implement it once per lockfile format, register at composition root
// (or via the package-level Register helper for in-tree built-ins),
// and the rest of the pipeline picks the new ecosystem up unchanged:
//
//	     ┌──────────────┐
//	     │  your code   │  one file: implement LockfileParser
//	     └──────┬───────┘
//	            │ Register
//	            ▼
//	     ┌──────────────┐
//	     │   Scanner    │  finds matching files in projectDir
//	     └──────┬───────┘
//	            │ ScanProject
//	            ▼
//	   []domain.Dependency  ──► OSV lookup, AST scan, heuristics
//
// See the "Extending" guide in the project docs for the end-to-end recipe.

package locksnap

import (
	"github.com/qwexvf/aegis-cli/internal/domain"
)

// LockfileParser turns the raw bytes of one lockfile into the
// canonical []domain.Dependency. Implementations are pure functions
// over the input bytes — no I/O, no env, no time.
//
// One parser handles one filename. Multiple parsers for the same
// ecosystem (e.g. four for Python: poetry.lock / uv.lock /
// Pipfile.lock / requirements.txt) register independently; the
// Scanner's mutex rules below decide which one wins when several
// files coexist.
type LockfileParser interface {
	// Filename is the exact file name the parser handles, looked
	// up at the project root. Examples: "package-lock.json",
	// "poetry.lock", "Cargo.lock". Case-sensitive — npm tolerates
	// case-insensitive on Windows but the ecosystem-canonical name
	// is what the parser must use.
	Filename() string

	// Ecosystem identifies which domain.Ecosystem the produced
	// Dependency values belong to. Used by the Scanner's
	// "first-match-per-ecosystem" rule (a project that has both
	// pnpm-lock.yaml and package-lock.json only parses the pnpm one).
	Ecosystem() domain.Ecosystem

	// Parse decodes the lockfile bytes into domain.Dependency
	// values. The `direct` map is non-nil only for npm (read from
	// package.json's dependencies + devDependencies); other
	// ecosystems receive nil and may flag direct vs transitive
	// from data inside their own lockfile.
	//
	// Returns an error only on a corrupt / unsupported file. An
	// empty lockfile (zero deps) is a successful parse with an
	// empty slice, NOT an error.
	Parse(raw []byte, direct map[string]bool) ([]domain.Dependency, error)
}

// Register adds a LockfileParser to the package-level registry the
// default Scanner uses. Idempotent — re-registering the same filename
// replaces the prior parser; useful for tests and for downstream
// distributions that swap out a built-in parser for a fork.
//
// Built-in parsers register themselves in init() inside their own
// lockfile_<eco>.go files. External code calls Register once at
// composition-root startup before constructing the Scanner.
//
// Concurrency: NOT safe for concurrent registrations. Call from
// init() or from the composition root's main goroutine before any
// scan begins.
func Register(p LockfileParser) {
	for i, existing := range registry {
		if existing.Filename() == p.Filename() {
			registry[i] = p // replace
			return
		}
	}
	registry = append(registry, p)
}

// Registered returns a snapshot of every currently-registered
// parser, in registration order. Useful for `aegis doctor`-style
// introspection and tests that need to verify built-ins are wired.
func Registered() []LockfileParser {
	out := make([]LockfileParser, len(registry))
	copy(out, registry)
	return out
}

// registry is the package-level parser list. Built-ins append
// themselves in init() blocks per lockfile_<eco>.go file (see the
// init() at the bottom of each parser file). External code uses
// Register at composition root.
var registry []LockfileParser

// parserFunc is a tiny helper that turns a function literal into a
// LockfileParser — used by the in-tree parsers to register without
// each defining its own wrapper struct.
type parserFunc struct {
	filename string
	eco      domain.Ecosystem
	parse    func(raw []byte, direct map[string]bool) ([]domain.Dependency, error)
}

func (p parserFunc) Filename() string            { return p.filename }
func (p parserFunc) Ecosystem() domain.Ecosystem { return p.eco }
func (p parserFunc) Parse(raw []byte, d map[string]bool) ([]domain.Dependency, error) {
	return p.parse(raw, d)
}

// newFuncParser builds a LockfileParser from a function literal.
// Used inside built-in parser init() blocks. External implementations
// usually define their own struct so they can carry per-parser
// configuration; see the "Extending" guide in the project docs.
func newFuncParser(filename string, eco domain.Ecosystem, fn func(raw []byte, direct map[string]bool) ([]domain.Dependency, error)) LockfileParser {
	return parserFunc{filename: filename, eco: eco, parse: fn}
}
