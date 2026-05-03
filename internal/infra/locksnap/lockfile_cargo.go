package locksnap

import "github.com/qwexvf/aegis-cli/internal/domain"

// parseCargoLock parses Rust's Cargo.lock. The format is identical
// to poetry.lock and uv.lock at the structural level — a series of
// `[[package]]` tables — so we reuse parseTOMLPackages. Cargo emits
// extra fields (source, dependencies, checksum) which the helper
// silently ignores.
//
// All entries are treated as transitive; Cargo.lock doesn't directly
// encode "direct vs transitive" — that information lives in
// Cargo.toml's [dependencies] table, which we don't parse here.
// Treating everything as transitive is conservative for OSV lookup
// (we still query every dep) and only affects the rendered "Direct
// only" filter in `aegis snapshot show` (which falls back to
// "show all" when nothing is marked direct).
func parseCargoLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	pkgs, err := parseTOMLPackages(raw)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Dependency, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoCrates,
			Name:      p.Name,
			Version:   p.Version,
		})
	}
	return out, nil
}
