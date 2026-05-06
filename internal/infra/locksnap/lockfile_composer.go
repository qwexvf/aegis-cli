package locksnap

import (
	"encoding/json"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseComposerLock parses PHP's composer.lock. Format is JSON with a
// `packages` array (runtime deps) and a `packages-dev` array (dev only).
// Each entry has at least `name` and `version`. We skip dev-only deps —
// they don't ship with the package on Packagist install. Composer uses
// the form "vendor/package" as canonical name (matching OSV.dev's
// expected shape for the Packagist ecosystem).
//
// Direct vs transitive isn't directly encoded; composer.lock is a
// flat post-resolution list. Treat all entries as transitive
// (consistent with cargo / poetry / etc.).
func parseComposerLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var doc struct {
		Packages []pkg `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("composer.lock: %w", err)
	}
	out := make([]domain.Dependency, 0, len(doc.Packages))
	for _, p := range doc.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoPackagist,
			Name:      p.Name,
			Version:   p.Version,
		})
	}
	return out, nil
}
