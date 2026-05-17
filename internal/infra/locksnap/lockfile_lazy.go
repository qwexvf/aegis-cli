package locksnap

import (
	"encoding/json"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseLazyLock parses lazy.nvim's lazy-lock.json — the dominant
// Neovim plugin manager. Schema is a JSON object keyed by plugin name:
//
//	{
//	  "telescope.nvim": { "branch": "master", "commit": "abc123..." },
//	  "nvim-treesitter": { "branch": "main", "commit": "def456..." }
//	}
//
// Some entries carry only `commit`; some include `version` (semver pin)
// or `tag`. The commit SHA is the canonical Version for diff purposes
// because it's the only field that uniquely pins source.
//
// Branch / version / tag are ignored at parse time — they're cosmetic
// for users; the commit SHA is what aegis tracks.
func parseLazyLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var entries map[string]lazyEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("lazy-lock.json: %w", err)
	}
	out := make([]domain.Dependency, 0, len(entries))
	for name, e := range entries {
		if e.Commit == "" {
			// Skip entries without a commit SHA — nothing to pin.
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoNeovim,
			Name:      name,
			Version:   e.Commit,
		})
	}
	return out, nil
}

// lazyEntry mirrors lazy.nvim's lock entry. Only `commit` is consumed;
// other fields are decoded for forward compatibility but ignored.
type lazyEntry struct {
	Branch  string `json:"branch,omitempty"`
	Commit  string `json:"commit"`
	Tag     string `json:"tag,omitempty"`
	Version string `json:"version,omitempty"`
}
