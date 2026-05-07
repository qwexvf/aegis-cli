package locksnap

import (
	"encoding/json"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parsePackagesLockJson parses NuGet's packages.lock.json (introduced
// with the `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`
// MSBuild property in .NET Core 2.1+). Format:
//
//	{
//	  "version": 1,
//	  "dependencies": {
//	    "net8.0": {
//	      "Newtonsoft.Json": {
//	        "type": "Direct",
//	        "requested": "[13.0.3, )",
//	        "resolved": "13.0.3",
//	        "contentHash": "..."
//	      },
//	      "...": { ... }
//	    }
//	  }
//	}
//
// One file per project. We flatten across all target frameworks (a
// single package may appear under multiple TFMs with the same resolved
// version; deduped by canonical name+version).
func parsePackagesLockJson(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	type entry struct {
		Type     string `json:"type"`
		Resolved string `json:"resolved"`
	}
	var doc struct {
		Dependencies map[string]map[string]entry `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("packages.lock.json: %w", err)
	}

	seen := map[string]bool{}
	out := []domain.Dependency{}
	for _, pkgs := range doc.Dependencies {
		for name, e := range pkgs {
			if e.Resolved == "" {
				continue
			}
			key := name + "@" + e.Resolved
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, domain.Dependency{
				Ecosystem: domain.EcoNuGet,
				Name:      name,
				Version:   e.Resolved,
				// `type: "Direct"` means the user's csproj listed it
				// explicitly; `Transitive` means it was pulled in by
				// another package.
				Direct: e.Type == "Direct",
			})
		}
	}
	return out, nil
}
