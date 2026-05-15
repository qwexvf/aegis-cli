package locksnap

import (
	"encoding/json"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseRenvLock parses R's renv.lock (JSON). renv is the standard
// reproducible environment tool for R projects. Structure:
//
//	{
//	  "R": {"Version": "4.3.1", ...},
//	  "Packages": {
//	    "ggplot2": {"Package": "ggplot2", "Version": "3.4.4", "Source": "Repository"},
//	    "myGitPkg": {"Package": "myGitPkg", "Version": "1.0.0", "Source": "GitHub",
//	                 "RemoteUsername": "owner", "RemoteRepo": "repo"}
//	  }
//	}
//
// CRAN/Bioconductor-sourced packages are queried against OSV "CRAN".
// GitHub/GitLab/Bitbucket/Local-sourced packages are included with their
// version so the snapshot records them; OSV won't match them, which is
// correct — git deps aren't in the CRAN registry.
func parseRenvLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var doc struct {
		Packages map[string]struct {
			Package string `json:"Package"`
			Version string `json:"Version"`
			Source  string `json:"Source"`
		} `json:"Packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("renv.lock decode: %w", err)
	}

	out := make([]domain.Dependency, 0, len(doc.Packages))
	for _, pkg := range doc.Packages {
		if pkg.Package == "" || pkg.Version == "" {
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoCRAN,
			Name:      pkg.Package,
			Version:   pkg.Version,
			// Direct flag not reliably encoded in renv.lock without
			// cross-referencing DESCRIPTION; treat all as transitive.
		})
	}
	return out, nil
}
