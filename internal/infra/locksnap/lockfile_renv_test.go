package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseRenvLock_CRANPackages(t *testing.T) {
	raw := []byte(`{
  "R": {"Version": "4.3.1", "Repositories": [{"Name": "CRAN", "URL": "https://cran.rstudio.com"}]},
  "Packages": {
    "ggplot2": {
      "Package": "ggplot2",
      "Version": "3.4.4",
      "Source": "Repository",
      "Repository": "CRAN"
    },
    "dplyr": {
      "Package": "dplyr",
      "Version": "1.1.3",
      "Source": "Repository",
      "Repository": "CRAN"
    }
  }
}`)

	deps, err := parseRenvLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 deps, got %d: %v", len(deps), deps)
	}
	for _, d := range deps {
		if d.Ecosystem != domain.EcoCRAN {
			t.Errorf("%s: ecosystem = %v; want cran", d.Name, d.Ecosystem)
		}
	}
	byName := make(map[string]domain.Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}
	if d, ok := byName["ggplot2"]; !ok {
		t.Error("missing ggplot2")
	} else if d.Version != "3.4.4" {
		t.Errorf("ggplot2 version = %q; want 3.4.4", d.Version)
	}
}

func TestParseRenvLock_GitHubPackage(t *testing.T) {
	raw := []byte(`{
  "Packages": {
    "myPkg": {
      "Package": "myPkg",
      "Version": "0.1.0",
      "Source": "GitHub",
      "RemoteUsername": "owner",
      "RemoteRepo": "myPkg",
      "RemoteSha": "abc123"
    }
  }
}`)

	deps, err := parseRenvLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("want 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "myPkg" || deps[0].Version != "0.1.0" {
		t.Errorf("unexpected dep: %+v", deps[0])
	}
}

func TestParseRenvLock_SkipsEmptyVersion(t *testing.T) {
	raw := []byte(`{
  "Packages": {
    "broken": {"Package": "broken", "Version": "", "Source": "Repository"}
  }
}`)
	deps, err := parseRenvLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("empty-version pkg should be skipped, got %v", deps)
	}
}

func TestParseRenvLock_InvalidJSON(t *testing.T) {
	_, err := parseRenvLock([]byte(`{invalid`), nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
