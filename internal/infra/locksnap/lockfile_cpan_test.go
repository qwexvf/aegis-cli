package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseCpanfileSnapshot_Basic(t *testing.T) {
	raw := []byte(`# carton snapshot format: version 1.0
DISTRIBUTIONS
  M/MI/MIYAGAWA/Module-CPANfile-1.1004.tar.gz
    pathname: M/MI/MIYAGAWA/Module-CPANfile-1.1004.tar.gz
    provides:
      Module::CPANfile 1.1004
    requirements:
      CPAN::Meta 2.110580 [runtime]
  C/CO/CORION/Carton-1.0.34.tar.gz
    pathname: C/CO/CORION/Carton-1.0.34.tar.gz
    provides:
      Carton 1.0.34
    requirements:
      Module::CPANfile 0 [runtime]
`)

	deps, err := parseCpanfileSnapshot(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 deps, got %d: %v", len(deps), deps)
	}

	byName := make(map[string]domain.Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	if d, ok := byName["Module-CPANfile"]; !ok {
		t.Error("missing Module-CPANfile")
	} else {
		if d.Version != "1.1004" {
			t.Errorf("version = %q; want 1.1004", d.Version)
		}
		if d.Ecosystem != domain.EcoCPAN {
			t.Errorf("ecosystem = %v; want cpan", d.Ecosystem)
		}
	}

	if d, ok := byName["Carton"]; !ok {
		t.Error("missing Carton")
	} else if d.Version != "1.0.34" {
		t.Errorf("version = %q; want 1.0.34", d.Version)
	}
}

func TestParseCpanfileSnapshot_Deduplicates(t *testing.T) {
	raw := []byte(`DISTRIBUTIONS
  A/AU/AUTHOR/Foo-1.0.tar.gz
    pathname: A/AU/AUTHOR/Foo-1.0.tar.gz
    provides:
      Foo 1.0
  A/AU/AUTHOR/Foo-1.0.tar.gz
    pathname: A/AU/AUTHOR/Foo-1.0.tar.gz
    provides:
      Foo 1.0
`)
	deps, err := parseCpanfileSnapshot(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Errorf("want 1 dep (deduped), got %d", len(deps))
	}
}

func TestParseCpanfileSnapshot_Empty(t *testing.T) {
	deps, err := parseCpanfileSnapshot([]byte("# carton snapshot format: version 1.0\nDISTRIBUTIONS\n"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("want 0 deps, got %d", len(deps))
	}
}
