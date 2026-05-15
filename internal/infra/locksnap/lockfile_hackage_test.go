package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseCabalFreeze_Basic(t *testing.T) {
	raw := []byte(`constraints: aeson ==2.1.2.1,
             base ==4.17.2.0,
             bytestring ==0.11.5.3,
             text ==2.0.2
`)

	deps, err := parseCabalFreeze(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 4 {
		t.Fatalf("want 4 deps, got %d: %v", len(deps), deps)
	}

	byName := make(map[string]domain.Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	if d, ok := byName["aeson"]; !ok {
		t.Error("missing aeson")
	} else {
		if d.Version != "2.1.2.1" {
			t.Errorf("aeson version = %q; want 2.1.2.1", d.Version)
		}
		if d.Ecosystem != domain.EcoHackage {
			t.Errorf("ecosystem = %v; want hackage", d.Ecosystem)
		}
	}
}

func TestParseCabalFreeze_SkipsAnyPrefix(t *testing.T) {
	raw := []byte(`constraints: any.base ==4.17.2.0,
             aeson ==2.1.2.1
`)
	deps, err := parseCabalFreeze(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// any.base should be skipped
	if len(deps) != 1 {
		t.Fatalf("want 1 dep (any.base skipped), got %d: %v", len(deps), deps)
	}
	if deps[0].Name != "aeson" {
		t.Errorf("expected aeson, got %q", deps[0].Name)
	}
}

func TestParseStackYamlLock_HackageDep(t *testing.T) {
	raw := []byte(`packages:
- completed:
    hackage: aeson-2.1.2.1@sha256:abcdef1234567890,size:98765
    pantry-tree:
      sha256: xyz789
      size: 123
  original:
    hackage: aeson-2.1.2.1@sha256:abcdef1234567890,size:98765
- completed:
    hackage: text-2.0.2@sha256:aabbcc,size:54321
  original:
    hackage: text-2.0.2@sha256:aabbcc,size:54321
snapshots:
- completed:
    url: https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master/lts/21/22.yaml
    sha256: deadbeef
    size: 999999
  original:
    url: https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master/lts/21/22.yaml
`)

	deps, err := parseStackYamlLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// aeson and text should appear once each (deduped from completed+original)
	if len(deps) != 2 {
		t.Fatalf("want 2 deps (deduped), got %d: %v", len(deps), deps)
	}
	byName := make(map[string]domain.Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}
	if d, ok := byName["aeson"]; !ok {
		t.Error("missing aeson")
	} else if d.Version != "2.1.2.1" {
		t.Errorf("aeson version = %q; want 2.1.2.1", d.Version)
	}
	if d, ok := byName["text"]; !ok {
		t.Error("missing text")
	} else if d.Version != "2.0.2" {
		t.Errorf("text version = %q; want 2.0.2", d.Version)
	}
}
