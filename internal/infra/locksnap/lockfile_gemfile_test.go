package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseGemfileLock(t *testing.T) {
	in := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.1.2)
      actionview (= 7.1.2)
      activesupport (= 7.1.2)
    activerecord (7.1.2)
      activemodel (= 7.1.2)
    nokogiri (1.16.0)
      racc (~> 1.4)
    racc (1.7.3)

PLATFORMS
  ruby

DEPENDENCIES
  actionpack (~> 7.1)
  nokogiri

BUNDLED WITH
   2.4.10
`)
	deps, err := parseGemfileLock(in, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 4 {
		t.Fatalf("got %d deps, want 4", len(deps))
	}

	versions := map[string]string{}
	directs := map[string]bool{}
	for _, d := range deps {
		if d.Ecosystem != domain.EcoRubyGems {
			t.Errorf("ecosystem = %v, want rubygems", d.Ecosystem)
		}
		versions[d.Name] = d.Version
		directs[d.Name] = d.Direct
	}
	if versions["actionpack"] != "7.1.2" {
		t.Errorf("actionpack = %q", versions["actionpack"])
	}
	if versions["nokogiri"] != "1.16.0" {
		t.Errorf("nokogiri = %q", versions["nokogiri"])
	}

	// DEPENDENCIES section says actionpack + nokogiri are direct.
	if !directs["actionpack"] {
		t.Error("actionpack should be Direct (in DEPENDENCIES)")
	}
	if !directs["nokogiri"] {
		t.Error("nokogiri should be Direct (in DEPENDENCIES)")
	}
	if directs["activerecord"] {
		t.Error("activerecord should NOT be Direct (transitive)")
	}
}
