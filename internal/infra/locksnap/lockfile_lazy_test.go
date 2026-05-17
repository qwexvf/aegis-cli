package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseLazyLock(t *testing.T) {
	in := []byte(`{
  "telescope.nvim": { "branch": "master", "commit": "a4ed6831b7748a2ddc4e3d6207baf3df56cba6dd" },
  "nvim-treesitter": { "branch": "main", "commit": "11111111111111111111111111111111deadbeef" },
  "plenary.nvim":    { "branch": "master", "commit": "55555555555555555555555555555555cafe0bad", "version": "0.1" },
  "no-commit-here":  { "branch": "main" }
}`)
	deps, err := parseLazyLock(in, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// 3 valid entries; the no-commit one is skipped.
	if len(deps) != 3 {
		t.Fatalf("got %d deps, want 3", len(deps))
	}
	versions := map[string]string{}
	for _, d := range deps {
		if d.Ecosystem != domain.EcoNeovim {
			t.Errorf("ecosystem = %v, want neovim", d.Ecosystem)
		}
		versions[d.Name] = d.Version
	}
	if got := versions["telescope.nvim"]; got != "a4ed6831b7748a2ddc4e3d6207baf3df56cba6dd" {
		t.Errorf("telescope.nvim commit = %q", got)
	}
	if got := versions["plenary.nvim"]; got != "55555555555555555555555555555555cafe0bad" {
		// plenary has a version field; commit must still win.
		t.Errorf("plenary.nvim commit = %q (version field must NOT replace commit)", got)
	}
	if _, ok := versions["no-commit-here"]; ok {
		t.Errorf("entries without commit must be skipped")
	}
}

func TestParseLazyLock_MalformedJSON(t *testing.T) {
	_, err := parseLazyLock([]byte(`{ broken`), nil)
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}
