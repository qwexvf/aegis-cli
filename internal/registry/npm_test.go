package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(WithRegistry(srv.URL), WithHTTPClient(srv.Client()))
}

const lodashPackument = `{
  "name": "lodash",
  "dist-tags": {"latest": "4.17.21", "next": "5.0.0-pre.1"},
  "versions": {
    "4.17.19": {"version": "4.17.19"},
    "4.17.20": {"version": "4.17.20"},
    "4.17.21": {"version": "4.17.21"},
    "5.0.0-pre.1": {"version": "5.0.0-pre.1"}
  }
}`

func TestResolve(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, lodashPackument)
	}))

	cases := []struct {
		input string
		want  string
	}{
		{"", "4.17.21"},          // empty -> latest
		{"latest", "4.17.21"},    // tag
		{"next", "5.0.0-pre.1"},  // tag
		{"4.17.20", "4.17.20"},   // exact
		{"^4.17.0", "4.17.21"},   // range -> highest matching
		{"~4.17.19", "4.17.21"},  // tilde range
		{"<4.17.21", "4.17.20"},  // less-than
	}
	for _, c2 := range cases {
		got, err := c.Resolve(context.Background(), "lodash", c2.input)
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", c2.input, err)
			continue
		}
		if got != c2.want {
			t.Errorf("Resolve(%q) = %q, want %q", c2.input, got, c2.want)
		}
	}
}

func TestResolveScoped(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// npm registry path for @scope/name is /@scope%2Fname
		if r.URL.Path != "/@bitwarden%2Fcli" && r.URL.EscapedPath() != "/@bitwarden%2Fcli" {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{
			"name": "@bitwarden/cli",
			"dist-tags": {"latest": "2026.4.1"},
			"versions": {
				"2026.3.5": {"version": "2026.3.5"},
				"2026.4.0": {"version": "2026.4.0"},
				"2026.4.1": {"version": "2026.4.1"}
			}
		}`)
	}))

	got, err := c.Resolve(context.Background(), "@bitwarden/cli", "")
	if err != nil {
		t.Fatalf("Resolve scoped: %v", err)
	}
	if got != "2026.4.1" {
		t.Errorf("Resolve scoped = %q, want 2026.4.1", got)
	}
}

func TestResolveNotFound(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	if _, err := c.Resolve(context.Background(), "no-such-package", ""); err == nil {
		t.Error("expected error for missing package")
	}
}

func TestResolveBadRange(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, lodashPackument)
	}))
	if _, err := c.Resolve(context.Background(), "lodash", "not-a-version"); err == nil {
		t.Error("expected error for unsatisfiable range")
	}
}
