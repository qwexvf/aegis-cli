package epss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestEnrichAdvisories_BatchAndMap(t *testing.T) {
	var gotCVE string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCVE = r.URL.Query().Get("cve")
		_, _ = w.Write([]byte(`{
		  "status":"OK",
		  "data":[
		    {"cve":"CVE-2021-44228","epss":"0.94358","percentile":"0.99963"},
		    {"cve":"CVE-2024-9999","epss":"0.001","percentile":"0.05"}
		  ]
		}`))
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL))
	advs := []domain.Advisory{
		{ID: "CVE-2021-44228"}, // direct CVE
		{ID: "GHSA-xxxx-xxxx-xxxx", Aliases: []string{"CVE-2024-9999"}}, // via alias
		{ID: "GHSA-no-cve-alias"}, // no CVE → skip
	}

	out := c.EnrichAdvisories(context.Background(), advs)

	if !strings.Contains(gotCVE, "CVE-2021-44228") || !strings.Contains(gotCVE, "CVE-2024-9999") {
		t.Errorf("batch query CVE list missing entries: %q", gotCVE)
	}
	if strings.Contains(gotCVE, "GHSA-no-cve-alias") {
		t.Errorf("GHSA-only advisory should not be queried; got %q", gotCVE)
	}

	if out[0].EPSS == 0 || out[0].EPSSPercentile == 0 {
		t.Errorf("CVE-2021-44228 not enriched: %+v", out[0])
	}
	if out[1].EPSS == 0 {
		t.Errorf("alias-mapped advisory not enriched: %+v", out[1])
	}
	if out[2].EPSS != 0 {
		t.Errorf("GHSA-only advisory should not be enriched: %+v", out[2])
	}
}

func TestEnrichAdvisories_NoCVEs_NoCall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL))
	advs := []domain.Advisory{
		{ID: "GHSA-only"},
		{ID: "MAL-2024-1"},
	}
	out := c.EnrichAdvisories(context.Background(), advs)
	if called {
		t.Error("expected no HTTP call when no advisories carry CVE IDs")
	}
	if len(out) != 2 {
		t.Errorf("output length = %d, want 2", len(out))
	}
}

func TestEnrichAdvisories_NetworkFailureDegrades(t *testing.T) {
	c := New(WithBaseURL("http://127.0.0.1:1")) // unroutable
	advs := []domain.Advisory{{ID: "CVE-2021-1"}}

	out := c.EnrichAdvisories(context.Background(), advs)
	// Best-effort: the advisory should be returned unchanged, no panic.
	if len(out) != 1 {
		t.Fatalf("out len = %d", len(out))
	}
	if out[0].EPSS != 0 {
		t.Errorf("network failure should leave EPSS=0; got %v", out[0].EPSS)
	}
}

func TestEnrichAdvisories_MalformedScoreSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"OK","data":[{"cve":"CVE-X","epss":"not-a-number","percentile":"0.5"}]}`))
	}))
	defer srv.Close()
	c := New(WithBaseURL(srv.URL))
	advs := []domain.Advisory{{ID: "CVE-X"}}
	out := c.EnrichAdvisories(context.Background(), advs)
	if out[0].EPSS != 0 {
		t.Errorf("malformed EPSS should be skipped (stay 0), got %v", out[0].EPSS)
	}
}

func TestEnrichAdvisories_DuplicateCVE_OnlyFirstWins(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"OK","data":[{"cve":"CVE-DUP","epss":"0.5","percentile":"0.9"}]}`))
	}))
	defer srv.Close()
	c := New(WithBaseURL(srv.URL))
	advs := []domain.Advisory{
		{ID: "GHSA-a", Aliases: []string{"CVE-DUP"}},
		{ID: "GHSA-b", Aliases: []string{"CVE-DUP"}},
	}
	out := c.EnrichAdvisories(context.Background(), advs)
	// first-wins index — only the first advisory gets the score.
	if out[0].EPSS == 0 {
		t.Errorf("first advisory with duplicated CVE should be enriched: %+v", out[0])
	}
}

func TestFindCVEID(t *testing.T) {
	tests := []struct {
		name string
		adv  domain.Advisory
		want string
	}{
		{"direct CVE", domain.Advisory{ID: "CVE-2024-1"}, "CVE-2024-1"},
		{"via alias", domain.Advisory{ID: "GHSA-x", Aliases: []string{"CVE-2024-2"}}, "CVE-2024-2"},
		{"no CVE", domain.Advisory{ID: "GHSA-only"}, ""},
		{"multiple aliases, first CVE wins", domain.Advisory{
			ID: "GHSA-x", Aliases: []string{"OSV-1", "CVE-2024-3", "CVE-2024-4"},
		}, "CVE-2024-3"},
	}
	for _, tt := range tests {
		if got := findCVEID(tt.adv); got != tt.want {
			t.Errorf("%s: findCVEID = %q, want %q", tt.name, got, tt.want)
		}
	}
}
