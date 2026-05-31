package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestCvssBaseScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		// FIRST.org example vectors with known scores.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8}, // Critical
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9}, // Critical scope-changed
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8}, // High
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5}, // Medium
		{"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L", 2.5}, // Low
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0}, // zero impact
		// Invalid / absent inputs.
		{"", -1},
		{"not-a-vector", -1},
		{"CVSS:3.1/AV:N/AC:L", -1}, // too few parts
		{"CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", -1}, // bad AV value
	}
	for _, tt := range tests {
		got := cvssBaseScore(tt.vector)
		if got != tt.want {
			t.Errorf("cvssBaseScore(%q) = %.1f, want %.1f", tt.vector, got, tt.want)
		}
	}
}

// TestLookup_Batch verifies the happy path: a 2-dep query produces a
// single batch POST and per-dep GET fan-out, and the results map is
// keyed by AdvisoryQuery.Key() with one Advisory each.
func TestLookup_Batch(t *testing.T) {
	var batchHits, vulnHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			atomic.AddInt64(&batchHits, 1)
			// Two queries → two results, one with a vuln, one empty.
			fmt.Fprintln(w, `{"results":[{"vulns":[{"id":"GHSA-jvqj-7wpc-9bqp","modified":"2018-11-26"}]},{"vulns":[]}]}`)
		case "/v1/vulns/GHSA-jvqj-7wpc-9bqp":
			atomic.AddInt64(&vulnHits, 1)
			fmt.Fprintln(w, `{
				"id": "GHSA-jvqj-7wpc-9bqp",
				"aliases": ["CVE-2018-1000620"],
				"summary": "Malicious package — Bitcoin wallet credential exfiltration",
				"database_specific": {"severity": "CRITICAL"}
			}`)
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithoutDiskCache())

	queries := []domain.AdvisoryQuery{
		{Ecosystem: domain.EcoNpm, Name: "event-stream", Version: "3.3.6"},
		{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21"},
	}
	results, err := c.Lookup(context.Background(), queries)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	// Check key shape + content.
	bad := results["npm/event-stream@3.3.6"]
	if len(bad) != 1 {
		t.Fatalf("event-stream: got %d advisories, want 1", len(bad))
	}
	if bad[0].ID != "GHSA-jvqj-7wpc-9bqp" {
		t.Errorf("ID = %q", bad[0].ID)
	}
	if bad[0].Severity != domain.SevCritical {
		t.Errorf("Severity = %v, want Critical", bad[0].Severity)
	}
	if bad[0].URL != "https://osv.dev/vulnerability/GHSA-jvqj-7wpc-9bqp" {
		t.Errorf("URL = %q", bad[0].URL)
	}

	// Empty slice (not nil) so re-runs don't re-query.
	clean, ok := results["npm/lodash@4.17.21"]
	if !ok {
		t.Fatal("lodash key missing from results")
	}
	if clean == nil {
		t.Error("lodash advisories should be non-nil empty slice")
	}
	if len(clean) != 0 {
		t.Errorf("lodash should have 0 advisories, got %d", len(clean))
	}

	// Wire economy: one batch POST, one detail GET.
	if got := atomic.LoadInt64(&batchHits); got != 1 {
		t.Errorf("batch POST count = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&vulnHits); got != 1 {
		t.Errorf("vuln GET count = %d, want 1", got)
	}
}

// TestLookup_NoQueries returns an empty map without making any HTTP
// calls. The use case pre-filters and may pass us a zero-length slice.
func TestLookup_NoQueries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no HTTP call expected for empty query list, got %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithoutDiskCache())
	results, err := c.Lookup(context.Background(), nil)
	if err != nil {
		t.Fatalf("Lookup(nil): %v", err)
	}
	if len(results) != 0 {
		t.Errorf("nil queries should produce empty result, got %d entries", len(results))
	}
}

// TestParseOSVVuln_DatabaseSpecificSeverity exercises the severity
// fallback path: OSV records without a CVSS vector still have a
// bucketed severity in database_specific. npm advisories are the
// classic case.
func TestParseOSVVuln_DatabaseSpecificSeverity(t *testing.T) {
	tests := []struct {
		dbSpec string
		want   domain.Severity
	}{
		{"CRITICAL", domain.SevCritical},
		{"HIGH", domain.SevHigh},
		{"MODERATE", domain.SevMedium},
		{"MEDIUM", domain.SevMedium},
		{"LOW", domain.SevLow},
		{"unknown", domain.SevInfo},
		{"", domain.SevInfo},
	}
	for _, tc := range tests {
		t.Run(tc.dbSpec, func(t *testing.T) {
			doc := osvDoc{
				ID:      "GHSA-test",
				Summary: "test",
			}
			doc.DatabaseSpecific.Severity = tc.dbSpec
			raw, _ := json.Marshal(doc)
			adv, err := parseOSVVuln(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if adv.Severity != tc.want {
				t.Errorf("Severity for %q = %v, want %v", tc.dbSpec, adv.Severity, tc.want)
			}
		})
	}
}

// TestLookup_BatchHTTPError surfaces the upstream error verbatim
// rather than silently dropping advisories.
func TestLookup_BatchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithoutDiskCache())
	_, err := c.Lookup(context.Background(), []domain.AdvisoryQuery{
		{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21"},
	})
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
}

// TestLookup_VulnFetchErrorSurfaceStub: when one of the per-ID GETs
// fails, Lookup keeps the rest and emits a stub Advisory carrying
// the ID + URL so the user can pivot upstream. We don't want one
// flaky vuln record to blackhole the entire snapshot enrich.
func TestLookup_VulnFetchErrorSurfaceStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			fmt.Fprintln(w, `{"results":[{"vulns":[{"id":"GHSA-broken","modified":"2026-01-01"}]}]}`)
		case "/v1/vulns/GHSA-broken":
			http.Error(w, "not found", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithoutDiskCache())
	results, err := c.Lookup(context.Background(), []domain.AdvisoryQuery{
		{Ecosystem: domain.EcoNpm, Name: "evil", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	advs := results["npm/evil@1.0.0"]
	if len(advs) != 1 {
		t.Fatalf("expected 1 stub advisory, got %d", len(advs))
	}
	if advs[0].ID != "GHSA-broken" {
		t.Errorf("stub ID = %q", advs[0].ID)
	}
	if advs[0].URL == "" {
		t.Error("stub should carry a URL so user can pivot upstream")
	}
}

// TestOsvEcosystem locks the OSV ecosystem vocabulary. OSV rejects an
// unknown or mis-cased ecosystem with HTTP 400, so exact strings matter;
// ecosystems OSV doesn't cover must map to "" so the caller drops them.
func TestOsvEcosystem(t *testing.T) {
	tests := []struct {
		eco  domain.Ecosystem
		want string
	}{
		{domain.EcoNpm, "npm"},
		{domain.EcoPyPI, "PyPI"},
		{domain.EcoCrates, "crates.io"},
		{domain.EcoGo, "Go"},
		{domain.EcoRubyGems, "RubyGems"},
		{domain.EcoMaven, "Maven"},
		{domain.EcoPackagist, "Packagist"},
		{domain.EcoNuGet, "NuGet"},
		{domain.EcoGleam, "Hex"},
		{domain.EcoPub, "Pub"},
		{domain.EcoSwiftPM, "SwiftURL"},
		{domain.EcoCRAN, "CRAN"},
		{domain.EcoHackage, "Hackage"},
		// No OSV ecosystem — must be dropped, not sent.
		{domain.EcoCPAN, ""},
		{domain.EcoCocoaPods, ""},
		{domain.EcoNeovim, ""},
	}
	for _, tt := range tests {
		if got := osvEcosystem(tt.eco); got != tt.want {
			t.Errorf("osvEcosystem(%v) = %q, want %q", tt.eco, got, tt.want)
		}
	}
}

// TestOsvPackageName covers SwiftURL name normalization: lockfiles store
// the full clone URL but OSV keys packages by the bare repo path.
func TestOsvPackageName(t *testing.T) {
	tests := []struct {
		eco  domain.Ecosystem
		name string
		want string
	}{
		{domain.EcoSwiftPM, "https://github.com/vapor/vapor.git", "github.com/vapor/vapor"},
		{domain.EcoSwiftPM, "https://github.com/Alamofire/Alamofire.git", "github.com/Alamofire/Alamofire"},
		{domain.EcoSwiftPM, "github.com/vapor/vapor", "github.com/vapor/vapor"},
		{domain.EcoSwiftPM, "http://example.com/pkg.git", "example.com/pkg"},
		// Non-Swift names pass through untouched.
		{domain.EcoNpm, "lodash", "lodash"},
		{domain.EcoGo, "github.com/foo/bar", "github.com/foo/bar"},
	}
	for _, tt := range tests {
		q := domain.AdvisoryQuery{Ecosystem: tt.eco, Name: tt.name}
		if got := osvPackageName(q); got != tt.want {
			t.Errorf("osvPackageName(%v, %q) = %q, want %q", tt.eco, tt.name, got, tt.want)
		}
	}
}

// TestLookup_SkipsUnsupportedEcosystems verifies that deps in ecosystems
// OSV doesn't cover are dropped from the batch (not sent), the remaining
// results realign to the original queries, and SwiftURL names are
// normalized on the wire. Regression for the HTTP-400-poisons-whole-batch
// bug where one CPAN/CocoaPods dep killed enrichment for every dep.
func TestLookup_SkipsUnsupportedEcosystems(t *testing.T) {
	var sentEcosystems []string
	var sentNames []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
				} `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode batch: %v", err)
			}
			results := make([]string, 0, len(req.Queries))
			for _, q := range req.Queries {
				sentEcosystems = append(sentEcosystems, q.Package.Ecosystem)
				sentNames = append(sentNames, q.Package.Name)
				// hex dep gets a vuln, the rest are clean.
				if q.Package.Ecosystem == "Hex" {
					results = append(results, `{"vulns":[{"id":"GHSA-test-hex-0001","modified":"2026-01-01"}]}`)
				} else {
					results = append(results, `{"vulns":[]}`)
				}
			}
			fmt.Fprintf(w, `{"results":[%s]}`, strings.Join(results, ","))
		case "/v1/vulns/GHSA-test-hex-0001":
			fmt.Fprintln(w, `{"id":"GHSA-test-hex-0001","summary":"test","database_specific":{"severity":"HIGH"}}`)
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithoutDiskCache())
	queries := []domain.AdvisoryQuery{
		{Ecosystem: domain.EcoCPAN, Name: "Try-Tiny", Version: "0.30"},                               // unsupported → dropped
		{Ecosystem: domain.EcoGleam, Name: "plug", Version: "1.14.0"},                                // Hex → has vuln
		{Ecosystem: domain.EcoCocoaPods, Name: "Alamofire", Version: "5.6.4"},                        // unsupported → dropped
		{Ecosystem: domain.EcoSwiftPM, Name: "https://github.com/vapor/vapor.git", Version: "4.0.0"}, // normalized
	}
	results, err := c.Lookup(context.Background(), queries)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	// Only the 2 OSV-supported ecosystems hit the wire.
	if len(sentEcosystems) != 2 {
		t.Fatalf("sent %d queries to OSV, want 2: %v", len(sentEcosystems), sentEcosystems)
	}
	for _, e := range sentEcosystems {
		if e == "cpan" || e == "CPAN" || e == "cocoapods" {
			t.Errorf("unsupported ecosystem %q leaked into batch", e)
		}
	}
	// SwiftURL name normalized on the wire.
	swiftSent := false
	for _, n := range sentNames {
		if n == "github.com/vapor/vapor" {
			swiftSent = true
		}
		if n == "https://github.com/vapor/vapor.git" {
			t.Errorf("SwiftURL name sent un-normalized: %q", n)
		}
	}
	if !swiftSent {
		t.Errorf("normalized SwiftURL name not found in %v", sentNames)
	}

	// Results realign: hex dep has the advisory, dropped deps are empty (non-nil).
	hex := results["hex/plug@1.14.0"]
	if len(hex) != 1 || hex[0].ID != "GHSA-test-hex-0001" {
		t.Errorf("plug advisories = %+v, want 1 with GHSA-test-hex-0001", hex)
	}
	for _, key := range []string{"cpan/Try-Tiny@0.30", "cocoapods/Alamofire@5.6.4"} {
		got, ok := results[key]
		if !ok {
			t.Errorf("%s missing from results", key)
		}
		if got == nil {
			t.Errorf("%s should be non-nil empty slice", key)
		}
		if len(got) != 0 {
			t.Errorf("%s should have 0 advisories, got %d", key, len(got))
		}
	}
}
