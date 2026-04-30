package aegisapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

// captureSubmitServer spins up an httptest server that records the
// last request's X-API-Key header and returns a minimal valid ack.
func captureSubmitServer(t *testing.T, capturedKey *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/supply-chain/reports" {
			http.NotFound(w, r)
			return
		}
		*capturedKey = r.Header.Get("X-API-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(usecase.PackageReportAck{
			ReportID: "abc",
			URL:      "http://test/abc",
		})
	}))
}

func TestSubmitReport_AttachesAPIKeyWhenConfigured(t *testing.T) {
	var got string
	srv := captureSubmitServer(t, &got)
	defer srv.Close()

	t.Setenv("AEGIS_API_URL", srv.URL)
	c := New(WithAPIKey("supersecret"))

	_, err := c.SubmitReport(context.Background(), usecase.PackageReportRequest{
		ReporterID: "00000000-0000-0000-0000-000000000000",
		Ecosystem:  "npm",
		Name:       "x",
		Version:    "1.0.0",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if got != "supersecret" {
		t.Fatalf("X-API-Key = %q, want %q", got, "supersecret")
	}
}

func TestSubmitReport_OmitsAPIKeyWhenUnset(t *testing.T) {
	var got string
	srv := captureSubmitServer(t, &got)
	defer srv.Close()

	t.Setenv("AEGIS_API_URL", srv.URL)
	c := New() // no WithAPIKey option

	_, err := c.SubmitReport(context.Background(), usecase.PackageReportRequest{
		ReporterID: "00000000-0000-0000-0000-000000000000",
		Ecosystem:  "npm",
		Name:       "x",
		Version:    "1.0.0",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if got != "" {
		t.Fatalf("X-API-Key should be absent, got %q", got)
	}
}

func TestSubmitReport_OmitsAPIKeyWhenEmptyOption(t *testing.T) {
	// WithAPIKey("") is a no-op — same as not passing the option at
	// all. The empty key must NOT leak as an empty header value
	// (some servers behave differently for empty vs missing).
	var got string
	hadHeader := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if vs, ok := r.Header[http.CanonicalHeaderKey("X-API-Key")]; ok {
			hadHeader = true
			if len(vs) > 0 {
				got = vs[0]
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(usecase.PackageReportAck{ReportID: "ok"})
	}))
	defer srv.Close()

	t.Setenv("AEGIS_API_URL", srv.URL)
	c := New(WithAPIKey(""))
	_, err := c.SubmitReport(context.Background(), usecase.PackageReportRequest{
		ReporterID: "00000000-0000-0000-0000-000000000000",
		Ecosystem:  "npm",
		Name:       "x",
		Version:    "1.0.0",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if hadHeader {
		t.Fatalf("X-API-Key should not be set when key is empty (got %q)", got)
	}
}

func TestSubmitReport_PropagatesNon2xxAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"missing X-API-Key header"}`))
	}))
	defer srv.Close()

	t.Setenv("AEGIS_API_URL", srv.URL)
	c := New()
	_, err := c.SubmitReport(context.Background(), usecase.PackageReportRequest{
		ReporterID: "00000000-0000-0000-0000-000000000000",
		Ecosystem:  "npm",
		Name:       "x",
		Version:    "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error should mention 401, got %v", err)
	}
}
