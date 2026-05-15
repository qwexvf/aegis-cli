package npmattestations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// slsaPayload builds a base64-encoded SLSA v1 in-toto statement.
func slsaPayload(repo, sha string) string {
	stmt := map[string]any{
		"predicateType": slsaPredicateType,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"externalParameters": map[string]any{
					"workflow": map[string]any{
						"repository": repo,
						"sha":        sha,
						"ref":        "refs/heads/main",
					},
				},
			},
		},
	}
	b, _ := json.Marshal(stmt)
	return base64.StdEncoding.EncodeToString(b)
}

// publishPayload builds a base64-encoded publish attestation payload (no source).
func publishPayload() string {
	stmt := map[string]any{
		"predicateType": publishPredicateType,
		"predicate":     map[string]any{"name": "test-pkg", "version": "1.0.0"},
	}
	b, _ := json.Marshal(stmt)
	return base64.StdEncoding.EncodeToString(b)
}

func newTestClient(srv *httptest.Server) *Client {
	return New(
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)
}

func TestFetchProvenance_SLSAv1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"attestations": []map[string]any{{
				"predicateType": slsaPredicateType,
				"bundle": map[string]any{
					"dsseEnvelope": map[string]any{
						"payload": slsaPayload("https://github.com/owner/repo", "abc123"),
					},
				},
			}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	result, err := newTestClient(srv).FetchProvenance(context.Background(), "test-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "attested" {
		t.Errorf("Status = %q; want attested", result.Status)
	}
	if result.SourceURI != "https://github.com/owner/repo" {
		t.Errorf("SourceURI = %q", result.SourceURI)
	}
	if result.Commit != "abc123" {
		t.Errorf("Commit = %q; want abc123", result.Commit)
	}
}

func TestFetchProvenance_PublishOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"attestations": []map[string]any{{
				"predicateType": publishPredicateType,
				"bundle": map[string]any{
					"dsseEnvelope": map[string]any{"payload": publishPayload()},
				},
			}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	result, err := newTestClient(srv).FetchProvenance(context.Background(), "test-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "attested" {
		t.Errorf("Status = %q; want attested (publish-only still counts)", result.Status)
	}
	if result.SourceURI != "" || result.Commit != "" {
		t.Errorf("publish-only should have empty SourceURI/Commit, got %q %q", result.SourceURI, result.Commit)
	}
}

func TestFetchProvenance_404_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	result, err := newTestClient(srv).FetchProvenance(context.Background(), "no-attest-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "missing" {
		t.Errorf("Status = %q; want missing", result.Status)
	}
}

func TestFetchProvenance_EmptyAttestations_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"attestations": []any{}})
	}))
	defer srv.Close()

	result, err := newTestClient(srv).FetchProvenance(context.Background(), "empty-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "missing" {
		t.Errorf("Status = %q; want missing", result.Status)
	}
}

func TestFetchProvenance_HTTP500_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	result, err := newTestClient(srv).FetchProvenance(context.Background(), "bad-pkg", "1.0.0")
	if err == nil {
		t.Error("expected error for HTTP 500, got nil")
	}
	if result.Status != "error" {
		t.Errorf("Status = %q; want error", result.Status)
	}
}

func TestFetchProvenance_MalformedBase64_FallsThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"attestations": []map[string]any{
				{
					"predicateType": slsaPredicateType,
					"bundle": map[string]any{
						"dsseEnvelope": map[string]any{"payload": "!!!not-base64!!!"},
					},
				},
				{
					"predicateType": publishPredicateType,
					"bundle": map[string]any{
						"dsseEnvelope": map[string]any{"payload": publishPayload()},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	result, err := newTestClient(srv).FetchProvenance(context.Background(), "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Skips malformed SLSA entry, falls through to publish-only → still "attested"
	if result.Status != "attested" {
		t.Errorf("Status = %q; want attested (fallthrough to publish attestation)", result.Status)
	}
}

func TestFetchProvenance_ScopedPackage_URLEncoding(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RawPath preserves %2F; Path decodes it to /. Use RawPath when set.
		if r.URL.RawPath != "" {
			capturedPath = r.URL.RawPath
		} else {
			capturedPath = r.URL.Path
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, _ = newTestClient(srv).FetchProvenance(context.Background(), "@scope/pkg", "1.0.0")

	// @scope/pkg@1.0.0 must be: /-/npm/v1/attestations/@scope%2Fpkg@1.0.0
	if capturedPath != "/-/npm/v1/attestations/@scope%2Fpkg@1.0.0" {
		t.Errorf("URL path = %q; want /-/npm/v1/attestations/@scope%%2Fpkg@1.0.0", capturedPath)
	}
}

// ---------------------------------------------------------------------------
// Pure unit tests for parseAttestationResponse (no HTTP).
// ---------------------------------------------------------------------------

func TestParseAttestationResponse_InvalidJSON(t *testing.T) {
	_, err := parseAttestationResponse([]byte(`{invalid`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseAttestationResponse_SLSAPreferred(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"attestations": []map[string]any{
			{
				"predicateType": publishPredicateType,
				"bundle":        map[string]any{"dsseEnvelope": map[string]any{"payload": publishPayload()}},
			},
			{
				"predicateType": slsaPredicateType,
				"bundle":        map[string]any{"dsseEnvelope": map[string]any{"payload": slsaPayload("https://github.com/a/b", "def456")}},
			},
		},
	})
	result, err := parseAttestationResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SourceURI != "https://github.com/a/b" {
		t.Errorf("SLSA v1 should be preferred; SourceURI = %q", result.SourceURI)
	}
	if result.Commit != "def456" {
		t.Errorf("Commit = %q; want def456", result.Commit)
	}
}
