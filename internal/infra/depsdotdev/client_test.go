package depsdotdev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestFetchDeprecated_ParsesIsDeprecated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mirror real deps.dev response: isDeprecated is TOP-level, not
		// nested under a "version" key.
		_, _ = w.Write([]byte(`{
		  "versionKey":{"system":"NPM","name":"request","version":"2.88.2"},
		  "isDeprecated": true,
		  "deprecatedReason": "request has been deprecated"
		}`))
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL))
	dep, reason, err := c.FetchDeprecated(context.Background(), domain.EcoNpm, "request", "2.88.2")
	if err != nil {
		t.Fatalf("FetchDeprecated: %v", err)
	}
	if !dep {
		t.Errorf("expected deprecated=true")
	}
	if reason == "" {
		t.Errorf("expected non-empty reason")
	}
}

func TestFetchDeprecated_NotDeprecated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"versionKey":{"system":"NPM"},"isDeprecated": false, "deprecatedReason":""}`))
	}))
	defer srv.Close()
	c := New(WithBaseURL(srv.URL))
	dep, reason, err := c.FetchDeprecated(context.Background(), domain.EcoNpm, "lodash", "4.17.21")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dep || reason != "" {
		t.Errorf("expected (false, \"\"), got (%v, %q)", dep, reason)
	}
}

func TestFetchDeprecated_NotFoundReturnsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New(WithBaseURL(srv.URL))
	dep, reason, err := c.FetchDeprecated(context.Background(), domain.EcoNpm, "ghost", "0.0.1")
	if err != nil {
		t.Errorf("404 should not error, got %v", err)
	}
	if dep || reason != "" {
		t.Errorf("404 should produce zero result")
	}
}

func TestFetchDeprecated_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(WithBaseURL(srv.URL))
	_, _, err := c.FetchDeprecated(context.Background(), domain.EcoNpm, "x", "1")
	if err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestFetchDeprecated_UnsupportedEcosystem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("HTTP should not be called for unsupported ecosystem")
	}))
	defer srv.Close()
	c := New(WithBaseURL(srv.URL))
	dep, reason, err := c.FetchDeprecated(context.Background(), domain.EcoRubyGems, "rails", "8")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if dep || reason != "" {
		t.Errorf("unsupported eco should produce zero result")
	}
}

func TestDepsSystem(t *testing.T) {
	tests := []struct {
		eco  domain.Ecosystem
		want string
	}{
		{domain.EcoNpm, "npm"},
		{domain.EcoPyPI, "pypi"},
		{domain.EcoCrates, "cargo"},
		{domain.EcoGo, "go"},
		{domain.EcoMaven, "maven"},
		{domain.EcoNuGet, "nuget"},
		{domain.EcoRubyGems, ""}, // unsupported
	}
	for _, tt := range tests {
		if got := depsSystem(tt.eco); got != tt.want {
			t.Errorf("depsSystem(%v) = %q, want %q", tt.eco, got, tt.want)
		}
	}
}
