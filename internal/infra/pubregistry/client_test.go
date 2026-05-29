package pubregistry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(WithRegistry(srv.URL), WithHTTPClient(srv.Client()))
}

const httpPkgPayload = `{
  "name": "http",
  "latest": {"version": "1.2.0", "published": "2024-02-01T12:00:00Z"},
  "versions": [
    {"version": "1.2.0", "published": "2024-02-01T12:00:00Z"},
    {"version": "1.1.0", "published": "2023-09-15T10:00:00Z"},
    {"version": "1.0.0", "published": "2023-01-10T08:00:00Z", "retracted": true}
  ]
}`

const httpPublisherPayload = `{"publisherId": "dart.dev"}`

func handlePubAPI(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/packages/http":
		fmt.Fprint(w, httpPkgPayload)
	case "/packages/http/publisher":
		fmt.Fprint(w, httpPublisherPayload)
	default:
		http.NotFound(w, r)
	}
}

func TestFetchMaintainerSignal_Latest(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(handlePubAPI))
	got, err := c.FetchMaintainerSignal(context.Background(), "http", "1.2.0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.PublishedAt != "2024-02-01T12:00:00Z" {
		t.Errorf("PublishedAt = %q", got.PublishedAt)
	}
	if got.PreviousVersion != "1.1.0" {
		t.Errorf("PreviousVersion = %q", got.PreviousVersion)
	}
	if got.PreviousPublishedAt != "2023-09-15T10:00:00Z" {
		t.Errorf("PreviousPublishedAt = %q", got.PreviousPublishedAt)
	}
	if got.Publisher != "dart.dev" {
		t.Errorf("Publisher = %q", got.Publisher)
	}
	if got.PreviousPublisher != "dart.dev" {
		t.Errorf("PreviousPublisher = %q", got.PreviousPublisher)
	}
	if got.WeeklyDownloads != 0 {
		t.Errorf("WeeklyDownloads must be 0 for pub.dev (not exposed), got %d", got.WeeklyDownloads)
	}
}

func TestFetchMaintainerSignal_Retracted(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(handlePubAPI))
	got, err := c.FetchMaintainerSignal(context.Background(), "http", "1.0.0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got.VersionUnpublished {
		t.Error("retracted version should set VersionUnpublished")
	}
}

func TestFetchMaintainerSignal_PublisherMissing(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/packages/http" {
			fmt.Fprint(w, httpPkgPayload)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	got, err := c.FetchMaintainerSignal(context.Background(), "http", "1.2.0")
	if err != nil {
		t.Fatalf("publisher 401 must not bubble up, got err: %v", err)
	}
	if got.Publisher != "" {
		t.Errorf("Publisher should be empty when endpoint returns 401, got %q", got.Publisher)
	}
}

func TestFetchMaintainerSignal_NotFound(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	_, err := c.FetchMaintainerSignal(context.Background(), "missing", "1.0.0")
	if err == nil {
		t.Error("expected error for 404")
	}
}

func TestFetchMaintainerSignal_EmptyInputs(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(handlePubAPI))
	if _, err := c.FetchMaintainerSignal(context.Background(), "", "1.0.0"); err == nil {
		t.Error("expected error for empty pkg")
	}
	if _, err := c.FetchMaintainerSignal(context.Background(), "http", ""); err == nil {
		t.Error("expected error for empty version")
	}
}

func TestFetchMaintainerSignalForEcosystem_WrongEco(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(handlePubAPI))
	got, err := c.FetchMaintainerSignalForEcosystem(context.Background(), domain.EcoNpm, "http", "1.2.0")
	if err != nil {
		t.Errorf("non-Pub ecosystem must not error, got %v", err)
	}
	if got != (domain.MaintainerSignal{}) {
		t.Errorf("non-Pub ecosystem must return zero signal, got %+v", got)
	}
}

func TestCache(t *testing.T) {
	hits := map[string]int{}
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		handlePubAPI(w, r)
	}))
	_, _ = c.FetchMaintainerSignal(context.Background(), "http", "1.2.0")
	_, _ = c.FetchMaintainerSignal(context.Background(), "http", "1.1.0")
	if hits["/packages/http"] != 1 {
		t.Errorf("expected 1 pkg fetch (cached), got %d", hits["/packages/http"])
	}
}
