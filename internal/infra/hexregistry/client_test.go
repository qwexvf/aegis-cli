package hexregistry

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

const phoenixPayload = `{
  "name": "phoenix",
  "downloads": {"all": 50000000, "week": 120000, "day": 17000},
  "releases": [
    {"version": "1.7.0", "inserted_at": "2024-01-15T10:00:00.000Z",
     "publisher": {"username": "chrismccord"}},
    {"version": "1.6.0", "inserted_at": "2022-08-26T13:13:18.000Z",
     "publisher": {"username": "chrismccord"}},
    {"version": "1.5.0", "inserted_at": "2020-04-22T09:00:00.000Z",
     "publisher": {"username": "chrismccord"},
     "retirement": {"reason": "security"}}
  ]
}`

func TestFetchMaintainerSignal_Latest(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/packages/phoenix" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, phoenixPayload)
	}))

	got, err := c.FetchMaintainerSignal(context.Background(), "phoenix", "1.7.0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.PublishedAt != "2024-01-15T10:00:00.000Z" {
		t.Errorf("PublishedAt = %q", got.PublishedAt)
	}
	if got.Publisher != "chrismccord" {
		t.Errorf("Publisher = %q", got.Publisher)
	}
	if got.PreviousVersion != "1.6.0" {
		t.Errorf("PreviousVersion = %q", got.PreviousVersion)
	}
	if got.PreviousPublishedAt != "2022-08-26T13:13:18.000Z" {
		t.Errorf("PreviousPublishedAt = %q", got.PreviousPublishedAt)
	}
	if got.PreviousPublisher != "chrismccord" {
		t.Errorf("PreviousPublisher = %q", got.PreviousPublisher)
	}
	if got.WeeklyDownloads != 120000 {
		t.Errorf("WeeklyDownloads = %d", got.WeeklyDownloads)
	}
	if got.VersionUnpublished {
		t.Error("VersionUnpublished should be false for 1.7.0")
	}
}

func TestFetchMaintainerSignal_Retired(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, phoenixPayload)
	}))
	got, err := c.FetchMaintainerSignal(context.Background(), "phoenix", "1.5.0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got.VersionUnpublished {
		t.Error("VersionUnpublished should be true for retired 1.5.0")
	}
}

func TestFetchMaintainerSignal_NoPrevious(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, phoenixPayload)
	}))
	got, err := c.FetchMaintainerSignal(context.Background(), "phoenix", "1.5.0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.PreviousVersion != "" {
		t.Errorf("oldest release should have no PreviousVersion, got %q", got.PreviousVersion)
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
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if _, err := c.FetchMaintainerSignal(context.Background(), "", "1.0.0"); err == nil {
		t.Error("expected error for empty pkg")
	}
	if _, err := c.FetchMaintainerSignal(context.Background(), "phoenix", ""); err == nil {
		t.Error("expected error for empty version")
	}
}

func TestFetchMaintainerSignalForEcosystem_WrongEco(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	got, err := c.FetchMaintainerSignalForEcosystem(context.Background(), domain.EcoNpm, "phoenix", "1.0.0")
	if err != nil {
		t.Errorf("non-Hex ecosystem should not error, got %v", err)
	}
	if got != (domain.MaintainerSignal{}) {
		t.Errorf("non-Hex ecosystem should return zero signal, got %+v", got)
	}
}

func TestCache(t *testing.T) {
	hits := 0
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, phoenixPayload)
	}))
	_, _ = c.FetchMaintainerSignal(context.Background(), "phoenix", "1.7.0")
	_, _ = c.FetchMaintainerSignal(context.Background(), "phoenix", "1.6.0")
	if hits != 1 {
		t.Errorf("expected 1 HTTP fetch for cached package, got %d", hits)
	}
}
