// Package hexregistry fetches package metadata from the hex.pm public
// API. Used by the maintainer-hijack heuristic for Elixir, Gleam, and
// Erlang packages — anything published to Hex.
//
// API reference: https://github.com/hexpm/hexpm/blob/main/lib/hexpm_web/controllers/api/package_controller.ex
package hexregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

// DefaultRegistry is the public Hex API base URL.
const DefaultRegistry = "https://hex.pm/api"

// Client fetches hex.pm package metadata with an in-memory cache.
type Client struct {
	baseURL string
	http    *http.Client
	retry   httpx.RetryPolicy

	mu    sync.Mutex
	cache map[string]*pkgPayload
}

// Option configures a Client.
type Option func(*Client)

// WithRegistry sets a non-default API base URL (test/mirror).
func WithRegistry(u string) Option {
	return func(c *Client) { c.baseURL = u }
}

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// New returns a Client with sensible defaults.
func New(opts ...Option) *Client {
	c := &Client{
		baseURL: DefaultRegistry,
		http:    httpx.NewClient(httpx.Config{}),
		retry:   httpx.DefaultRetry,
		cache:   make(map[string]*pkgPayload),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// pkgPayload is the subset of the hex.pm /packages/{name} response we
// consume. Hex returns all releases inline with publisher per release;
// one round-trip per package is enough for the maintainer-hijack
// heuristic.
type pkgPayload struct {
	Name      string `json:"name"`
	Downloads struct {
		All  int64 `json:"all"`
		Week int64 `json:"week"`
		Day  int64 `json:"day"`
	} `json:"downloads"`
	Releases []struct {
		Version    string `json:"version"`
		InsertedAt string `json:"inserted_at"`
		Publisher  struct {
			Username string `json:"username"`
		} `json:"publisher"`
		// Retired releases keep a non-nil retirement block; we surface
		// this as VersionUnpublished.
		Retirement *struct {
			Reason string `json:"reason"`
		} `json:"retirement"`
	} `json:"releases"`
}

// FetchMaintainerSignal returns the metadata bundle used by the
// maintainer-hijack heuristic. The hex.pm /packages/{name} endpoint
// returns all releases with publisher attribution inline, so one
// fetch covers PublishedAt, PreviousPublishedAt, Publisher,
// PreviousPublisher, VersionUnpublished, and WeeklyDownloads.
func (c *Client) FetchMaintainerSignal(ctx context.Context, pkg, version string) (domain.MaintainerSignal, error) {
	if pkg == "" || version == "" {
		return domain.MaintainerSignal{}, fmt.Errorf("empty package name or version")
	}

	p, err := c.fetchPackage(ctx, pkg)
	if err != nil {
		return domain.MaintainerSignal{}, err
	}

	current, previous := -1, -1
	for i, r := range p.Releases {
		if r.Version == version {
			current = i
			break
		}
	}
	// hex returns releases newest-first; the next entry is the
	// chronologically-previous release.
	if current >= 0 && current+1 < len(p.Releases) {
		previous = current + 1
	}

	out := domain.MaintainerSignal{
		WeeklyDownloads: p.Downloads.Week,
	}
	if current >= 0 {
		rel := p.Releases[current]
		out.PublishedAt = rel.InsertedAt
		out.Publisher = rel.Publisher.Username
		out.VersionUnpublished = rel.Retirement != nil
	}
	if previous >= 0 {
		rel := p.Releases[previous]
		out.PreviousVersion = rel.Version
		out.PreviousPublishedAt = rel.InsertedAt
		out.PreviousPublisher = rel.Publisher.Username
	}
	return out, nil
}

func (c *Client) fetchPackage(ctx context.Context, pkg string) (*pkgPayload, error) {
	c.mu.Lock()
	if cached, ok := c.cache[pkg]; ok {
		c.mu.Unlock()
		return cached, nil
	}
	c.mu.Unlock()

	reqURL := c.baseURL + "/packages/" + url.PathEscape(pkg)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aegis-cli (https://github.com/qwexvf/aegis-cli)")

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return nil, fmt.Errorf("hex.pm fetch %s: %w", pkg, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found on hex.pm", pkg)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("hex.pm returned %d for %s", resp.StatusCode, pkg)
	}

	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read hex.pm response %s: %w", pkg, err)
	}
	var p pkgPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode hex.pm response %s: %w", pkg, err)
	}

	c.mu.Lock()
	c.cache[pkg] = &p
	c.mu.Unlock()
	return &p, nil
}

// FetchMaintainerSignalForEcosystem implements
// usecase.MaintainerSignalFetcher for Hex-hosted ecosystems
// (EcoGleam covers both Gleam and Elixir today). Returns a zero
// signal for unsupported ecosystems so the heuristic degrades
// gracefully.
func (c *Client) FetchMaintainerSignalForEcosystem(ctx context.Context, eco domain.Ecosystem, name, version string) (domain.MaintainerSignal, error) {
	if eco != domain.EcoGleam {
		return domain.MaintainerSignal{}, nil
	}
	return c.FetchMaintainerSignal(ctx, name, version)
}
