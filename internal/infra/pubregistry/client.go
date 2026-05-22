// Package pubregistry fetches package metadata from the pub.dev
// public API. Used by the maintainer-hijack heuristic for Dart and
// Flutter packages.
//
// API reference: https://github.com/dart-lang/pub.dev/blob/master/doc/api.md
//
// pub.dev does not expose download counts, so WeeklyDownloads is
// always zero. Uploader information lives on a separate endpoint and
// is best-effort (returns 401 for private publishers).
package pubregistry

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

// DefaultRegistry is the public pub.dev API base URL.
const DefaultRegistry = "https://pub.dev/api"

// Client fetches pub.dev package metadata with an in-memory cache.
type Client struct {
	baseURL string
	http    *http.Client
	retry   httpx.RetryPolicy

	mu    sync.Mutex
	cache map[string]*pkgPayload
}

// Option configures a Client.
type Option func(*Client)

// WithRegistry sets a non-default API base URL.
func WithRegistry(u string) Option { return func(c *Client) { c.baseURL = u } }

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

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

// pkgPayload is the subset of /api/packages/{name} we use. The
// `versions` array is sorted newest-first by pub.dev.
type pkgPayload struct {
	Name     string   `json:"name"`
	Latest   pubRel   `json:"latest"`
	Versions []pubRel `json:"versions"`
}

type pubRel struct {
	Version   string `json:"version"`
	Published string `json:"published"`
	Retracted bool   `json:"retracted"`
}

// publisherPayload is the subset of /api/packages/{name}/publisher.
type publisherPayload struct {
	PublisherID string `json:"publisherId"`
}

// FetchMaintainerSignal returns the metadata bundle used by the
// maintainer-hijack heuristic.
//
// Notes vs npm:
//   - pub.dev exposes publish time per version inline.
//   - The "publisher" is a verified-domain identity (e.g. "dart.dev"),
//     not a per-release username. We surface it as Publisher and
//     PreviousPublisher (same value — pub.dev publishers don't change
//     per-release).
//   - WeeklyDownloads is always 0: pub.dev does not expose counts.
func (c *Client) FetchMaintainerSignal(ctx context.Context, pkg, version string) (domain.MaintainerSignal, error) {
	if pkg == "" || version == "" {
		return domain.MaintainerSignal{}, fmt.Errorf("empty package name or version")
	}

	p, err := c.fetchPackage(ctx, pkg)
	if err != nil {
		return domain.MaintainerSignal{}, err
	}

	var current, previous int = -1, -1
	for i, v := range p.Versions {
		if v.Version == version {
			current = i
			break
		}
	}
	if current >= 0 && current+1 < len(p.Versions) {
		previous = current + 1
	}

	out := domain.MaintainerSignal{}
	if current >= 0 {
		rel := p.Versions[current]
		out.PublishedAt = rel.Published
		out.VersionUnpublished = rel.Retracted
	}
	if previous >= 0 {
		rel := p.Versions[previous]
		out.PreviousVersion = rel.Version
		out.PreviousPublishedAt = rel.Published
	}

	// Best-effort publisher lookup. Failure (private, 401, network) is
	// silently zeroed — heuristic interprets "" as no signal.
	if pub, err := c.fetchPublisher(ctx, pkg); err == nil && pub != "" {
		out.Publisher = pub
		out.PreviousPublisher = pub // pub.dev: publisher is per-package, not per-release.
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
		return nil, fmt.Errorf("pub.dev fetch %s: %w", pkg, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found on pub.dev", pkg)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("pub.dev returned %d for %s", resp.StatusCode, pkg)
	}

	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read pub.dev response %s: %w", pkg, err)
	}
	var p pkgPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode pub.dev response %s: %w", pkg, err)
	}

	c.mu.Lock()
	c.cache[pkg] = &p
	c.mu.Unlock()
	return &p, nil
}

func (c *Client) fetchPublisher(ctx context.Context, pkg string) (string, error) {
	reqURL := c.baseURL + "/packages/" + url.PathEscape(pkg) + "/publisher"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aegis-cli (https://github.com/qwexvf/aegis-cli)")

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return "", err
	}
	var pp publisherPayload
	if err := json.Unmarshal(body, &pp); err != nil {
		return "", err
	}
	return pp.PublisherID, nil
}

// FetchMaintainerSignalForEcosystem implements
// usecase.MaintainerSignalFetcher for the Pub ecosystem (Dart). Returns
// a zero signal for unsupported ecosystems so the heuristic degrades
// gracefully.
func (c *Client) FetchMaintainerSignalForEcosystem(ctx context.Context, eco domain.Ecosystem, name, version string) (domain.MaintainerSignal, error) {
	if eco != domain.EcoPub {
		return domain.MaintainerSignal{}, nil
	}
	return c.FetchMaintainerSignal(ctx, name, version)
}
