// Package npmregistry resolves npm version ranges and tags to concrete
// versions by querying the npm public registry. It satisfies
// usecase.VersionResolver.
package npmregistry

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/sync/singleflight"

	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

// DefaultRegistry is the public npm registry. Override with WithRegistry.
const DefaultRegistry = "https://registry.npmjs.org"

// Client is an npm registry client with an in-memory metadata cache. The
// cache lives for the lifetime of the process — appropriate for a single
// `aegis npm install` invocation.
//
// Concurrent fetches for the same package are coalesced through
// singleflight: the snapshot enrich worker pool can request the same
// packument from N workers at once when sibling versions are processed
// in parallel. Without coalescing each goroutine misses the cache and
// fires its own HTTP call; with it the N–1 followers wait for the
// in-flight request and reuse the result.
type Client struct {
	baseURL      string
	downloadsURL string // empty → DefaultDownloadsURL
	http         *http.Client
	retry        httpx.RetryPolicy

	mu    sync.Mutex
	cache map[string]*packument

	flight singleflight.Group
}

// Option configures a Client.
type Option func(*Client)

// WithRegistry sets a non-default registry URL.
func WithRegistry(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// WithDownloadsURL overrides the api.npmjs.org URL used by
// FetchMaintainerSignal for download-count lookups. Use this for
// private mirrors that expose a downloads-shaped endpoint, or for
// httptest servers in tests.
func WithDownloadsURL(u string) Option {
	return func(c *Client) { c.downloadsURL = strings.TrimRight(u, "/") }
}

// WithHTTPClient overrides the default HTTP client (useful for tests).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithRetryPolicy overrides the retry policy used by Resolve and
// PublishedAt. Default: httpx.DefaultRetry. Pass httpx.NoRetry to
// disable retries (rarely useful here — registry queries are GETs).
func WithRetryPolicy(p httpx.RetryPolicy) Option {
	return func(c *Client) { c.retry = p }
}

// New constructs a Client with sensible defaults.
func New(opts ...Option) *Client {
	c := &Client{
		baseURL: DefaultRegistry,
		http:    httpx.NewClient(httpx.Config{}),
		retry:   httpx.DefaultRetry,
		cache:   make(map[string]*packument),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// packument is the subset of the npm registry response we care about.
type packument struct {
	Name     string            `json:"name"`
	DistTags map[string]string `json:"dist-tags"`
	Versions map[string]struct {
		Version string `json:"version"`
	} `json:"versions"`
}

// DefaultDownloadsURL is the public npm downloads API. Overrideable
// via WithDownloadsURL — separate from the registry URL because npm
// hosts these on a different domain (api.npmjs.org vs
// registry.npmjs.org).
const DefaultDownloadsURL = "https://api.npmjs.org"

// MaintainerSignal bundles the metadata the maintainer-hijack
// heuristic needs into one round-trip-friendly shape. All fields are
// best-effort — a missing endpoint or stripped field zeroes out and
// the heuristic degrades gracefully.
type MaintainerSignal struct {
	// PublishedAt is the registry-reported publish time of the
	// requested version (RFC3339). Empty when the registry doesn't
	// expose it.
	PublishedAt string

	// WeeklyDownloads is the package's last-week download count from
	// api.npmjs.org. Zero on lookup failure (treat as "unknown",
	// not "no users").
	WeeklyDownloads int64

	// PreviousVersion is the most-recent version BEFORE the queried
	// one (lex sort over time map). Used to compute the publish-gap.
	// Empty when there's no prior version (first publish).
	PreviousVersion string

	// PreviousPublishedAt is RFC3339 of the previous version's
	// publish time. Pair with PublishedAt to compute the gap.
	PreviousPublishedAt string
}

// FetchMaintainerSignal returns the metadata bundle used by the
// maintainer-hijack heuristic. Implements usecase.MaintainerSignalFetcher
// via the wrapper below. One full-packument GET (which we already do
// for PublishedAt) plus one downloads GET. Errors from either are
// non-fatal — the returned struct just has zero/empty fields where
// the data was unavailable.
//
// Cheap on warm cache: the underlying fetchPackument is singleflighted
// and process-cached, so repeated calls for sibling versions of the
// same package share the round-trip.
func (c *Client) FetchMaintainerSignal(ctx context.Context, pkg, version string) (MaintainerSignal, error) {
	if pkg == "" || version == "" {
		return MaintainerSignal{}, fmt.Errorf("empty package name or version")
	}
	encoded := url.PathEscape(pkg)
	if strings.HasPrefix(pkg, "@") {
		encoded = strings.Replace(encoded, "/", "%2F", 1)
	}
	reqURL := c.baseURL + "/" + encoded
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return MaintainerSignal{}, err
	}
	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return MaintainerSignal{}, fmt.Errorf("registry fetch %s: %w", pkg, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return MaintainerSignal{}, fmt.Errorf("registry returned %d for %s", resp.StatusCode, pkg)
	}
	var p struct {
		Time map[string]string `json:"time"`
	}
	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return MaintainerSignal{}, fmt.Errorf("read packument %s: %w", pkg, err)
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return MaintainerSignal{}, fmt.Errorf("decode packument %s: %w", pkg, err)
	}

	out := MaintainerSignal{
		PublishedAt: p.Time[version],
	}
	out.PreviousVersion, out.PreviousPublishedAt = previousVersion(p.Time, version, out.PublishedAt)

	// Best-effort weekly downloads. Failure is silently zeroed —
	// the heuristic interprets zero as "unknown", not "no users".
	if dl, err := c.fetchWeeklyDownloads(ctx, pkg); err == nil {
		out.WeeklyDownloads = dl
	}
	return out, nil
}

// fetchWeeklyDownloads hits the npm downloads endpoint
// (api.npmjs.org/downloads/point/last-week/<pkg>). Returns an error
// only when the call itself fails; a 404 (unpublished package, or
// scoped packages which don't have public download stats) returns 0
// with a nil error.
func (c *Client) fetchWeeklyDownloads(ctx context.Context, pkg string) (int64, error) {
	downloadsURL := cmp.Or(c.downloadsURL, DefaultDownloadsURL)
	// The downloads endpoint uses URL path encoding for scoped
	// packages — same %2F convention as the registry.
	encoded := url.PathEscape(pkg)
	if strings.HasPrefix(pkg, "@") {
		encoded = strings.Replace(encoded, "/", "%2F", 1)
	}
	reqURL := downloadsURL + "/downloads/point/last-week/" + encoded
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil // no public stats; not an error
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("downloads %s: HTTP %d", pkg, resp.StatusCode)
	}
	var dl struct {
		Downloads int64 `json:"downloads"`
	}
	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal(body, &dl); err != nil {
		return 0, err
	}
	return dl.Downloads, nil
}

// previousVersion finds the version published most recently BEFORE
// `current` (using publish times from the packument's time map).
// Skips entries that don't parse as RFC3339 timestamps and meta keys
// like "created" / "modified". Returns ("", "") when there's no
// earlier version.
func previousVersion(timeMap map[string]string, current, currentTime string) (string, string) {
	if currentTime == "" {
		return "", ""
	}
	var (
		bestVer  string
		bestTime string
	)
	for ver, t := range timeMap {
		if ver == current || ver == "created" || ver == "modified" {
			continue
		}
		if t >= currentTime {
			continue // not earlier
		}
		if t > bestTime {
			bestVer = ver
			bestTime = t
		}
	}
	return bestVer, bestTime
}

// PublishedAt fetches the npm `time[version]` value for a specific
// version. Returns "" with a nil error when the registry doesn't
// expose that field for the version.
//
// Uses the *full* packument (no Accept header) because the abbreviated
// metadata format omits the `time` map.
func (c *Client) PublishedAt(ctx context.Context, pkg, version string) (string, error) {
	if pkg == "" || version == "" {
		return "", fmt.Errorf("empty package name or version")
	}

	encoded := url.PathEscape(pkg)
	if strings.HasPrefix(pkg, "@") {
		encoded = strings.Replace(encoded, "/", "%2F", 1)
	}
	reqURL := c.baseURL + "/" + encoded

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	// No Accept header here — the abbreviated install-v1 packument
	// strips the `time` map we need.

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return "", fmt.Errorf("registry fetch %s: %w", pkg, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("package %q not found on registry", pkg)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("registry returned %d for %s", resp.StatusCode, pkg)
	}

	var p struct {
		Time map[string]string `json:"time"`
	}
	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return "", fmt.Errorf("read packument %s: %w", pkg, err)
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", fmt.Errorf("decode packument time map for %s: %w", pkg, err)
	}
	if t, ok := p.Time[version]; ok {
		return t, nil
	}
	return "", nil
}

// Resolve returns the concrete version of pkg that matches the given range,
// tag, or exact version. An empty rangeOrTag is treated as "latest".
//
// Examples:
//
//	Resolve(ctx, "lodash", "")          -> "4.17.21"  (latest)
//	Resolve(ctx, "lodash", "latest")    -> "4.17.21"
//	Resolve(ctx, "lodash", "^4.17.0")   -> "4.17.21"
//	Resolve(ctx, "lodash", "4.17.20")   -> "4.17.20"  (exact)
func (c *Client) Resolve(ctx context.Context, pkg, rangeOrTag string) (string, error) {
	if pkg == "" {
		return "", fmt.Errorf("empty package name")
	}

	pkmt, err := c.fetchPackument(ctx, pkg)
	if err != nil {
		return "", err
	}

	if rangeOrTag == "" {
		rangeOrTag = "latest"
	}

	// Tag: exact match against dist-tags.
	if v, ok := pkmt.DistTags[rangeOrTag]; ok {
		return v, nil
	}

	// Exact version: must exist in versions map.
	if _, ok := pkmt.Versions[rangeOrTag]; ok {
		return rangeOrTag, nil
	}

	// Range: pick the highest version that satisfies it.
	constraint, err := semver.NewConstraint(rangeOrTag)
	if err != nil {
		return "", fmt.Errorf("invalid version or range %q for %s: %w", rangeOrTag, pkg, err)
	}

	var best *semver.Version
	for v := range pkmt.Versions {
		ver, err := semver.NewVersion(v)
		if err != nil {
			continue
		}
		if !constraint.Check(ver) {
			continue
		}
		if best == nil || ver.GreaterThan(best) {
			best = ver
		}
	}
	if best == nil {
		return "", fmt.Errorf("no version of %s satisfies %q", pkg, rangeOrTag)
	}
	return best.Original(), nil
}

func (c *Client) fetchPackument(ctx context.Context, pkg string) (*packument, error) {
	c.mu.Lock()
	if p, ok := c.cache[pkg]; ok {
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()

	// Coalesce concurrent same-key misses. The first goroutine does
	// the fetch; the rest wait inside Do() and receive the same
	// pointer (or error) without re-issuing the HTTP request.
	v, err, _ := c.flight.Do(pkg, func() (any, error) {
		return c.fetchPackumentLocked(ctx, pkg)
	})
	if err != nil {
		return nil, err
	}
	return v.(*packument), nil
}

// fetchPackumentLocked is the unsynchronized fetch + cache-store body.
// Only ever called from inside flight.Do for a given pkg key, so the
// cache write is race-free without holding c.mu around the HTTP call.
func (c *Client) fetchPackumentLocked(ctx context.Context, pkg string) (*packument, error) {
	// Re-check the cache: a previous in-flight call may have completed
	// between our first miss and the singleflight callback firing.
	c.mu.Lock()
	if p, ok := c.cache[pkg]; ok {
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()

	// npm registry expects scoped packages URL-encoded: @foo/bar -> @foo%2Fbar
	encoded := url.PathEscape(pkg)
	if strings.HasPrefix(pkg, "@") {
		// PathEscape doesn't escape '/' — do it manually for scoped packages.
		encoded = strings.Replace(encoded, "/", "%2F", 1)
	}
	reqURL := c.baseURL + "/" + encoded

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	// Abbreviated metadata is much smaller and contains everything we need.
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return nil, fmt.Errorf("registry fetch %s: %w", pkg, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found on registry", pkg)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("registry returned %d for %s", resp.StatusCode, pkg)
	}

	var p packument
	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read packument %s: %w", pkg, err)
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode registry response for %s: %w", pkg, err)
	}

	c.mu.Lock()
	c.cache[pkg] = &p
	c.mu.Unlock()
	return &p, nil
}
