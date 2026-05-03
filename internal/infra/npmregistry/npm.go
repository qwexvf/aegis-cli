// Package npmregistry resolves npm version ranges and tags to concrete
// versions by querying the npm public registry. It satisfies
// usecase.VersionResolver.
package npmregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"
	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

// DefaultRegistry is the public npm registry. Override with WithRegistry.
const DefaultRegistry = "https://registry.npmjs.org"

// Client is an npm registry client with an in-memory metadata cache. The
// cache lives for the lifetime of the process — appropriate for a single
// `aegis npm install` invocation.
type Client struct {
	baseURL string
	http    *http.Client
	retry   httpx.RetryPolicy

	mu    sync.Mutex
	cache map[string]*packument
}

// Option configures a Client.
type Option func(*Client)

// WithRegistry sets a non-default registry URL.
func WithRegistry(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
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
