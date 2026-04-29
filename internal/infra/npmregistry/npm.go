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
	"time"

	"github.com/Masterminds/semver/v3"
)

// DefaultRegistry is the public npm registry. Override with WithRegistry.
const DefaultRegistry = "https://registry.npmjs.org"

// Client is an npm registry client with an in-memory metadata cache. The
// cache lives for the lifetime of the process — appropriate for a single
// `aegis npm install` invocation.
type Client struct {
	baseURL string
	http    *http.Client

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

// New constructs a Client with sensible defaults.
func New(opts ...Option) *Client {
	c := &Client{
		baseURL: DefaultRegistry,
		http:    &http.Client{Timeout: 10 * time.Second},
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
	req.Header.Set("User-Agent", "aegis-cli/0.1.0-demo")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry fetch %s: %w", pkg, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found on registry", pkg)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("registry returned %d for %s", resp.StatusCode, pkg)
	}

	var p packument
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("decode registry response for %s: %w", pkg, err)
	}

	c.mu.Lock()
	c.cache[pkg] = &p
	c.mu.Unlock()
	return &p, nil
}
