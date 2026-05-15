// Package cratesregistry fetches package metadata from the crates.io API.
package cratesregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

const defaultBaseURL = "https://crates.io"

// Client fetches crates.io package metadata with an in-memory cache.
type Client struct {
	baseURL string
	http    *http.Client
	mu      sync.Mutex
	cache   map[string]string // "name@version" -> license
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client used for requests.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithBaseURL overrides the base URL (useful for testing).
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = u }
}

// New creates a crates.io client.
func New(opts ...Option) *Client {
	c := &Client{
		baseURL: defaultBaseURL,
		http:    http.DefaultClient,
		cache:   make(map[string]string),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

type cratesVersion struct {
	Version struct {
		License string `json:"license"`
	} `json:"version"`
}

// FetchLicense returns the SPDX license for a crates.io package version.
// Returns "" when the API reports no license. Results are cached in-memory.
func (c *Client) FetchLicense(ctx context.Context, name, version string) (string, error) {
	key := name + "@" + version
	c.mu.Lock()
	if lic, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return lic, nil
	}
	c.mu.Unlock()

	reqURL := fmt.Sprintf("%s/api/v1/crates/%s/%s",
		c.baseURL, url.PathEscape(name), url.PathEscape(version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	// crates.io requires a User-Agent identifying the client.
	req.Header.Set("User-Agent", "aegis-cli (https://github.com/qwexvf/aegis-cli)")

	resp, err := httpx.Do(ctx, c.http, req, httpx.DefaultRetry)
	if err != nil {
		return "", fmt.Errorf("crates.io fetch %s@%s: %w", name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("crates.io returned %d for %s@%s", resp.StatusCode, name, version)
	}

	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return "", fmt.Errorf("read crates.io response %s@%s: %w", name, version, err)
	}

	var info cratesVersion
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("decode crates.io response %s@%s: %w", name, version, err)
	}

	lic := info.Version.License
	c.mu.Lock()
	c.cache[key] = lic
	c.mu.Unlock()
	return lic, nil
}
