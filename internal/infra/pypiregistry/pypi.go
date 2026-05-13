// Package pypiregistry fetches package metadata from the PyPI JSON API.
package pypiregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

const defaultBaseURL = "https://pypi.org"

// Client fetches PyPI package metadata with an in-memory cache.
type Client struct {
	baseURL string
	http    *http.Client
	mu      sync.Mutex
	cache   map[string]string // "name@version" -> license
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client used for PyPI requests.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithBaseURL overrides the PyPI base URL (useful for testing).
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = u }
}

// New creates a PyPI client.
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

// pypiInfo is the subset of the PyPI JSON API we care about.
type pypiInfo struct {
	Info struct {
		License string `json:"license"`
	} `json:"info"`
}

// FetchLicense returns the license string for a PyPI package version.
// Returns "" when the API reports no license. Results are cached in-memory.
func (c *Client) FetchLicense(ctx context.Context, name, version string) (string, error) {
	key := name + "@" + version
	c.mu.Lock()
	if lic, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return lic, nil
	}
	c.mu.Unlock()

	reqURL := fmt.Sprintf("%s/pypi/%s/%s/json", c.baseURL, url.PathEscape(name), url.PathEscape(version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := httpx.Do(ctx, c.http, req, httpx.DefaultRetry)
	if err != nil {
		return "", fmt.Errorf("pypi fetch %s@%s: %w", name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("pypi returned %d for %s@%s", resp.StatusCode, name, version)
	}

	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return "", fmt.Errorf("read pypi response %s@%s: %w", name, version, err)
	}
	var info pypiInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("decode pypi response %s@%s: %w", name, version, err)
	}

	lic := info.Info.License
	c.mu.Lock()
	c.cache[key] = lic
	c.mu.Unlock()
	return lic, nil
}
