// Package rubygemsregistry fetches package metadata from the RubyGems API.
package rubygemsregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

const defaultBaseURL = "https://rubygems.org"

// Client fetches RubyGems package metadata with an in-memory cache.
type Client struct {
	baseURL string
	http    *http.Client
	mu      sync.Mutex
	cache   map[string]string // "name@version" -> license
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithBaseURL overrides the base URL (useful for testing).
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = u }
}

// New creates a RubyGems client.
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

// rubyGemVersion is returned by the RubyGems v2 version API.
type rubyGemVersion struct {
	Licenses []string `json:"licenses"`
}

// FetchLicense returns the license for a RubyGems package at a specific version.
// Uses the v2 API which provides version-specific metadata.
// Returns "" when the API reports no license. Results are cached in-memory.
func (c *Client) FetchLicense(ctx context.Context, name, version string) (string, error) {
	key := name + "@" + version
	c.mu.Lock()
	if lic, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return lic, nil
	}
	c.mu.Unlock()

	reqURL := fmt.Sprintf("%s/api/v2/rubygems/%s/versions/%s.json",
		c.baseURL, url.PathEscape(name), url.PathEscape(version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := httpx.Do(ctx, c.http, req, httpx.DefaultRetry)
	if err != nil {
		return "", fmt.Errorf("rubygems fetch %s@%s: %w", name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("rubygems returned %d for %s@%s", resp.StatusCode, name, version)
	}

	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return "", fmt.Errorf("read rubygems response %s@%s: %w", name, version, err)
	}

	var info rubyGemVersion
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("decode rubygems response %s@%s: %w", name, version, err)
	}

	lic := strings.Join(info.Licenses, ", ")
	c.mu.Lock()
	c.cache[key] = lic
	c.mu.Unlock()
	return lic, nil
}
