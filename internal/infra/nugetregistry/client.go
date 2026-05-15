// Package nugetregistry fetches package metadata from the NuGet v3 API.
package nugetregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

const defaultBaseURL = "https://api.nuget.org"

// Client fetches NuGet package metadata with an in-memory cache.
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

// New creates a NuGet client.
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

// nugetCatalogEntry is the subset of the NuGet registration leaf we care about.
type nugetCatalogEntry struct {
	CatalogEntry struct {
		LicenseExpression string `json:"licenseExpression"`
		LicenseURL        string `json:"licenseUrl"`
	} `json:"catalogEntry"`
}

// FetchLicense returns the license for a NuGet package at a specific version.
// Uses the v3 registration API (registration5-gz-semver2). Prefers
// licenseExpression (SPDX) over licenseUrl (legacy).
// Returns "" when the API reports no license. Results are cached in-memory.
func (c *Client) FetchLicense(ctx context.Context, name, version string) (string, error) {
	key := name + "@" + version
	c.mu.Lock()
	if lic, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return lic, nil
	}
	c.mu.Unlock()

	// NuGet registration URL uses lowercase package name.
	lower := strings.ToLower(name)
	reqURL := fmt.Sprintf("%s/v3/registration5-gz-semver2/%s/%s.json",
		c.baseURL, lower, strings.ToLower(version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := httpx.Do(ctx, c.http, req, httpx.DefaultRetry)
	if err != nil {
		return "", fmt.Errorf("nuget fetch %s@%s: %w", name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("nuget returned %d for %s@%s", resp.StatusCode, name, version)
	}

	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return "", fmt.Errorf("read nuget response %s@%s: %w", name, version, err)
	}

	var entry nugetCatalogEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		return "", fmt.Errorf("decode nuget response %s@%s: %w", name, version, err)
	}

	lic := entry.CatalogEntry.LicenseExpression
	if lic == "" {
		lic = entry.CatalogEntry.LicenseURL
	}
	c.mu.Lock()
	c.cache[key] = lic
	c.mu.Unlock()
	return lic, nil
}
