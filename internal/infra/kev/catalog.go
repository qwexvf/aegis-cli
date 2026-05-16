// Package kev downloads and caches the CISA Known Exploited
// Vulnerabilities catalog. KEV entries represent CVEs that are being
// actively exploited in the wild and carry a mandatory federal
// remediation deadline — they are the highest-priority findings.
//
// Feed URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
// Refreshed by CISA daily. We cache the full feed locally with a 24 h
// TTL so repeated scans don't re-download a multi-KB file every run.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

const (
	feedURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	cacheTTL  = 24 * time.Hour
	cacheFile = "kev.json"
)

// Catalog holds the KEV feed as an in-memory CVE ID set.
// Thread-safe after the first call to load().
type Catalog struct {
	cacheDir string
	http     *http.Client
	retry    httpx.RetryPolicy

	mu  sync.RWMutex
	set map[string]struct{} // nil = not yet loaded
}

// Option configures a Catalog.
type Option func(*Catalog)

// WithHTTPClient injects the shared HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Catalog) { c.http = h }
}

// WithCacheDir sets the directory for the on-disk KEV JSON cache.
// Empty string disables disk caching (fetch on every process start).
func WithCacheDir(dir string) Option {
	return func(c *Catalog) { c.cacheDir = dir }
}

// New returns a Catalog. The feed is NOT downloaded at construction;
// it is lazily loaded on the first IsKEV call.
func New(opts ...Option) *Catalog {
	c := &Catalog{
		http:  httpx.NewClient(httpx.Config{Timeout: 20 * time.Second}),
		retry: httpx.DefaultRetry,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// IsKEV returns true when cveID appears in the CISA KEV catalog.
// The catalog is loaded lazily on first call. Network or parse errors
// degrade to false so the rest of the scan isn't blocked.
func (c *Catalog) IsKEV(ctx context.Context, cveID string) bool {
	c.mu.RLock()
	if c.set != nil {
		_, ok := c.set[cveID]
		c.mu.RUnlock()
		return ok
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set != nil {
		_, ok := c.set[cveID]
		return ok
	}
	set, err := c.loadSet(ctx)
	if err != nil {
		c.set = map[string]struct{}{} // cache empty to avoid repeated failures
		return false
	}
	c.set = set
	_, ok := c.set[cveID]
	return ok
}

type kevFeed struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

func (c *Catalog) loadSet(ctx context.Context) (map[string]struct{}, error) {
	// Try disk cache first.
	if raw, ok := c.loadCached(); ok {
		return parseKEV(raw)
	}
	// Download from CISA.
	raw, err := c.download(ctx)
	if err != nil {
		return nil, err
	}
	c.saveCached(raw)
	return parseKEV(raw)
}

func (c *Catalog) cachePath() string {
	if c.cacheDir == "" {
		return ""
	}
	return filepath.Join(c.cacheDir, cacheFile)
}

func (c *Catalog) loadCached() ([]byte, bool) {
	p := c.cachePath()
	if p == "" {
		return nil, false
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) > cacheTTL {
		return nil, false // stale
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return raw, true
}

func (c *Catalog) saveCached(raw []byte) {
	p := c.cachePath()
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(p, raw, 0o600)
}

func (c *Catalog) download(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return nil, fmt.Errorf("kev feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev feed: HTTP %d", resp.StatusCode)
	}
	// KEV feed is ~300 KB; cap at 10 MB to be generous.
	const maxKEVBytes = 10 * 1024 * 1024
	return httpx.ReadCapped(resp.Body, maxKEVBytes)
}

func parseKEV(raw []byte) (map[string]struct{}, error) {
	var feed kevFeed
	if err := json.Unmarshal(raw, &feed); err != nil {
		return nil, fmt.Errorf("kev parse: %w", err)
	}
	set := make(map[string]struct{}, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		if v.CVEID != "" {
			set[v.CVEID] = struct{}{}
		}
	}
	return set, nil
}
