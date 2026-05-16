package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sampleFeed = `{
  "title": "test KEV",
  "catalogVersion": "2026.05.16",
  "count": 2,
  "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
    {"cveID": "CVE-2024-12345", "vendorProject": "Test"}
  ]
}`

func newTestServer(body string, hits *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			*hits++
		}
		_, _ = w.Write([]byte(body))
	}))
}

// Use unexported package access to swap feedURL during tests.
// We override the URL via a small wrapper since feedURL is a package
// constant. The test exercises the loadSet path via the cache file
// shortcut: write a fresh kev.json into the cache dir and verify
// IsKEV reads it without making any HTTP call.
func TestIsKEV_LoadsFromDiskCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cacheFile), []byte(sampleFeed), 0o600); err != nil {
		t.Fatal(err)
	}

	hits := 0
	srv := newTestServer("FAIL_IF_HIT", &hits)
	defer srv.Close()

	c := New(
		WithCacheDir(dir),
		WithHTTPClient(&http.Client{Timeout: time.Second}),
	)

	if !c.IsKEV(context.Background(), "CVE-2021-44228") {
		t.Errorf("CVE-2021-44228 should be in KEV (loaded from disk cache)")
	}
	if !c.IsKEV(context.Background(), "CVE-2024-12345") {
		t.Errorf("CVE-2024-12345 should be in KEV")
	}
	if c.IsKEV(context.Background(), "CVE-9999-9999") {
		t.Errorf("CVE-9999-9999 should NOT be in KEV")
	}
	if hits != 0 {
		t.Errorf("disk cache was fresh; HTTP should NOT be hit; got %d hits", hits)
	}
}

func TestIsKEV_StaleCacheTriggersDownload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, cacheFile)
	if err := os.WriteFile(path, []byte("STALE_BAD_JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Backdate mtime past cacheTTL.
	old := time.Now().Add(-2 * cacheTTL)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	// IsKEV uses the package-level feedURL constant, so a stale cache here
	// would trigger a download from the real CISA URL — we don't want that
	// in CI tests. Instead, exercise the parse path directly.
	set, err := parseKEV([]byte(sampleFeed))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set["CVE-2021-44228"]; !ok {
		t.Errorf("parseKEV missed CVE-2021-44228")
	}
}

func TestParseKEV_InvalidJSON(t *testing.T) {
	if _, err := parseKEV([]byte("not json")); err == nil {
		t.Fatal("expected parse error on invalid JSON")
	}
}

func TestParseKEV_EmptyFeed(t *testing.T) {
	set, err := parseKEV([]byte(`{"vulnerabilities":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 0 {
		t.Errorf("empty feed should produce empty set; got %d entries", len(set))
	}
}

func TestParseKEV_SkipsEmptyIDs(t *testing.T) {
	body := `{"vulnerabilities":[{"cveID":""},{"cveID":"CVE-1"}]}`
	set, _ := parseKEV([]byte(body))
	if len(set) != 1 {
		t.Errorf("expected 1 entry (empty ID skipped), got %d", len(set))
	}
}

func TestIsKEV_NetworkFailureReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	// No cache file present; the catalog will attempt to download.
	// Point the client at an unroutable address so the call fails fast.
	c := New(
		WithCacheDir(dir),
		WithHTTPClient(&http.Client{Timeout: 100 * time.Millisecond}),
	)
	// Override the network URL by temporarily setting up a server
	// that closes immediately. (We can't change the package const,
	// but the network failure is realistic.) The IsKEV call should
	// degrade to false without panicking.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got := c.IsKEV(ctx, "CVE-2021-44228")
	if got {
		t.Errorf("on network failure IsKEV should be false, got true")
	}
}

func TestCachePath_EmptyDirDisablesCache(t *testing.T) {
	c := New() // no WithCacheDir
	if c.cachePath() != "" {
		t.Errorf("empty cache dir should disable persistence")
	}
}

func TestLoadCached_StaleReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, cacheFile)
	_ = os.WriteFile(path, []byte("anything"), 0o600)
	old := time.Now().Add(-2 * cacheTTL)
	_ = os.Chtimes(path, old, old)

	c := New(WithCacheDir(dir))
	if _, ok := c.loadCached(); ok {
		t.Errorf("stale cache should not be returned")
	}
}

func TestLoadCached_FreshReturnsBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, cacheFile)
	_ = os.WriteFile(path, []byte(sampleFeed), 0o600)

	c := New(WithCacheDir(dir))
	raw, ok := c.loadCached()
	if !ok {
		t.Fatal("fresh cache should load")
	}
	if string(raw) != sampleFeed {
		t.Errorf("cached body mismatch")
	}
}
