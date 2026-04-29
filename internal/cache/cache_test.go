package cache

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/api"
)

func tmpCache(t *testing.T) *Cache {
	t.Helper()
	dir := t.TempDir()
	return NewAt(filepath.Join(dir, "decisions.json"))
}

func sampleDecision() *api.Decision {
	return &api.Decision{
		Ecosystem: "npm",
		Package:   "lodash",
		Version:   "4.17.21",
		Decision:  "allow",
		Severity:  "info",
		Cached:    false,
	}
}

func TestCache_GetMissReturnsFalse(t *testing.T) {
	c := tmpCache(t)
	if _, ok := c.Get(Key("npm", "lodash", "4.17.21")); ok {
		t.Error("Get on empty cache should miss")
	}
}

func TestCache_PutThenGet(t *testing.T) {
	c := tmpCache(t)
	d := sampleDecision()
	if err := c.Put(Key("npm", "lodash", "4.17.21"), d, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get(Key("npm", "lodash", "4.17.21"))
	if !ok {
		t.Fatal("expected hit after Put")
	}
	if got.Package != "lodash" {
		t.Errorf("got package %q, want lodash", got.Package)
	}
}

func TestCache_GetExpiredReturnsFalse(t *testing.T) {
	c := tmpCache(t)
	d := sampleDecision()
	// Negative TTL would fall back to default; pass a tiny positive then wait.
	if err := c.Put(Key("npm", "lodash", "4.17.21"), d, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.Get(Key("npm", "lodash", "4.17.21")); ok {
		t.Error("expected miss after expiry")
	}
}

func TestCache_Clear(t *testing.T) {
	c := tmpCache(t)
	if err := c.Put("k", sampleDecision(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("k"); ok {
		t.Error("expected miss after Clear")
	}
	// Clear on missing file must not error.
	if err := c.Clear(); err != nil {
		t.Errorf("Clear on missing file errored: %v", err)
	}
}

func TestCache_List(t *testing.T) {
	c := tmpCache(t)
	c.Put(Key("npm", "react", "18.0.0"), sampleDecision(), time.Minute)
	c.Put(Key("npm", "lodash", "4.17.21"), sampleDecision(), time.Minute)
	entries, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// Sorted by key — lodash before react alphabetically.
	if entries[0].Key != Key("npm", "lodash", "4.17.21") {
		t.Errorf("entries not sorted: %v", entries)
	}
}

func TestCache_CorruptFileRecovers(t *testing.T) {
	c := tmpCache(t)
	// Plant garbage in the cache file.
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Get returns miss (decode error → false).
	if _, ok := c.Get("k"); ok {
		t.Error("expected miss on corrupt file")
	}
	// Put recovers by overwriting.
	if err := c.Put("k", sampleDecision(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("k"); !ok {
		t.Error("expected hit after Put recovered corrupt cache")
	}
}

func TestCache_ConcurrentPuts(t *testing.T) {
	c := tmpCache(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Put(Key("npm", "p", string(rune('a'+i%26))), sampleDecision(), time.Minute)
		}(i)
	}
	wg.Wait()
	// Final state must be parseable.
	if _, err := c.List(); err != nil {
		t.Fatalf("cache corrupt after concurrent puts: %v", err)
	}
}
