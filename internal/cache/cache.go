// Package cache stores Aegis API decisions on disk so repeat installs
// of the same package@version don't hit the network.
package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/api"
)

// DefaultTTL is how long cached decisions are considered fresh when no
// explicit TTL is provided. Override with AEGIS_CACHE_TTL (Go duration).
const DefaultTTL = time.Hour

// Entry is one persisted cache record.
type Entry struct {
	Decision  *api.Decision `json:"decision"`
	ExpiresAt time.Time     `json:"expires_at"`
}

type fileSchema struct {
	Entries map[string]Entry `json:"entries"`
}

// Cache is a JSON-file decision cache. Safe for concurrent use within a
// process; concurrent users across processes rely on the atomic temp+
// rename writes (last-write-wins, no lock file).
type Cache struct {
	path string
	mu   sync.Mutex
}

// New returns a Cache at AEGIS_CACHE_DIR/decisions.json (default
// ~/.aegis/cache/decisions.json). Missing parent directories are
// created lazily on the first Put.
func New() *Cache {
	dir := os.Getenv("AEGIS_CACHE_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".aegis", "cache")
	}
	return &Cache{path: filepath.Join(dir, "decisions.json")}
}

// NewAt builds a cache at an explicit path. For tests.
func NewAt(path string) *Cache {
	return &Cache{path: path}
}

// Path returns the on-disk file path the cache uses.
func (c *Cache) Path() string { return c.path }

// Get returns a cached decision if one exists and has not expired.
// Missing-file, decode-error, and expired entries all return false.
// Get treats decode errors as a miss; the next Put will overwrite.
func (c *Cache) Get(key string) (*api.Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := c.load()
	if err != nil {
		return nil, false
	}
	e, ok := data.Entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.ExpiresAt) {
		return nil, false
	}
	return e.Decision, true
}

// Put writes a decision to the cache. ttl <= 0 falls back to DefaultTTL.
func (c *Cache) Put(key string, d *api.Decision, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := c.load()
	if err != nil {
		// If load failed because the file is corrupt, start fresh —
		// a usable cache beats a broken one.
		data = &fileSchema{Entries: map[string]Entry{}}
	}
	data.Entries[key] = Entry{
		Decision:  d,
		ExpiresAt: time.Now().Add(ttl),
	}
	return c.save(data)
}

// Clear deletes the cache file. Missing file is not an error.
func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// List returns all entries sorted by key. Used by `aegis cache list`.
type Listing struct {
	Key       string
	Decision  *api.Decision
	ExpiresAt time.Time
}

func (c *Cache) List() ([]Listing, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := c.load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]Listing, 0, len(data.Entries))
	for k, e := range data.Entries {
		out = append(out, Listing{Key: k, Decision: e.Decision, ExpiresAt: e.ExpiresAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Key builds the canonical cache key for a (ecosystem, name, version).
func Key(ecosystem, name, version string) string {
	return ecosystem + "/" + name + "@" + version
}

// load reads the file. Missing file returns empty schema, NOT error,
// so first-write-wins works without a separate "exists?" probe.
func (c *Cache) load() (*fileSchema, error) {
	b, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &fileSchema{Entries: map[string]Entry{}}, nil
		}
		return nil, err
	}
	var data fileSchema
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("cache decode: %w", err)
	}
	if data.Entries == nil {
		data.Entries = map[string]Entry{}
	}
	return &data, nil
}

// save writes via temp+rename to be atomic on POSIX.
func (c *Cache) save(data *fileSchema) error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".decisions.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, c.path)
}
