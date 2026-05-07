package diskcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/qwexvf/aegis-cli/internal/infra/atomicwrite"
)

// UsageCache stores the per-file output of depusage's import +
// used-symbols pass keyed by content hash. AnalyzeUsage hits this
// cache first; on miss it parses the file and writes the result back.
//
// Why content-hashed: re-enrich after a one-file edit doesn't have to
// rewalk every other file in the project. Tree-sitter parsing is fast
// in absolute terms but adds up across hundreds of files; the cache
// keeps the file walk near-IO-bound on warm runs.
//
// Layout: <root>/usage/<lang>/<sha256[:2]>/<sha256[2:]>.json — same
// shape as the fingerprint cache so `cache clear` can wipe it the
// same way.
type UsageCache struct {
	dir string
}

// UsageEntry is the on-disk shape: a flat list of imports + a
// flat list of used symbols, both keyed by raw module string. We
// denormalize the depusage Result here rather than re-export it,
// because the on-disk form is allowed to drift from the in-memory
// API across depusage versions.
type UsageEntry struct {
	// Each entry: raw module name → DepKey (or "" for relative / stdlib).
	Imports map[string]string `json:"imports,omitempty"`
	// Each entry: depKey → sorted set of bound names referenced.
	Symbols map[string][]string `json:"symbols,omitempty"`
}

// NewUsageCache returns a cache rooted at AEGIS_CACHE_DIR/usage
// (default ~/.aegis/cache/usage).
func NewUsageCache() *UsageCache {
	dir := os.Getenv("AEGIS_CACHE_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".aegis", "cache")
	}
	return &UsageCache{dir: filepath.Join(dir, "usage")}
}

// NewUsageCacheAt builds a cache at an explicit dir. Tests.
func NewUsageCacheAt(dir string) *UsageCache {
	return &UsageCache{dir: dir}
}

// FileHash returns the sha256 hex of body — the canonical cache key.
// Lives here (rather than at the call site) so the path layout stays
// internal to this package.
func FileHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Get returns the cached entry for the given (lang, sha) pair, or
// false on miss. Corrupt cache files are silently treated as miss —
// the caller will overwrite on Put.
func (c *UsageCache) Get(lang, sha string) (UsageEntry, bool) {
	path := c.path(lang, sha)
	body, err := os.ReadFile(path)
	if err != nil {
		return UsageEntry{}, false
	}
	var e UsageEntry
	if err := json.Unmarshal(body, &e); err != nil {
		return UsageEntry{}, false
	}
	return e, true
}

// Put writes the entry. Best-effort: a write failure is non-fatal
// (we'll re-parse on the next run).
func (c *UsageCache) Put(lang, sha string, e UsageEntry) error {
	path := c.path(lang, sha)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("usage encode: %w", err)
	}
	return atomicwrite.WriteFile(path, body, 0o600)
}

// Clear removes the entire usage cache. Missing-dir is fine.
func (c *UsageCache) Clear() error {
	if err := os.RemoveAll(c.dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Dir returns the on-disk root.
func (c *UsageCache) Dir() string { return c.dir }

// path layout: <dir>/<lang>/<sha[:2]>/<sha[2:]>.json
//
// Two-level fanout keeps any single directory bounded for projects
// with very large file counts. Matches the diskcache.advisories
// layout for consistency.
func (c *UsageCache) path(lang, sha string) string {
	prefix := sha
	rest := ""
	if len(sha) > 2 {
		prefix = sha[:2]
		rest = sha[2:]
	}
	return filepath.Join(c.dir, lang, prefix, rest+".json")
}
