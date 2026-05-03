// Package diskcache satisfies usecase.DecisionCache by persisting
// domain.Decision values to a single JSON file. Concurrent processes
// rely on atomic temp+rename for last-write-wins semantics.
package diskcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/atomicwrite"
	"github.com/qwexvf/aegis-cli/internal/infra/flock"
)

// DefaultTTL is how long cached decisions are considered fresh when no
// explicit TTL is configured. Override via AEGIS_CACHE_TTL.
const DefaultTTL = time.Hour

// Cache is a JSON-file decision cache.
type Cache struct {
	path string
	ttl  time.Duration
	mu   sync.Mutex
}

// New returns a Cache at AEGIS_CACHE_DIR/decisions.json (default
// ~/.aegis/cache/decisions.json). TTL comes from AEGIS_CACHE_TTL or
// DefaultTTL.
func New() *Cache {
	dir := os.Getenv("AEGIS_CACHE_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".aegis", "cache")
	}
	ttl := DefaultTTL
	if v := os.Getenv("AEGIS_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			ttl = d
		}
	}
	return &Cache{path: filepath.Join(dir, "decisions.json"), ttl: ttl}
}

// NewAt builds a cache at an explicit path. For tests.
func NewAt(path string, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Cache{path: path, ttl: ttl}
}

// Path returns the on-disk file path the cache uses.
func (c *Cache) Path() string { return c.path }

// Get implements usecase.DecisionCache.
func (c *Cache) Get(key string) (domain.Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := c.load()
	if err != nil {
		return domain.Decision{}, false
	}
	e, ok := data.Entries[key]
	if !ok {
		return domain.Decision{}, false
	}
	if time.Now().After(e.ExpiresAt) {
		return domain.Decision{}, false
	}
	return e.Decision.toDomain(), true
}

// Put implements usecase.DecisionCache.
//
// Concurrency: a coarse cross-process lock around (load, modify,
// save) prevents the lost-update race where two parallel `aegis`
// invocations both read state {a}, each adds a different key, and
// the later writer's atomic rename clobbers the other's addition.
func (c *Cache) Put(key string, d domain.Decision) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	unlock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlock()

	data, err := c.load()
	if err != nil {
		// Corrupt file: start fresh. A usable cache beats a broken one.
		data = &fileSchema{Entries: map[string]entry{}}
	}
	data.Entries[key] = entry{
		Decision:  fromDomain(d),
		ExpiresAt: time.Now().Add(c.ttl),
	}
	return c.save(data)
}

// lock takes an exclusive cross-process lock on a sentinel file
// alongside decisions.json. We don't lock decisions.json itself
// because it's renamed-into-place by save; flocks on the old inode
// stop coordinating once the rename happens.
func (c *Cache) lock() (func(), error) {
	lockPath := c.path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cache lockfile: %w", err)
	}
	unlock, err := flock.LockExclusive(f)
	if err != nil {
		_ = f.Close() // already failing on flock; nothing to recover
		return nil, fmt.Errorf("cache flock: %w", err)
	}
	return func() {
		unlock()
		_ = f.Close() // unlock(): kernel-level fcntl release is the only thing that matters
	}, nil
}

// Clear deletes the cache file. Missing-file is not an error.
func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Listing is one row in the human-readable List output.
type Listing struct {
	Key       string
	Kind      domain.DecisionKind
	Severity  domain.Severity
	ExpiresAt time.Time
}

// List returns all entries sorted by key. Used by `aegis cache list`.
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
		out = append(out, Listing{
			Key:       k,
			Kind:      domain.DecisionKind(e.Decision.Kind),
			Severity:  domain.Severity(e.Decision.Severity),
			ExpiresAt: e.ExpiresAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// --- on-disk DTOs -----------------------------------------------------

type fileSchema struct {
	Entries map[string]entry `json:"entries"`
}

type entry struct {
	Decision  decisionDTO `json:"decision"`
	ExpiresAt time.Time   `json:"expires_at"`
}

type decisionDTO struct {
	Kind       string   `json:"kind"`
	Severity   string   `json:"severity"`
	Reasons    []reason `json:"reasons,omitempty"`
	AdvisoryID string   `json:"advisory_id,omitempty"`
	Date       string   `json:"date,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	References []string `json:"references,omitempty"`
}

type reason struct {
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

func fromDomain(d domain.Decision) decisionDTO {
	out := decisionDTO{Kind: string(d.Kind), Severity: string(d.Severity)}
	if len(d.Reasons) > 0 {
		out.Reasons = make([]reason, len(d.Reasons))
		for i, r := range d.Reasons {
			out.Reasons[i] = reason{Category: r.Category, Detail: r.Detail}
		}
	}
	if d.Incident != nil {
		out.AdvisoryID = d.Incident.AdvisoryID
		out.Date = d.Incident.Date
		out.Summary = d.Incident.Summary
		out.References = d.Incident.References
	}
	return out
}

func (d decisionDTO) toDomain() domain.Decision {
	out := domain.Decision{Kind: domain.DecisionKind(d.Kind), Severity: domain.Severity(d.Severity)}
	if len(d.Reasons) > 0 {
		out.Reasons = make([]domain.Reason, len(d.Reasons))
		for i, r := range d.Reasons {
			out.Reasons[i] = domain.Reason{Category: r.Category, Detail: r.Detail}
		}
	}
	if d.AdvisoryID != "" || d.Date != "" || d.Summary != "" || len(d.References) > 0 {
		out.Incident = &domain.Incident{
			AdvisoryID: d.AdvisoryID,
			Date:       d.Date,
			Summary:    d.Summary,
			References: d.References,
		}
	}
	return out
}

// --- io ---------------------------------------------------------------

func (c *Cache) load() (*fileSchema, error) {
	b, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &fileSchema{Entries: map[string]entry{}}, nil
		}
		return nil, err
	}
	var data fileSchema
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("cache decode: %w", err)
	}
	if data.Entries == nil {
		data.Entries = map[string]entry{}
	}
	return &data, nil
}

func (c *Cache) save(data *fileSchema) error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("cache encode: %w", err)
	}
	return atomicwrite.WriteFile(c.path, b, 0o600)
}
