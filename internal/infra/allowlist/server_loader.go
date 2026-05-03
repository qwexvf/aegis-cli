package allowlist

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// ServerCacheFileName is the name of the on-disk cache for the
// server-fetched allowlist. Lives under the user dir alongside the
// per-user allowlist.yaml so a single AEGIS_CONFIG_DIR contains
// everything.
const ServerCacheFileName = "cache/org-allowlist.yaml"

// DefaultServerTTL is how long the cached YAML is considered fresh.
// Server reload via `aegis allowlist sync` ignores TTL and always
// re-fetches. The 1h default keeps `aegis bun add ...` from hitting
// the network on every install while still picking up new admin rules
// within an hour.
const DefaultServerTTL = time.Hour

// AllowlistFetcher is the network-side interface the loader uses to
// reach the API. Mirrors usecase.DecisionChecker shape (small surface,
// easy to mock). Returns the raw YAML body — server is the source of
// truth for the schema.
type AllowlistFetcher interface {
	FetchAllowlist(ctx context.Context) ([]byte, error)
}

// ServerLoader manages the cached, server-fetched allowlist overlay.
// Wraps a Loader (which owns the user-dir path resolution) and an
// AllowlistFetcher (the API client). Construct via NewServerLoader.
type ServerLoader struct {
	user    *Loader          // shares user-dir resolution + AEGIS_CONFIG_DIR fallback
	fetcher AllowlistFetcher // nil → cache-only mode (no Sync possible)
	ttl     time.Duration
}

// NewServerLoader returns a ServerLoader rooted at the same user dir
// as the given Loader. fetcher may be nil — then Load reads the cache
// only (and Sync errors). Tests pass nil + pre-write a fixture cache
// file.
func NewServerLoader(user *Loader, fetcher AllowlistFetcher) *ServerLoader {
	return &ServerLoader{user: user, fetcher: fetcher, ttl: DefaultServerTTL}
}

// CachePath returns the absolute path to the cached YAML file.
func (s *ServerLoader) CachePath() string {
	return filepath.Join(s.user.userDir, ServerCacheFileName)
}

// Load reads the cached server allowlist and returns the parsed
// rules with Source="server". Missing cache file → empty result, nil
// error (the server overlay is opt-in; absence is a valid state).
//
// We deliberately do NOT auto-fetch here. Allowing the install gate
// to make network calls on every `bun add` is a UX disaster (slow +
// works-offline-broken). The user runs `aegis allowlist sync`
// explicitly; future reads use the cache.
func (s *ServerLoader) Load() ([]domain.AllowRule, error) {
	body, err := os.ReadFile(s.CachePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	rules, err := decodeFile(body, "server")
	if err != nil {
		// A corrupt cache shouldn't block the install. Return an empty
		// rule set + a context-tagged error; the loader callers log
		// the error and continue with the other layers.
		return nil, fmt.Errorf("server allowlist cache corrupt (run `aegis allowlist sync`): %w", err)
	}
	return rules, nil
}

// CacheAge returns how long ago the cache was written. Returns
// (0, false) when the cache does not exist.
func (s *ServerLoader) CacheAge() (time.Duration, bool) {
	info, err := os.Stat(s.CachePath())
	if err != nil {
		return 0, false
	}
	return time.Since(info.ModTime()), true
}

// IsFresh reports whether the cache exists AND is younger than TTL.
// Used by `aegis allowlist sync --if-stale` to skip the network when
// the cache is recent.
func (s *ServerLoader) IsFresh() bool {
	age, ok := s.CacheAge()
	return ok && age < s.ttl
}

// Sync fetches the latest YAML from the server and writes it to the
// cache atomically (temp file + rename). Returns the rule count for
// presenter output. ctx controls the network call.
//
// Errors fall into three buckets:
//   - "no fetcher configured" → composition root didn't wire the API
//     client; usually means the user lacks AEGIS_API_KEY.
//   - network/HTTP errors → propagated as-is so the user sees the
//     real cause (401, connection refused, etc.).
//   - parse errors → the server returned invalid YAML; we refuse to
//     overwrite a previously-good cache with garbage.
func (s *ServerLoader) Sync(ctx context.Context) (int, error) {
	if s.fetcher == nil {
		return 0, errors.New("no fetcher configured (set AEGIS_API_KEY and AEGIS_API_URL)")
	}
	body, err := s.fetcher.FetchAllowlist(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetch: %w", err)
	}
	// Validate before persisting. If the server is wrong (bad schema
	// version, unknown capability) the user keeps their previous,
	// known-good cache instead of getting a silent "0 rules" overlay.
	rules, err := decodeFile(body, "server")
	if err != nil {
		return 0, fmt.Errorf("server returned invalid YAML: %w", err)
	}
	if err := s.writeCache(body); err != nil {
		return 0, fmt.Errorf("persist cache: %w", err)
	}
	return len(rules), nil
}

// writeCache persists body to disk via temp-file + rename. Creates
// the parent dir 0700 if missing — the cache may contain ecosystem
// usage hints (which packages an org uses) so we keep it user-only.
func (s *ServerLoader) writeCache(body []byte) error {
	path := s.CachePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".org-allowlist.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
