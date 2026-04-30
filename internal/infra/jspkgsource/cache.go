package jspkgsource

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/qwexvf/aegis/services/cli/internal/infra/atomicwrite"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

// loadCached returns a previously-extracted package source from
// f.cacheDir if present. Atomicity: a sentinel file ".ok" is written
// last; we treat its absence as "incomplete cache, ignore".
func (f *Fetcher) loadCached(name, version string) (usecase.PackageSource, bool, error) {
	dir := f.cachePath(name, version)
	if _, err := os.Stat(filepath.Join(dir, ".ok")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return usecase.PackageSource{}, false, nil
		}
		return usecase.PackageSource{}, false, err
	}

	src := usecase.PackageSource{Files: map[string][]byte{}}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if base == ".ok" || base == ".tarball-sha256" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		// Cross-OS safety: use forward slashes inside PackageSource.
		rel = filepath.ToSlash(rel)
		src.Files[rel] = body
		if rel == "package.json" {
			src.Manifest = body
		}
		return nil
	})
	if err != nil {
		return usecase.PackageSource{}, false, err
	}
	// Best-effort: a side file holds the tarball sha so warm cache hits
	// still carry provenance. Old caches predate this and simply lack it.
	if sum, err := os.ReadFile(filepath.Join(dir, ".tarball-sha256")); err == nil {
		src.TarballSha256 = strings.TrimSpace(string(sum))
	}
	return src, true, nil
}

// saveCache writes the extracted source to disk. Best-effort: any I/O
// failure leaves the cache in an inconsistent state, signaled by the
// absence of the .ok sentinel.
func (f *Fetcher) saveCache(name, version string, src usecase.PackageSource) error {
	dir := f.cachePath(name, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for path, body := range src.Files {
		if !isSafeRel(path) {
			// defense in depth: refuse path traversal in tarball entries.
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(path))
		// Belt and suspenders: confirm Clean+Join didn't escape `dir`.
		if rel, err := filepath.Rel(dir, full); err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := atomicwrite.WriteFile(full, body, 0o644); err != nil {
			return err
		}
	}
	if src.TarballSha256 != "" {
		_ = atomicwrite.WriteFile(filepath.Join(dir, ".tarball-sha256"), []byte(src.TarballSha256), 0o644)
	}
	// Sentinel last so the cache only "appears valid" if writes succeeded.
	return atomicwrite.WriteFile(filepath.Join(dir, ".ok"), []byte(""), 0o644)
}

// isSafeRel rejects any path that, after cleaning, escapes the
// containing directory. We rely on filepath.IsLocal (Go 1.20+) which
// rejects absolute paths, "..", reserved Windows names, and trailing
// dots in segments. Tarball entries arriving as `foo/../bar` survive
// the simple `strings.Contains("..")` test in the legacy code; IsLocal
// catches them properly.
func isSafeRel(p string) bool {
	return filepath.IsLocal(filepath.FromSlash(p))
}

// cachePath returns <cacheDir>/npm/<safe-name>/<version>. Scoped names
// have their slash kept as a directory separator so the layout is
// browseable.
func (f *Fetcher) cachePath(name, version string) string {
	return filepath.Join(f.cacheDir, "npm", filepath.FromSlash(name), version)
}
