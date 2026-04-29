package jspkgsource

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

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
		if base == ".ok" {
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
		if strings.Contains(path, "..") {
			// defense in depth: refuse path traversal in tarball entries.
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, body, 0o644); err != nil {
			return err
		}
	}
	// Sentinel last so the cache only "appears valid" if writes succeeded.
	return os.WriteFile(filepath.Join(dir, ".ok"), []byte(""), 0o644)
}

// cachePath returns <cacheDir>/npm/<safe-name>/<version>. Scoped names
// have their slash kept as a directory separator so the layout is
// browseable.
func (f *Fetcher) cachePath(name, version string) string {
	return filepath.Join(f.cacheDir, "npm", filepath.FromSlash(name), version)
}
