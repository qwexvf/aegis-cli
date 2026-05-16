package heuristics

import (
	"slices"
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// largeJS returns exactly n bytes of inert JS content.
func largeJS(n int) []byte {
	const line = "var x = 1;\n" // 11 bytes
	repeats := n/len(line) + 1
	b := []byte(strings.Repeat(line, repeats))
	return b[:n]
}

func TestDetectUnlistedPayload(t *testing.T) {
	t.Run("tanstack-router-2026 — 2.3 MB router_init.js at root, not in files", func(t *testing.T) {
		manifest := []byte(`{
			"name": "@tanstack/react-router",
			"version": "1.169.5",
			"files": ["dist"]
		}`)
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"package.json":   manifest,
				"router_init.js": largeJS(600_000), // 600 KB > threshold
				"dist/index.js":  largeJS(1_000),
			},
			Manifest: manifest,
		}
		got := checkUnlistedPayload(NormalizedPackage{Files: src.Files, ManifestRaw: manifest})
		if !slices.Contains(got, domain.CapUnlistedLargeFile) {
			t.Fatalf("want CapUnlistedLargeFile, got %v", got)
		}
	})

	t.Run("large file in dist/ — whitelisted build output", func(t *testing.T) {
		manifest := []byte(`{"name": "pkg", "version": "1.0.0"}`)
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"package.json":   manifest,
				"dist/bundle.js": largeJS(1_000_000), // 1 MB but in dist/
			},
			Manifest: manifest,
		}
		got := checkUnlistedPayload(NormalizedPackage{Files: src.Files, ManifestRaw: manifest})
		if len(got) != 0 {
			t.Errorf("want 0 (dist/ is whitelisted), got %v", got)
		}
	})

	t.Run("large file declared in files field", func(t *testing.T) {
		manifest := []byte(`{
			"name": "pkg",
			"version": "1.0.0",
			"files": ["bundle.js"]
		}`)
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"package.json": manifest,
				"bundle.js":    largeJS(600_000),
			},
			Manifest: manifest,
		}
		got := checkUnlistedPayload(NormalizedPackage{Files: src.Files, ManifestRaw: manifest})
		if len(got) != 0 {
			t.Errorf("want 0 (file is declared in files field), got %v", got)
		}
	})

	t.Run("large non-code file — not flagged", func(t *testing.T) {
		manifest := []byte(`{"name": "pkg", "version": "1.0.0"}`)
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"package.json": manifest,
				"big.woff2":    largeJS(600_000), // font file, not a code file
			},
			Manifest: manifest,
		}
		got := checkUnlistedPayload(NormalizedPackage{Files: src.Files, ManifestRaw: manifest})
		if len(got) != 0 {
			t.Errorf("want 0 (non-code file), got %v", got)
		}
	})

	t.Run("small JS file at root — not flagged", func(t *testing.T) {
		manifest := []byte(`{"name": "pkg", "version": "1.0.0"}`)
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"package.json": manifest,
				"index.js":     largeJS(1_000), // 1 KB — fine
			},
			Manifest: manifest,
		}
		got := checkUnlistedPayload(NormalizedPackage{Files: src.Files, ManifestRaw: manifest})
		if len(got) != 0 {
			t.Errorf("want 0 (small file), got %v", got)
		}
	})

	t.Run("empty source — no signal", func(t *testing.T) {
		got := checkUnlistedPayload(NormalizedPackage{})
		if len(got) != 0 {
			t.Errorf("want 0 on empty input, got %v", got)
		}
	})
}
