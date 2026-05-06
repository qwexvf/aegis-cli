package usecase

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// readLocalPackageSource walks a directory and builds a PackageSource
// shaped like what the registry fetcher would have produced. Used by
// `aegis analyze --local <dir>` for fixture-based testing and for
// analysing a tree before publish.
//
// The manifest is the canonical per-ecosystem file at the directory
// root: package.json (npm), pyproject.toml or setup.py (pypi),
// Cargo.toml (crates), <name>.gemspec (rubygems). When no manifest is
// found we leave Manifest empty — the install-hook detector simply
// won't fire, the AST scanner still runs.
//
// Files map keys are paths relative to root, using forward slashes
// (matching the registry fetcher's convention).
//
// Symlinks, .git, and node_modules / vendor / __pycache__ trees are
// skipped — they're never the package's published source and walking
// them blows up scan time on real-world dev trees.
func readLocalPackageSource(root string, eco domain.Ecosystem) (PackageSource, error) {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return PackageSource{}, fmt.Errorf("stat %s: %w", root, err)
	}
	if !info.IsDir() {
		return PackageSource{}, fmt.Errorf("%s is not a directory", root)
	}

	files := map[string][]byte{}
	const maxFileBytes = 4 * 1024 * 1024 // 4MB per file — plenty for source

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		base := d.Name()
		if d.IsDir() {
			if isSkippedDir(base) {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip symlinks — never source, can loop forever.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
		if len(body) > maxFileBytes {
			body = body[:maxFileBytes]
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Always forward-slash for parity with tarball-extracted paths.
		files[filepath.ToSlash(rel)] = body
		return nil
	})
	if walkErr != nil {
		return PackageSource{}, walkErr
	}

	manifest := pickManifest(eco, files)

	return PackageSource{
		Files:    files,
		Manifest: manifest,
		// TarballSha256 is intentionally empty — there's no tarball.
	}, nil
}

func isSkippedDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn",
		"node_modules", "vendor",
		"__pycache__", ".venv", "venv", ".tox",
		"target", "dist", "build",
		".idea", ".vscode":
		return true
	}
	return false
}

// pickManifest returns the canonical manifest bytes for the ecosystem,
// or nil when no manifest is present at the root. For RubyGems we
// match any *.gemspec at the root (gemspec filenames are arbitrary).
func pickManifest(eco domain.Ecosystem, files map[string][]byte) []byte {
	candidates := manifestCandidates(eco)
	for _, name := range candidates {
		if body, ok := files[name]; ok {
			return body
		}
	}
	if eco == domain.EcoRubyGems {
		for path, body := range files {
			if !strings.Contains(path, "/") && strings.HasSuffix(path, ".gemspec") {
				return body
			}
		}
	}
	return nil
}

func manifestCandidates(eco domain.Ecosystem) []string {
	switch eco {
	case domain.EcoNpm:
		return []string{"package.json"}
	case domain.EcoPyPI:
		return []string{"pyproject.toml", "setup.py", "setup.cfg"}
	case domain.EcoCrates:
		return []string{"Cargo.toml"}
	case domain.EcoRubyGems:
		// Caller falls back to *.gemspec scan above.
		return nil
	}
	return nil
}
