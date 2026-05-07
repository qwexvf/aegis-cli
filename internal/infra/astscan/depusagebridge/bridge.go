// Package depusagebridge wires the depusage library into aegis: it
// maps file extensions to depusage.Language values, maps each
// depusage.Language to the domain.Ecosystem(s) whose dep keys live in
// that source, and walks a project directory yielding (lang, body)
// pairs while skipping dependency-install dirs.
//
// Lives outside internal/usecase because the file walk is concrete
// I/O and we want to keep usecase pure.
package depusagebridge

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/depusage"
)

// LanguageForExt returns the depusage.Language for a source-file
// extension (with leading dot), or false if the extension isn't
// covered.
func LanguageForExt(ext string) (depusage.Language, bool) {
	switch strings.ToLower(ext) {
	case ".js", ".cjs", ".mjs", ".jsx":
		return depusage.JavaScript, true
	case ".ts", ".tsx", ".mts", ".cts":
		return depusage.TypeScript, true
	case ".py", ".pyi":
		return depusage.Python, true
	case ".go":
		return depusage.Go, true
	case ".rs":
		return depusage.Rust, true
	case ".rb":
		return depusage.Ruby, true
	case ".java":
		return depusage.Java, true
	case ".php", ".phtml":
		return depusage.PHP, true
	case ".cs":
		return depusage.CSharp, true
	}
	return "", false
}

// EcosystemForLanguage maps a depusage.Language to the
// domain.Ecosystem whose lockfile keys are the right comparison
// target. JS/TS both map to npm.
func EcosystemForLanguage(l depusage.Language) (domain.Ecosystem, bool) {
	switch l {
	case depusage.JavaScript, depusage.TypeScript:
		return domain.EcoNpm, true
	case depusage.Python:
		return domain.EcoPyPI, true
	case depusage.Go:
		return domain.EcoGo, true
	case depusage.Rust:
		return domain.EcoCrates, true
	case depusage.Ruby:
		return domain.EcoRubyGems, true
	case depusage.Java:
		return domain.EcoMaven, true
	case depusage.PHP:
		return domain.EcoPackagist, true
	case depusage.CSharp:
		return domain.EcoNuGet, true
	}
	return "", false
}

// SkipDirs is the canonical list of directories whose contents are
// dependency installs / build outputs, not user source. Walking into
// them would mark transitive deps as "used" via *their* internal
// imports, defeating the whole reachability layer.
var SkipDirs = map[string]struct{}{
	"node_modules":     {}, // npm/yarn/pnpm/bun
	"bower_components": {},
	"vendor":           {}, // go, php, generic
	"target":           {}, // rust (cargo)
	"dist":             {}, // js bundlers
	"build":            {}, // generic
	"out":              {}, // generic
	".next":            {}, // next.js
	".nuxt":            {}, // nuxt
	".svelte-kit":      {}, // sveltekit
	".turbo":           {}, // turborepo cache
	".cache":           {},
	".git":             {},
	".hg":              {},
	".svn":             {},
	"__pycache__":      {}, // python
	".venv":            {}, // python virtualenv
	"venv":             {},
	".tox":             {}, // python
	".mypy_cache":      {},
	".pytest_cache":    {},
	".ruff_cache":      {},
	"site-packages":    {}, // python
	".bundle":          {}, // ruby
	".gradle":          {}, // gradle wrapper
	".idea":            {},
	".vscode":          {},
}

// FileLimit is the maximum file size depusage will parse. Large
// generated/minified files often parse for seconds; the heuristic
// drops them rather than wait.
const FileLimit = 2 * 1024 * 1024 // 2 MiB

// WalkProject walks projectDir, yielding (relPath, lang, body) for
// every supported source file. Returns when ctx is cancelled or the
// walk completes. Non-fatal errors (open/read failures) are skipped;
// only ctx cancellation propagates as an error.
func WalkProject(ctx context.Context, projectDir string, yield func(relPath string, lang depusage.Language, body []byte)) error {
	return filepath.WalkDir(projectDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission errors etc. — skip without aborting the walk.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if _, skip := SkipDirs[d.Name()]; skip {
				return fs.SkipDir
			}
			return nil
		}
		lang, ok := LanguageForExt(filepath.Ext(p))
		if !ok {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > FileLimit {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(projectDir, p)
		if err != nil {
			rel = p
		}
		yield(rel, lang, body)
		return nil
	})
}
