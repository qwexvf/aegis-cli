//go:build !nojsscan

// Package usecase: usage.go contains AnalyzeUsage, the project-source
// import walk that classifies each Dependency as Used / Unused /
// Unknown.
//
// This file is the full implementation. The `nojsscan` build (see
// usage_stub.go) ships no-op stubs so binaries without the AST scanner
// don't drag in depusage's cgo tree-sitter chain.
//
// Why a separate file (and not inside snapshot.go's Enrich): the import
// scan is independent of the OSV-lookup + AST-fingerprint phases. Wiring
// it as its own pass lets us run it on demand (e.g. `aegis snapshot
// analyze-usage`) and lets the existing Enrich worker pool stay focused
// on the per-package fetch+scan. Enrich can call AnalyzeUsage once at
// the end without intertwining responsibilities.
package usecase

import (
	"context"
	"slices"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan/depusagebridge"
	"github.com/qwexvf/aegis-cli/internal/infra/diskcache"
	"github.com/qwexvf/depusage"
)

// AnalyzeUsage walks projectDir, extracts the import set from every
// supported source file, and marks each entry of snap.Deps with a
// Reachability classification.
//
// Deps whose ecosystem isn't covered by any walked source language
// retain ReachabilityUnknown — same as a fresh load. This keeps
// scoring conservative for polyglot projects and unsupported langs.
//
// Errors propagate only on context cancellation. File read / parse
// errors are absorbed (a single bad file shouldn't taint the project's
// reachability verdict).
func AnalyzeUsage(ctx context.Context, projectDir string, snap *domain.Snapshot) error {
	return AnalyzeUsageWithCache(ctx, projectDir, snap, diskcache.NewUsageCache())
}

// AnalyzeUsageWithCache is the cache-injectable form. The default
// AnalyzeUsage builds a cache rooted at AEGIS_CACHE_DIR/usage; tests
// pass an explicit temp-dir cache. Pass nil to disable caching.
func AnalyzeUsageWithCache(ctx context.Context, projectDir string, snap *domain.Snapshot, cache *diskcache.UsageCache) error {
	if snap == nil || projectDir == "" {
		return nil
	}

	// usedKeys[ecosystem][depKey] = true when at least one source file
	// in the matching language imports that key.
	usedKeys := map[domain.Ecosystem]map[string]bool{}

	// usedSymbols[ecosystem][depKey] is the set of bound names the
	// user's code referenced from that dep. Empty for ecosystems
	// whose languages don't support the symbol pass (Rust, Ruby, C#).
	usedSymbols := map[domain.Ecosystem]map[string]map[string]struct{}{}

	// scannedEcos tracks which ecosystems we actually walked source for.
	// A dep in an ecosystem we never observed source for stays
	// ReachabilityUnknown — anything else flips to Used / Unused.
	scannedEcos := map[domain.Ecosystem]bool{}

	walkErr := depusagebridge.WalkProject(ctx, projectDir, func(rel string, lang depusage.Language, body []byte) {
		eco, ok := depusagebridge.EcosystemForLanguage(lang)
		if !ok {
			return
		}
		scannedEcos[eco] = true

		entry, hit := lookupOrParse(cache, lang, body)

		bucket, ok := usedKeys[eco]
		if !ok {
			bucket = map[string]bool{}
			usedKeys[eco] = bucket
		}
		for _, depKey := range entry.Imports {
			if depKey == "" {
				continue
			}
			bucket[depKey] = true
		}
		ecoSyms, ok := usedSymbols[eco]
		if !ok {
			ecoSyms = map[string]map[string]struct{}{}
			usedSymbols[eco] = ecoSyms
		}
		for depKey, syms := range entry.Symbols {
			if depKey == "" {
				continue
			}
			set, ok := ecoSyms[depKey]
			if !ok {
				set = map[string]struct{}{}
				ecoSyms[depKey] = set
			}
			for _, s := range syms {
				set[s] = struct{}{}
			}
		}
		// On miss, write the parsed entry back. Hits already returned
		// the cached value above; we only Put on parse.
		if !hit && cache != nil {
			_ = cache.Put(string(lang), diskcache.FileHash(body), entry)
		}
	})
	if walkErr != nil {
		return walkErr
	}

	for i := range snap.Deps {
		d := &snap.Deps[i]
		if !scannedEcos[d.Ecosystem] {
			// No source observed for this ecosystem — keep Unknown.
			continue
		}
		if isDepUsed(d.Ecosystem, d.Name, usedKeys[d.Ecosystem]) {
			d.Reachability = domain.ReachabilityUsed
			d.UsedSymbols = collectSymbolsFor(d.Ecosystem, d.Name, usedSymbols[d.Ecosystem])
		} else {
			d.Reachability = domain.ReachabilityUnused
			d.UsedSymbols = nil
		}
	}
	return nil
}

// collectSymbolsFor returns the sorted set of symbols observed for
// depName, including symbols recorded under sub-paths when the
// ecosystem allows prefix matches (Go).
func collectSymbolsFor(eco domain.Ecosystem, depName string, syms map[string]map[string]struct{}) []string {
	if len(syms) == 0 {
		return nil
	}
	merged := map[string]struct{}{}
	for k, set := range syms {
		if k == depName || (eco == domain.EcoGo && strings.HasPrefix(k, depName+"/")) {
			for s := range set {
				merged[s] = struct{}{}
			}
		}
	}
	if len(merged) == 0 {
		return nil
	}
	out := make([]string, 0, len(merged))
	for s := range merged {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// lookupOrParse returns the per-file usage entry, hitting the cache
// when possible and falling back to a fresh depusage.Extract. Returns
// (entry, hit) — callers Put on miss to populate the cache.
//
// Cache key is the file's sha256: a one-character edit changes the
// hash, so a single touched file invalidates exactly its own entry.
// Unrelated files keep their cached results across runs.
func lookupOrParse(cache *diskcache.UsageCache, lang depusage.Language, body []byte) (diskcache.UsageEntry, bool) {
	if cache != nil {
		if cached, ok := cache.Get(string(lang), diskcache.FileHash(body)); ok {
			return cached, true
		}
	}
	res, err := depusage.Extract(lang, body, depusage.Options{
		IncludeImports: true,
		IncludeSymbols: true,
	})
	if err != nil {
		return diskcache.UsageEntry{}, false
	}
	entry := diskcache.UsageEntry{
		Imports: map[string]string{},
		Symbols: map[string][]string{},
	}
	for _, imp := range res.Imports {
		entry.Imports[imp.Module] = imp.DepKey
	}
	// Aggregate symbols per depKey, dedup, sort for determinism.
	tmp := map[string]map[string]struct{}{}
	for _, u := range res.UsedSymbols {
		if u.DepKey == "" || u.Symbol == "" {
			continue
		}
		set, ok := tmp[u.DepKey]
		if !ok {
			set = map[string]struct{}{}
			tmp[u.DepKey] = set
		}
		set[u.Symbol] = struct{}{}
	}
	for k, set := range tmp {
		out := make([]string, 0, len(set))
		for s := range set {
			out = append(out, s)
		}
		slices.Sort(out)
		entry.Symbols[k] = out
	}
	return entry, false
}

// isDepUsed checks whether any imported key resolves to depName, with
// per-ecosystem matching rules. Go imports are package paths under a
// module root (e.g. `github.com/x/y/bindings/go`); the lockfile key is
// the module root (`github.com/x/y`). Other ecosystems already
// normalize to the lockfile key on the depusage side, so exact match
// is correct for them.
func isDepUsed(eco domain.Ecosystem, depName string, used map[string]bool) bool {
	if len(used) == 0 {
		return false
	}
	if used[depName] {
		return true
	}
	if eco == domain.EcoGo {
		prefix := depName + "/"
		for k := range used {
			if len(k) > len(prefix) && k[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}
