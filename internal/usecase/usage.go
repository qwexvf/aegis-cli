// Package usecase: usage.go contains AnalyzeUsage, the project-source
// import walk that classifies each Dependency as Used / Unused /
// Unknown.
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

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan/depusagebridge"
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
	if snap == nil || projectDir == "" {
		return nil
	}

	// usedKeys[ecosystem][depKey] = true when at least one source file
	// in the matching language imports that key.
	usedKeys := map[domain.Ecosystem]map[string]bool{}

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

		res, err := depusage.Extract(lang, body, depusage.Options{IncludeImports: true})
		if err != nil {
			return
		}
		bucket, ok := usedKeys[eco]
		if !ok {
			bucket = map[string]bool{}
			usedKeys[eco] = bucket
		}
		for _, imp := range res.Imports {
			if imp.DepKey == "" {
				continue
			}
			bucket[imp.DepKey] = true
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
		if usedKeys[d.Ecosystem][d.Name] {
			d.Reachability = domain.ReachabilityUsed
		} else {
			d.Reachability = domain.ReachabilityUnused
		}
	}
	return nil
}
