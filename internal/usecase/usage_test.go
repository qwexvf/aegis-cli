//go:build !nojsscan

package usecase

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/diskcache"
)

func TestAnalyzeUsage_MarksReachableUnreachable(t *testing.T) {
	root := t.TempDir()
	// Project source: imports lodash but NOT axios.
	mustWrite(t, filepath.Join(root, "src", "main.js"), `
import _ from 'lodash';
import { z } from 'zod';
const fs = require('fs');
`)

	snap := &domain.Snapshot{
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21"},
			{Ecosystem: domain.EcoNpm, Name: "zod", Version: "3.22.0"},
			{Ecosystem: domain.EcoNpm, Name: "axios", Version: "1.6.0"},
			// Different ecosystem — should stay unknown since no python
			// source was scanned.
			{Ecosystem: domain.EcoPyPI, Name: "requests", Version: "2.31.0"},
		},
	}

	if err := AnalyzeUsage(context.Background(), root, snap); err != nil {
		t.Fatal(err)
	}

	got := map[string]domain.Reachability{}
	for _, d := range snap.Deps {
		got[string(d.Ecosystem)+":"+d.Name] = d.Reachability
	}
	want := map[string]domain.Reachability{
		"npm:lodash":    domain.ReachabilityUsed,
		"npm:zod":       domain.ReachabilityUsed,
		"npm:axios":     domain.ReachabilityUnused,
		"pypi:requests": domain.ReachabilityUnknown, // no .py source observed
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("Reachability[%s] = %v, want %v", k, got[k], w)
		}
	}
}

func TestAnalyzeUsage_NoSourceMeansAllUnknown(t *testing.T) {
	root := t.TempDir()
	// No source files at all.
	snap := &domain.Snapshot{
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash"},
		},
	}
	if err := AnalyzeUsage(context.Background(), root, snap); err != nil {
		t.Fatal(err)
	}
	if snap.Deps[0].Reachability != domain.ReachabilityUnknown {
		t.Errorf("want Unknown when no source observed, got %v", snap.Deps[0].Reachability)
	}
}

func TestAnalyzeUsage_GoModuleRootPrefixMatch(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), `package main
import "github.com/spf13/cobra"
import "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"
func main() {}
`)

	snap := &domain.Snapshot{
		Deps: []domain.Dependency{
			// Lockfile key == import path: exact match.
			{Ecosystem: domain.EcoGo, Name: "github.com/spf13/cobra", Version: "v1.0.0"},
			// Lockfile key is the MODULE ROOT; user imports a sub-package.
			{Ecosystem: domain.EcoGo, Name: "github.com/tree-sitter/tree-sitter-c-sharp", Version: "v0.23.5"},
			// Truly unused.
			{Ecosystem: domain.EcoGo, Name: "github.com/sirupsen/logrus", Version: "v1.0.0"},
		},
	}
	if err := AnalyzeUsage(context.Background(), root, snap); err != nil {
		t.Fatal(err)
	}
	if snap.Deps[0].Reachability != domain.ReachabilityUsed {
		t.Errorf("cobra: want Used, got %v", snap.Deps[0].Reachability)
	}
	if snap.Deps[1].Reachability != domain.ReachabilityUsed {
		t.Errorf("c-sharp module root: want Used (prefix match), got %v", snap.Deps[1].Reachability)
	}
	if snap.Deps[2].Reachability != domain.ReachabilityUnused {
		t.Errorf("logrus: want Unused, got %v", snap.Deps[2].Reachability)
	}
}

func TestAnalyzeUsage_PopulatesUsedSymbolsForUsedDeps(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "src", "main.js"), `
import { merge, debounce } from 'lodash';
import _ from 'lodash';
merge({}, {});
debounce(fn, 200);
_.template('hi');
`)

	snap := &domain.Snapshot{
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21"},
			{Ecosystem: domain.EcoNpm, Name: "axios", Version: "1.6.0"},
		},
	}
	if err := AnalyzeUsage(context.Background(), root, snap); err != nil {
		t.Fatal(err)
	}

	// lodash is Used; UsedSymbols should be the merged sorted set.
	if snap.Deps[0].Reachability != domain.ReachabilityUsed {
		t.Fatalf("lodash should be Used, got %v", snap.Deps[0].Reachability)
	}
	want := []string{"debounce", "merge", "template"}
	if len(snap.Deps[0].UsedSymbols) != len(want) {
		t.Fatalf("UsedSymbols len = %d, want %d (%v)",
			len(snap.Deps[0].UsedSymbols), len(want), snap.Deps[0].UsedSymbols)
	}
	for i, s := range want {
		if snap.Deps[0].UsedSymbols[i] != s {
			t.Errorf("UsedSymbols[%d] = %q, want %q", i, snap.Deps[0].UsedSymbols[i], s)
		}
	}
	// axios is Unused; UsedSymbols must be cleared.
	if snap.Deps[1].Reachability != domain.ReachabilityUnused {
		t.Errorf("axios should be Unused, got %v", snap.Deps[1].Reachability)
	}
	if snap.Deps[1].UsedSymbols != nil {
		t.Errorf("Unused dep should have nil UsedSymbols, got %v", snap.Deps[1].UsedSymbols)
	}
}

func TestAnalyzeUsage_CacheRoundTrip(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.js"), `import { merge } from 'lodash'; merge({}, {});`)
	cache := diskcache.NewUsageCacheAt(t.TempDir())

	snap := &domain.Snapshot{
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash"},
		},
	}
	// First run: populates cache.
	if err := AnalyzeUsageWithCache(context.Background(), root, snap, cache); err != nil {
		t.Fatal(err)
	}
	if snap.Deps[0].Reachability != domain.ReachabilityUsed {
		t.Fatalf("first run: lodash should be Used, got %v", snap.Deps[0].Reachability)
	}

	// Second run on a snapshot with cleared Reachability — must still
	// classify Used, this time via the cache.
	snap.Deps[0].Reachability = domain.ReachabilityUnknown
	snap.Deps[0].UsedSymbols = nil
	if err := AnalyzeUsageWithCache(context.Background(), root, snap, cache); err != nil {
		t.Fatal(err)
	}
	if snap.Deps[0].Reachability != domain.ReachabilityUsed {
		t.Fatalf("second run (cache hit): lodash should still be Used, got %v", snap.Deps[0].Reachability)
	}
	if len(snap.Deps[0].UsedSymbols) == 0 || snap.Deps[0].UsedSymbols[0] != "merge" {
		t.Errorf("UsedSymbols not restored from cache: %v", snap.Deps[0].UsedSymbols)
	}
}

func TestAnalyzeUsage_NilCacheStillWorks(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.js"), `import { merge } from 'lodash'; merge({}, {});`)
	snap := &domain.Snapshot{
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash"},
		},
	}
	if err := AnalyzeUsageWithCache(context.Background(), root, snap, nil); err != nil {
		t.Fatal(err)
	}
	if snap.Deps[0].Reachability != domain.ReachabilityUsed {
		t.Errorf("nil cache should still classify, got %v", snap.Deps[0].Reachability)
	}
}

func TestAnalyzeUsage_NilSnapshotIsNoop(t *testing.T) {
	if err := AnalyzeUsage(context.Background(), t.TempDir(), nil); err != nil {
		t.Errorf("nil snap should be noop, got err: %v", err)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
