package usecase

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
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
