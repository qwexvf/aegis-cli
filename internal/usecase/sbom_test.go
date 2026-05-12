package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type stubVulnLookup struct {
	out map[string][]domain.Advisory
	err error
}

func (f *stubVulnLookup) Lookup(_ context.Context, qs []domain.AdvisoryQuery) (map[string][]domain.Advisory, error) {
	if f.err != nil {
		return nil, f.err
	}
	got := map[string][]domain.Advisory{}
	for _, q := range qs {
		if a, ok := f.out[q.Key()]; ok {
			got[q.Key()] = a
		}
	}
	return got, nil
}

func twoDepSnapshot() domain.Snapshot {
	return domain.Snapshot{
		SchemaVersion: 1,
		AegisVersion:  "test",
		Project:       "demo",
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21", Direct: true},
			{Ecosystem: domain.EcoNpm, Name: "@types/node", Version: "20.0.0", Direct: false},
		},
	}
}

func TestSbomGenerate_NoSnapshot(t *testing.T) {
	store := newFakeStore()
	uc := NewSbom(store, "test")
	var buf bytes.Buffer
	_, _, err := uc.Generate(context.Background(), "/proj", &buf, SbomOptions{})
	if err == nil || !strings.Contains(err.Error(), "no snapshot found") {
		t.Fatalf("expected no-snapshot error, got %v", err)
	}
}

func TestSbomGenerate_LockOnly(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = twoDepSnapshot()
	uc := NewSbom(store, "test")
	var buf bytes.Buffer
	comps, vulns, err := uc.Generate(context.Background(), "/proj", &buf, SbomOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if comps != 2 || vulns != 0 {
		t.Fatalf("counts: comps=%d vulns=%d", comps, vulns)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("bom is not valid JSON: %v", err)
	}
	if got["bomFormat"] != "CycloneDX" {
		t.Fatalf("bomFormat: %v", got["bomFormat"])
	}
	if got["specVersion"] != "1.5" {
		t.Fatalf("specVersion: %v", got["specVersion"])
	}
	if _, ok := got["vulnerabilities"]; ok {
		t.Fatalf("vulnerabilities section should be absent without --include-vulns")
	}
}

func TestSbomGenerate_IncludeVulnsWithoutLookup(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = twoDepSnapshot()
	uc := NewSbom(store, "test")
	var buf bytes.Buffer
	_, _, err := uc.Generate(context.Background(), "/proj", &buf, SbomOptions{IncludeVulnerabilities: true})
	if err == nil || !strings.Contains(err.Error(), "--include-vulns") {
		t.Fatalf("expected include-vulns config error, got %v", err)
	}
}

func TestSbomGenerate_IncludeVulnsMerged(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = twoDepSnapshot()
	vulns := &stubVulnLookup{
		out: map[string][]domain.Advisory{
			"npm/lodash@4.17.21": {{
				ID: "GHSA-fake", Severity: domain.SevHigh, Summary: "fake", URL: "https://x", Source: "osv",
			}},
		},
	}
	uc := NewSbom(store, "test").WithVulnLookup(vulns)
	var buf bytes.Buffer
	comps, n, err := uc.Generate(context.Background(), "/proj", &buf, SbomOptions{IncludeVulnerabilities: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if comps != 2 || n != 1 {
		t.Fatalf("counts: comps=%d vulns=%d", comps, n)
	}
	if !strings.Contains(buf.String(), "GHSA-fake") {
		t.Fatalf("missing advisory id in bom: %s", buf.String())
	}
}

func TestSbomGenerate_LookupError(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = twoDepSnapshot()
	uc := NewSbom(store, "test").WithVulnLookup(&stubVulnLookup{err: errors.New("boom")})
	var buf bytes.Buffer
	_, _, err := uc.Generate(context.Background(), "/proj", &buf, SbomOptions{IncludeVulnerabilities: true})
	if err == nil || !strings.Contains(err.Error(), "vuln lookup") {
		t.Fatalf("expected vuln lookup error, got %v", err)
	}
}
