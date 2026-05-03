package usecase

import (
	"context"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// fakeVulnLookup is a minimal in-memory VulnLookup implementation. It
// records the queries it receives so tests can assert batch shape,
// and returns canned advisories per AdvisoryQuery.Key().
type fakeVulnLookup struct {
	calls    int
	received []domain.AdvisoryQuery
	out      map[string][]domain.Advisory
	err      error
}

func (f *fakeVulnLookup) Lookup(_ context.Context, queries []domain.AdvisoryQuery) (map[string][]domain.Advisory, error) {
	f.calls++
	f.received = append(f.received, queries...)
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string][]domain.Advisory, len(queries))
	for _, q := range queries {
		if v, ok := f.out[q.Key()]; ok {
			out[q.Key()] = v
			continue
		}
		out[q.Key()] = []domain.Advisory{}
	}
	return out, nil
}

// TestEnrich_StampsAdvisories asserts that Snapshot.Enrich passes
// every dep to the VulnLookup adapter exactly once and writes the
// returned advisories back into the saved snapshot.
func TestEnrich_StampsAdvisories(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		dep("evil", "1.0.0"),
		dep("clean", "2.0.0"),
	}}
	vuln := &fakeVulnLookup{
		out: map[string][]domain.Advisory{
			"npm/evil@1.0.0": {{
				ID:       "GHSA-test-evil",
				Severity: domain.SevCritical,
				Summary:  "Malicious",
				Source:   "osv",
			}},
		},
	}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test").
		WithRiskEngine(&fakeFetcher{}, &fakeAnalyzer{out: domain.Fingerprint{Analyzed: true}}, newFPCache()).
		WithVulnLookup(vuln)

	if err := uc.Enrich(context.Background(), "/proj"); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if vuln.calls != 1 {
		t.Errorf("VulnLookup should be called exactly once per Enrich, got %d", vuln.calls)
	}
	if got := len(vuln.received); got != 2 {
		t.Errorf("VulnLookup should receive 2 queries (one per dep), got %d", got)
	}

	// Verify advisories were stamped onto the saved snapshot.
	saved := store.saved["/proj"]
	for _, d := range saved.Deps {
		switch d.Name {
		case "evil":
			if len(d.Advisories) != 1 {
				t.Errorf("evil should have 1 advisory, got %d", len(d.Advisories))
			} else if d.Advisories[0].ID != "GHSA-test-evil" {
				t.Errorf("evil advisory ID = %q", d.Advisories[0].ID)
			}
		case "clean":
			// "Looked up, none found" — empty slice, not nil. The
			// distinction matters because nil triggers re-lookup.
			if d.Advisories == nil {
				t.Error("clean should have non-nil empty Advisories slice (signals 'looked up')")
			}
			if len(d.Advisories) != 0 {
				t.Errorf("clean should have 0 advisories, got %d", len(d.Advisories))
			}
		}
	}
}

// TestEnrich_NoVulnLookup_NoAdvisories: when the use case is built
// without a VulnLookup adapter (the offline / cloud-down case), Enrich
// still completes successfully — the snapshot just carries no
// Advisories. Local AST findings remain authoritative.
func TestEnrich_NoVulnLookup_NoAdvisories(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		dep("anything", "1.0.0"),
	}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test").
		WithRiskEngine(&fakeFetcher{}, &fakeAnalyzer{out: domain.Fingerprint{Analyzed: true}}, newFPCache())
	// Note: no WithVulnLookup() call.

	if err := uc.Enrich(context.Background(), "/proj"); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	saved := store.saved["/proj"]
	for _, d := range saved.Deps {
		if d.Advisories != nil {
			t.Errorf("Advisories should be nil when no VulnLookup configured, got %v", d.Advisories)
		}
	}
}

// TestEnrich_VulnLookupError_StillSavesAST: a flaky vulnerability
// feed shouldn't lose the AST findings already in memory. The
// snapshot persists with empty Advisories and an info message tells
// the user the lookup failed.
func TestEnrich_VulnLookupError_StillSavesAST(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		dep("a", "1"),
	}}
	vuln := &fakeVulnLookup{err: context.DeadlineExceeded}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test").
		WithRiskEngine(&fakeFetcher{}, &fakeAnalyzer{out: domain.Fingerprint{
			Analyzed:     true,
			Capabilities: domain.NewCapabilitySet(domain.CapShellSpawn),
		}}, newFPCache()).
		WithVulnLookup(vuln)

	if err := uc.Enrich(context.Background(), "/proj"); err != nil {
		t.Fatalf("Enrich should not fail on vuln lookup error, got: %v", err)
	}

	saved := store.saved["/proj"]
	if len(saved.Deps) != 1 {
		t.Fatalf("saved.Deps len = %d", len(saved.Deps))
	}
	if saved.Deps[0].Fingerprint == nil || !saved.Deps[0].Fingerprint.Analyzed {
		t.Error("AST fingerprint should still be persisted despite vuln-lookup error")
	}
}
