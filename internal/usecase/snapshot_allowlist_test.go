package usecase

import (
	"context"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// allowlistSetup creates a snapshot with a saved "lodash@4.17.21" with
// CapDynamicEval flagged, then live-rescans the same dep so Diff has
// something to assess.
func allowlistSetup(t *testing.T, set domain.AllowSet) (*Snapshot, *snapshotCapturingPresenter) {
	t.Helper()
	store := newFakeStore()
	prevFP := &domain.Fingerprint{
		Analyzed:     true,
		Capabilities: domain.NewCapabilitySet(domain.CapDynamicEval),
	}
	store.saved["/proj"] = domain.Snapshot{
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21", Fingerprint: prevFP},
		},
	}
	scanner := &fakeScanner{deps: []domain.Dependency{
		{
			Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.22",
			Fingerprint: &domain.Fingerprint{
				Analyzed:     true,
				Capabilities: domain.NewCapabilitySet(domain.CapDynamicEval),
			},
		},
	}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test").WithAllowlist(set)
	return uc, pres
}

func TestSnapshot_DiffAllowlistSuppressesScore(t *testing.T) {
	rules := []domain.AllowRule{
		{Ecosystem: domain.EcoNpm, Name: "lodash", Capability: domain.CapDynamicEval, Reason: "tpl"},
	}
	set, err := domain.NewAllowSet(rules)
	if err != nil {
		t.Fatal(err)
	}
	uc, pres := allowlistSetup(t, set)

	if err := uc.Diff("/proj", "", ""); err != nil {
		t.Fatal(err)
	}
	d := pres.diffs[0]
	upgrades := entriesByKind(d, DiffUpgraded)
	if len(upgrades) != 1 {
		t.Fatalf("expected 1 upgrade, got %d", len(upgrades))
	}
	e := upgrades[0]
	if e.Risk.Score != 0 {
		t.Errorf("allowlist should zero risk score; got %d", e.Risk.Score)
	}
	if len(e.Risk.Flags) != 1 || !e.Risk.Flags[0].Suppressed {
		t.Errorf("flag should be marked Suppressed: %+v", e.Risk.Flags)
	}
	if e.Risk.Flags[0].SuppressBy != "tpl" {
		t.Errorf("SuppressBy = %q, want tpl", e.Risk.Flags[0].SuppressBy)
	}
}

func TestSnapshot_DiffNoAllowlistKeepsScore(t *testing.T) {
	uc, pres := allowlistSetup(t, domain.EmptyAllowSet())

	uc.Diff("/proj", "", "")
	d := pres.diffs[0]
	upgrades := entriesByKind(d, DiffUpgraded)
	if upgrades[0].Risk.Score != domain.WeightDynamicEval {
		t.Errorf("without allowlist, score should be %d, got %d",
			domain.WeightDynamicEval, upgrades[0].Risk.Score)
	}
	if upgrades[0].Risk.Flags[0].Suppressed {
		t.Error("flag should NOT be suppressed without allowlist")
	}
}

func TestSnapshot_DiffAllowlistAppliedToAddedToo(t *testing.T) {
	// Same allowlist applies to Added entries (newly-introduced deps).
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{}}
	scanner := &fakeScanner{deps: []domain.Dependency{
		{
			Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21",
			Fingerprint: &domain.Fingerprint{
				Analyzed:     true,
				Capabilities: domain.NewCapabilitySet(domain.CapDynamicEval),
			},
		},
	}}
	pres := &snapshotCapturingPresenter{}
	set, _ := domain.NewAllowSet([]domain.AllowRule{
		{Ecosystem: domain.EcoNpm, Name: "lodash", Capability: domain.CapDynamicEval, Reason: "tpl"},
	})
	uc := NewSnapshot(store, scanner, pres, "test").WithAllowlist(set)

	if err := uc.Diff("/proj", "", ""); err != nil {
		t.Fatal(err)
	}
	added := entriesByKind(pres.diffs[0], DiffAdded)
	if len(added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(added))
	}
	if added[0].Risk.Score != 0 || !added[0].Risk.Flags[0].Suppressed {
		t.Errorf("Added entry should also be allowlist-suppressed: %+v", added[0])
	}
}

func TestSnapshot_DiffAllowlistDriftSuppression(t *testing.T) {
	// Drift's "capability-added" flag must also respect allowlist.
	prev := &domain.Fingerprint{Analyzed: true} // no capabilities
	next := &domain.Fingerprint{
		Analyzed:     true,
		Capabilities: domain.NewCapabilitySet(domain.CapShellSpawn),
	}
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "esbuild", Version: "0.20.0", Fingerprint: prev},
	}}
	scanner := &fakeScanner{deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "esbuild", Version: "0.21.0", Fingerprint: next},
	}}
	pres := &snapshotCapturingPresenter{}
	set, _ := domain.NewAllowSet([]domain.AllowRule{
		{Ecosystem: domain.EcoNpm, Name: "esbuild", Capability: domain.CapShellSpawn, Reason: "build tool"},
	})
	uc := NewSnapshot(store, scanner, pres, "test").WithAllowlist(set)

	uc.Diff("/proj", "", "")
	upgrades := entriesByKind(pres.diffs[0], DiffUpgraded)
	if upgrades[0].Drift.Score != 0 {
		t.Errorf("drift score should be 0 after allowlist, got %d", upgrades[0].Drift.Score)
	}
	if !upgrades[0].Drift.Flags[0].Suppressed {
		t.Error("drift flag should be suppressed via Detail-encoded Capability")
	}
}

// stub context to satisfy any future Diff signature changes
var _ = context.Background
