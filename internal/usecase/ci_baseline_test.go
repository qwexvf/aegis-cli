package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// TestCI_BaselineModeNoChanges_Passes — saved == live, no findings.
func TestCI_BaselineModeNoChanges_Passes(t *testing.T) {
	dep := domain.Dependency{
		Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21",
		Fingerprint: &domain.Fingerprint{Analyzed: true},
	}
	store := newFakeStore()
	store.files["/baseline.lock"] = domain.Snapshot{Deps: []domain.Dependency{dep}}
	scanner := &fakeScanner{deps: []domain.Dependency{dep}}
	snap := NewSnapshot(store, scanner, &snapshotCapturingPresenter{}, "test")
	ci := NewCI(snap, &ciCapturingPresenter{})

	result, err := ci.Run(context.Background(), CIRequest{
		ProjectDir:   "/proj",
		FailOn:       domain.VerdictBlock,
		Enrich:       false,
		BaselinePath: "/baseline.lock",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed {
		t.Errorf("expected pass on no-diff baseline, got findings: %+v", result.Findings)
	}
}

// TestCI_BaselineMode_VersionUpgradeWithDriftFails — same package
// upgraded with a new postinstall hook → drift score → block verdict.
func TestCI_BaselineMode_VersionUpgradeWithDriftFails(t *testing.T) {
	cleanFP := &domain.Fingerprint{
		Analyzed:     true,
		Capabilities: domain.NewCapabilitySet(),
	}
	driftFP := &domain.Fingerprint{
		Analyzed: true,
		Capabilities: domain.NewCapabilitySet(
			domain.CapShellSpawn, domain.CapNetEgress, domain.CapDynamicEval,
		),
		Hooks: []domain.InstallHook{
			{Phase: domain.PhasePostInstall, Source: "scripts.postinstall"},
		},
	}
	store := newFakeStore()
	store.files["/baseline.lock"] = domain.Snapshot{Deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "p", Version: "1.0.0", Fingerprint: cleanFP},
	}}
	scanner := &fakeScanner{deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "p", Version: "1.0.1", Fingerprint: driftFP},
	}}
	snap := NewSnapshot(store, scanner, &snapshotCapturingPresenter{}, "test")
	ci := NewCI(snap, &ciCapturingPresenter{})

	// fail-on=review catches anything ≥ review; the diff verdict for
	// this upgrade pattern (3 caps + new hook on previously-empty fp)
	// lands well above safe.
	result, _ := ci.Run(context.Background(), CIRequest{
		ProjectDir:   "/proj",
		FailOn:       domain.VerdictReview,
		BaselinePath: "/baseline.lock",
	})
	if result.Passed {
		t.Errorf("expected fail on drift upgrade at fail-on=review, got passed=true")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding from drift upgrade")
	}
	if result.Findings[0].Dep.Name != "p" {
		t.Errorf("finding name = %q, want p", result.Findings[0].Dep.Name)
	}
}

// TestCI_BaselineMode_BaselineLoadErrorsBubble — bad path fails fast.
func TestCI_BaselineMode_BaselineLoadErrorsBubble(t *testing.T) {
	store := newFakeStore()
	store.loadFile = func(string) (domain.Snapshot, error) {
		return domain.Snapshot{}, errors.New("nope")
	}
	scanner := &fakeScanner{}
	snap := NewSnapshot(store, scanner, &snapshotCapturingPresenter{}, "test")
	pres := &ciCapturingPresenter{}
	ci := NewCI(snap, pres)

	_, err := ci.Run(context.Background(), CIRequest{
		ProjectDir:   "/proj",
		FailOn:       domain.VerdictBlock,
		BaselinePath: "/missing.lock",
	})
	if err == nil {
		t.Error("expected error when baseline file load fails")
	}
	if len(pres.errors) != 1 {
		t.Errorf("expected 1 OnCIError, got %d", len(pres.errors))
	}
}

// TestCI_BaselineMode_DoesNotOverwriteSavedSnapshot — the project's
// aegis.lock should be untouched after a baseline run.
func TestCI_BaselineMode_DoesNotOverwriteSavedSnapshot(t *testing.T) {
	dep := domain.Dependency{
		Ecosystem: domain.EcoNpm, Name: "p", Version: "1",
		Fingerprint: &domain.Fingerprint{Analyzed: true},
	}
	store := newFakeStore()
	store.files["/baseline.lock"] = domain.Snapshot{Deps: []domain.Dependency{dep}}
	scanner := &fakeScanner{deps: []domain.Dependency{dep}}
	snap := NewSnapshot(store, scanner, &snapshotCapturingPresenter{}, "test")
	ci := NewCI(snap, &ciCapturingPresenter{})

	_, err := ci.Run(context.Background(), CIRequest{
		ProjectDir:   "/proj",
		FailOn:       domain.VerdictBlock,
		BaselinePath: "/baseline.lock",
	})
	if err != nil {
		t.Fatal(err)
	}
	// In drift mode the save() path is skipped; nothing should land
	// in store.saved at /proj.
	if _, ok := store.saved["/proj"]; ok {
		t.Errorf("baseline mode must NOT write a snapshot to /proj")
	}
}
