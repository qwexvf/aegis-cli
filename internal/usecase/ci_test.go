package usecase

import (
	"context"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// ciCapturingPresenter captures CI lifecycle calls for assertions.
type ciCapturingPresenter struct {
	begins  int
	results []CIResult
	errors  []error
}

func (p *ciCapturingPresenter) OnCIBegin(string, domain.VerdictKind, bool) { p.begins++ }
func (p *ciCapturingPresenter) OnCIResult(r CIResult)                      { p.results = append(p.results, r) }
func (p *ciCapturingPresenter) OnCIError(e error)                          { p.errors = append(p.errors, e) }

func newSnapshotForCI(t *testing.T, deps []domain.Dependency) (*Snapshot, *snapshotCapturingPresenter, *fakeStore) {
	t.Helper()
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: deps}
	scanner := &fakeScanner{deps: deps}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test")
	return uc, pres, store
}

func TestCI_PassesWhenAllSafeBelowThreshold(t *testing.T) {
	cleanFP := &domain.Fingerprint{
		Analyzed:     true,
		Capabilities: domain.NewCapabilitySet(),
	}
	deps := []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "a", Version: "1", Fingerprint: cleanFP},
		{Ecosystem: domain.EcoNpm, Name: "b", Version: "1", Fingerprint: cleanFP},
	}
	snap, _, _ := newSnapshotForCI(t, deps)
	pres := &ciCapturingPresenter{}
	ci := NewCI(snap, pres)

	result, err := ci.Run(context.Background(), CIRequest{
		ProjectDir: "/proj",
		FailOn:     domain.VerdictBlock,
		Enrich:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed {
		t.Errorf("expected passed=true, got false: %+v", result)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.Summary.Total != 2 || result.Summary.Safe != 2 {
		t.Errorf("summary: %+v", result.Summary)
	}
}

func TestCI_FailsOnBlockingFinding(t *testing.T) {
	highRisk := &domain.Fingerprint{
		Analyzed: true,
		Capabilities: domain.NewCapabilitySet(
			domain.CapShellSpawn, domain.CapDynamicEval,
			domain.CapBase64Decode, domain.CapNetEgress,
			domain.CapObfuscatedPayload,
		),
		Hooks: []domain.InstallHook{
			{Phase: domain.PhasePostInstall, Source: "scripts.postinstall"},
		},
	}
	deps := []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "evil", Version: "1.0.0", Fingerprint: highRisk},
	}
	snap, _, _ := newSnapshotForCI(t, deps)
	pres := &ciCapturingPresenter{}
	ci := NewCI(snap, pres)

	result, err := ci.Run(context.Background(), CIRequest{
		ProjectDir: "/proj",
		FailOn:     domain.VerdictBlock,
		Enrich:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed {
		t.Errorf("expected passed=false on blocking finding")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Verdict != domain.VerdictBlock {
		t.Errorf("verdict = %s, want block", result.Findings[0].Verdict)
	}
	if result.Summary.Blocked != 1 {
		t.Errorf("summary.blocked = %d, want 1", result.Summary.Blocked)
	}
}

func TestCI_ThresholdReviewCatchesLowerSeverity(t *testing.T) {
	// One CapShellSpawn (weight 20) lands at score=20 = VerdictSafe.
	// Two caps (40) → VerdictReview. With FailOn=Review, this fails.
	moderateRisk := &domain.Fingerprint{
		Analyzed: true,
		Capabilities: domain.NewCapabilitySet(
			domain.CapShellSpawn, domain.CapDynamicEval,
		),
	}
	deps := []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "moderate", Version: "1", Fingerprint: moderateRisk},
	}
	snap, _, _ := newSnapshotForCI(t, deps)
	pres := &ciCapturingPresenter{}
	ci := NewCI(snap, pres)

	// fail-on=block: passes (verdict is review, not block)
	r, _ := ci.Run(context.Background(), CIRequest{
		ProjectDir: "/proj", FailOn: domain.VerdictBlock,
	})
	if !r.Passed {
		t.Errorf("expected pass at fail-on=block for review-level dep")
	}

	// fail-on=review: fails
	r, _ = ci.Run(context.Background(), CIRequest{
		ProjectDir: "/proj", FailOn: domain.VerdictReview,
	})
	if r.Passed {
		t.Errorf("expected fail at fail-on=review for review-level dep")
	}
}

func TestCI_NoSnapshotErrors(t *testing.T) {
	pres := &ciCapturingPresenter{}
	ci := NewCI(nil, pres)
	_, err := ci.Run(context.Background(), CIRequest{ProjectDir: "/proj", FailOn: domain.VerdictBlock})
	if err == nil {
		t.Error("expected error when snapshot not configured")
	}
	if len(pres.errors) != 1 {
		t.Errorf("expected 1 presenter error, got %d", len(pres.errors))
	}
}

func TestCI_EnrichRequestedButNoRiskEngineErrors(t *testing.T) {
	snap, _, _ := newSnapshotForCI(t, []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "a", Version: "1"},
	})
	// Snapshot is constructed without WithRiskEngine — Enrich should be refused.
	pres := &ciCapturingPresenter{}
	ci := NewCI(snap, pres)

	_, err := ci.Run(context.Background(), CIRequest{
		ProjectDir: "/proj",
		FailOn:     domain.VerdictBlock,
		Enrich:     true,
	})
	if err == nil {
		t.Error("expected error when --enrich requested without risk engine")
	}
	if len(pres.errors) != 1 {
		t.Errorf("expected 1 presenter error, got %d", len(pres.errors))
	}
}

func TestCI_InvalidFailOnRejected(t *testing.T) {
	snap, _, _ := newSnapshotForCI(t, []domain.Dependency{})
	pres := &ciCapturingPresenter{}
	ci := NewCI(snap, pres)

	_, err := ci.Run(context.Background(), CIRequest{
		ProjectDir: "/proj",
		FailOn:     domain.VerdictKind(99),
	})
	if err == nil {
		t.Error("expected error for invalid fail-on")
	}
}

func TestCI_AllowlistSuppressionDropsBelowThreshold(t *testing.T) {
	// dynamic-eval alone scores 25 → VerdictReview. With an allowlist
	// suppressing it, score drops to 0 → VerdictSafe → passes even
	// at fail-on=review.
	rules := []domain.AllowRule{
		{Ecosystem: domain.EcoNpm, Name: "trusted", VersionRange: "*", Capability: domain.CapDynamicEval, Reason: "test"},
	}
	set, err := domain.NewAllowSet(rules)
	if err != nil {
		t.Fatal(err)
	}

	fp := &domain.Fingerprint{
		Analyzed:     true,
		Capabilities: domain.NewCapabilitySet(domain.CapDynamicEval),
	}
	deps := []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "trusted", Version: "1.0.0", Fingerprint: fp},
	}
	snap, _, _ := newSnapshotForCI(t, deps)
	snap.WithAllowlist(set)
	pres := &ciCapturingPresenter{}
	ci := NewCI(snap, pres)

	r, _ := ci.Run(context.Background(), CIRequest{
		ProjectDir: "/proj", FailOn: domain.VerdictReview,
	})
	if !r.Passed {
		t.Errorf("expected pass after allowlist suppression: %+v findings", r.Findings)
	}
}

// TestCI_NoLockfilePassesCleanly is the regression test for the
// "snapshot vanished after save (this is a bug)" false positive that
// fired on monorepo roots without a lockfile (e.g. lockfiles live in
// services/api/, web/, etc.). Save returns nil + emits OnSnapshotEmpty;
// runFull then loads, gets ok=false, used to misreport the bug.
//
// Expected behaviour: PASS with 0 deps, exit 0, clear info message.
func TestCI_NoLockfilePassesCleanly(t *testing.T) {
	store := newFakeStore()
	// store.saved deliberately does NOT contain "/proj" — Save with
	// no lockfile won't write, so Load returns ok=false.
	scanner := &fakeScanner{deps: nil} // empty scan = "no lockfile found"
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test")
	ciPres := &ciCapturingPresenter{}
	ci := NewCI(uc, ciPres)

	r, err := ci.Run(context.Background(), CIRequest{
		ProjectDir: "/proj",
		FailOn:     domain.VerdictBlock,
		Enrich:     false,
	})
	if err != nil {
		t.Fatalf("expected nil error on empty project, got: %v", err)
	}
	if !r.Passed {
		t.Errorf("expected Passed=true on empty project, got Passed=false: %+v", r)
	}
	if r.Summary.Total != 0 {
		t.Errorf("expected 0 total deps, got %d", r.Summary.Total)
	}
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Findings))
	}
}
