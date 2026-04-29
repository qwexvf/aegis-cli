package cli

import (
	"strings"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

func upgEntry(name, oldV, newV string, v domain.VerdictKind, risk, drift domain.RiskAssessment) usecase.DiffEntry {
	old := domain.Dependency{Name: name, Version: oldV, Ecosystem: domain.EcoNpm}
	new_ := domain.Dependency{Name: name, Version: newV, Ecosystem: domain.EcoNpm}
	return usecase.DiffEntry{Kind: usecase.DiffUpgraded, Old: &old, New: &new_, Verdict: v, Risk: risk, Drift: drift}
}

func TestSnapshotPresenter_VerdictMarkers(t *testing.T) {
	cases := []struct {
		verdict domain.VerdictKind
		marker  string
	}{
		{domain.VerdictSafe, "✓"},
		{domain.VerdictReview, "⚠"},
		{domain.VerdictPrompt, "⚠"},
		{domain.VerdictBlock, "✗"},
	}
	for _, c := range cases {
		t.Run(c.verdict.String(), func(t *testing.T) {
			sp, buf := snapshotPresenterTest(t)
			risk := domain.RiskAssessment{Score: 50, Flags: []domain.RiskFlag{
				{Code: "demo", Detail: "x", Weight: 50},
			}}
			sp.OnSnapshotDiff(usecase.DiffReport{
				Entries: []usecase.DiffEntry{upgEntry("p", "1.0.0", "1.0.1", c.verdict, risk, domain.RiskAssessment{})},
			})
			if !strings.Contains(buf.String(), c.marker) {
				t.Errorf("verdict=%s expected marker %q in:\n%s", c.verdict, c.marker, buf.String())
			}
		})
	}
}

func TestSnapshotPresenter_SafeVerdictHidesBreakdown(t *testing.T) {
	// Safe + zero risk/drift: no per-flag lines, no "verdict=" line.
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotDiff(usecase.DiffReport{
		Entries: []usecase.DiffEntry{
			upgEntry("p", "1.0.0", "1.0.1", domain.VerdictSafe,
				domain.RiskAssessment{}, domain.RiskAssessment{}),
		},
	})
	out := buf.String()
	if strings.Contains(out, "verdict=") {
		t.Errorf("zero-score safe verdict should not show breakdown:\n%s", out)
	}
	if strings.Contains(out, "└─") {
		t.Errorf("zero-score should not draw box-drawing line:\n%s", out)
	}
}

func TestSnapshotPresenter_DriftFlagsRenderedWithDeltaMarker(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotDiff(usecase.DiffReport{
		Entries: []usecase.DiffEntry{
			upgEntry("p", "1.0.0", "1.0.1", domain.VerdictPrompt,
				domain.RiskAssessment{Score: 30, Flags: []domain.RiskFlag{
					{Code: "shell-spawn", Detail: "spawns", Weight: 20},
				}},
				domain.RiskAssessment{Score: 80, Flags: []domain.RiskFlag{
					{Code: "install-hook-added", Detail: "new hook", Weight: 30},
					{Code: "capability-added", Detail: "new cap", Weight: 15},
				}},
			),
		},
	})
	out := buf.String()
	if !strings.Contains(out, "+ shell-spawn") {
		t.Errorf("risk flag should use + marker:\n%s", out)
	}
	if !strings.Contains(out, "Δ install-hook-added") {
		t.Errorf("drift flag should use Δ marker:\n%s", out)
	}
	if !strings.Contains(out, "Δ capability-added") {
		t.Errorf("second drift flag missing:\n%s", out)
	}
}

func TestSnapshotPresenter_AddedEntryShowsVerdict(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	pkg := domain.Dependency{Name: "evil", Version: "1.0.0", Ecosystem: domain.EcoNpm, Direct: true}
	sp.OnSnapshotDiff(usecase.DiffReport{
		AnyBlocked: true,
		Entries: []usecase.DiffEntry{{
			Kind: usecase.DiffAdded, New: &pkg, Verdict: domain.VerdictBlock,
			Risk: domain.RiskAssessment{Score: 110, Flags: []domain.RiskFlag{
				{Code: "shell-spawn", Detail: "spawns", Weight: 20},
			}},
		}},
	})
	out := buf.String()
	if !strings.Contains(out, "+ added (1)") {
		t.Errorf("missing added section header:\n%s", out)
	}
	if !strings.Contains(out, "✗") || !strings.Contains(out, "evil@1.0.0") {
		t.Errorf("added entry missing verdict marker / pkg ref:\n%s", out)
	}
	if !strings.Contains(out, "(direct)") {
		t.Errorf("direct badge missing:\n%s", out)
	}
}

func TestSnapshotPresenter_RemovedEntryNoBreakdown(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	pkg := domain.Dependency{Name: "p", Version: "1.0.0", Ecosystem: domain.EcoNpm}
	sp.OnSnapshotDiff(usecase.DiffReport{
		Entries: []usecase.DiffEntry{
			{Kind: usecase.DiffRemoved, Old: &pkg, Verdict: domain.VerdictSafe},
		},
	})
	out := buf.String()
	if !strings.Contains(out, "removed (1)") {
		t.Errorf("missing removed header:\n%s", out)
	}
	if strings.Contains(out, "verdict=") || strings.Contains(out, "└─") {
		t.Errorf("removed entry should not show risk breakdown:\n%s", out)
	}
}

func TestSnapshotPresenter_EnrichProgressShowsCounter(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotEnrichProgress(3, 7, "ua-parser-js")
	out := buf.String()
	for _, want := range []string{"[3/7]", "ua-parser-js", "analyzing"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestSnapshotPresenter_SavedShowsCount(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotSaved("/proj/aegis.lock", 42)
	if !strings.Contains(buf.String(), "saved 42 deps") {
		t.Errorf("expected saved count in output:\n%s", buf.String())
	}
}

func TestSnapshotPresenter_ErrorShowsBangMarker(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotError(testError("boom"))
	out := buf.String()
	if !strings.Contains(out, "boom") || !strings.Contains(out, "!") {
		t.Errorf("error output missing message or marker:\n%s", out)
	}
}

func TestSnapshotPresenter_MultipleAddedSorted(t *testing.T) {
	// We don't sort in the presenter (use case does); still verify
	// they all render without dropping any.
	sp, buf := snapshotPresenterTest(t)
	a := domain.Dependency{Name: "a", Version: "1", Ecosystem: domain.EcoNpm}
	b := domain.Dependency{Name: "b", Version: "1", Ecosystem: domain.EcoNpm}
	c := domain.Dependency{Name: "c", Version: "1", Ecosystem: domain.EcoNpm}
	sp.OnSnapshotDiff(usecase.DiffReport{
		Entries: []usecase.DiffEntry{
			{Kind: usecase.DiffAdded, New: &a, Verdict: domain.VerdictSafe},
			{Kind: usecase.DiffAdded, New: &b, Verdict: domain.VerdictSafe},
			{Kind: usecase.DiffAdded, New: &c, Verdict: domain.VerdictSafe},
		},
	})
	out := buf.String()
	if !strings.Contains(out, "+ added (3)") {
		t.Errorf("expected 3-count header:\n%s", out)
	}
	for _, n := range []string{"a@1", "b@1", "c@1"} {
		if !strings.Contains(out, n) {
			t.Errorf("missing %q in:\n%s", n, out)
		}
	}
}

type testError string

func (e testError) Error() string { return string(e) }

// diffReportFromUpgrade builds a single-entry DiffReport for upgrade
// rendering tests. Shared between snapshot_verdict_test.go and
// allowlist_render_test.go.
func diffReportFromUpgrade(oldDep, newDep domain.Dependency, v domain.VerdictKind, risk, drift domain.RiskAssessment) usecase.DiffReport {
	return usecase.DiffReport{
		Entries: []usecase.DiffEntry{{
			Kind: usecase.DiffUpgraded,
			Old:  &oldDep, New: &newDep,
			Verdict: v, Risk: risk, Drift: drift,
		}},
	}
}
