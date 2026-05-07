package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func snapshotPresenterTest(t *testing.T) (*SnapshotPresenter, *bytes.Buffer) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	buf := &bytes.Buffer{}
	return NewSnapshotPresenter(NewWith(buf)), buf
}

func TestSnapshotPresenter_Saved(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotSaved("/proj/aegis.lock", 42)
	out := buf.String()
	if !strings.Contains(out, "saved 42 deps") || !strings.Contains(out, "aegis.lock") {
		t.Errorf("missing markers:\n%s", out)
	}
}

func TestSnapshotPresenter_Show(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotShow(domain.Snapshot{
		SchemaVersion: 1,
		Project:       "demo",
		CreatedAt:     time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21", Direct: true},
			{Ecosystem: domain.EcoNpm, Name: "ms", Version: "2.1.3"},
		},
	}, false, false)
	out := buf.String()
	for _, want := range []string{"snapshot: demo", "lodash", "4.17.21", "ms"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestSnapshotPresenter_ShowDirectOnlyFiltersTransitives(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotShow(domain.Snapshot{
		Deps: []domain.Dependency{
			{Name: "lodash", Version: "4.17.21", Direct: true, Ecosystem: domain.EcoNpm},
			{Name: "ms", Version: "2.1.3", Ecosystem: domain.EcoNpm},
		},
	}, true, false)
	out := buf.String()
	if !strings.Contains(out, "lodash") {
		t.Errorf("direct dep missing:\n%s", out)
	}
	if strings.Contains(out, "ms") {
		t.Errorf("transitive dep should be filtered:\n%s", out)
	}
	if !strings.Contains(out, "shown 1 direct deps") {
		t.Errorf("missing footer:\n%s", out)
	}
}

func TestSnapshotPresenter_ShowMarksUnused(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotShow(domain.Snapshot{
		Deps: []domain.Dependency{
			{
				Ecosystem:    domain.EcoNpm,
				Name:         "lodash",
				Version:      "4.17.21",
				Direct:       true,
				Reachability: domain.ReachabilityUnused,
				Fingerprint:  &domain.Fingerprint{Analyzed: true},
			},
		},
	}, false, false)
	if !strings.Contains(buf.String(), "[unused]") {
		t.Errorf("expected [unused] marker in CAPS column:\n%s", buf.String())
	}
}

func TestSnapshotPresenter_ShowUsedOnlyHidesUnused(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotShow(domain.Snapshot{
		Deps: []domain.Dependency{
			{
				Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21",
				Direct: true, Reachability: domain.ReachabilityUsed,
			},
			{
				Ecosystem: domain.EcoNpm, Name: "axios", Version: "1.6.0",
				Direct: true, Reachability: domain.ReachabilityUnused,
			},
		},
	}, false, true)
	out := buf.String()
	if !strings.Contains(out, "lodash") {
		t.Errorf("used dep should render:\n%s", out)
	}
	if strings.Contains(out, "axios") {
		t.Errorf("unused dep should be hidden under --used-only:\n%s", out)
	}
	if !strings.Contains(out, "hid 1 unused deps") {
		t.Errorf("missing footer:\n%s", out)
	}
}

func TestSnapshotPresenter_DiffEmpty(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotDiff(usecase.DiffReport{})
	if !strings.Contains(buf.String(), "no changes") {
		t.Errorf("expected 'no changes':\n%s", buf.String())
	}
}

func TestSnapshotPresenter_DiffMixed(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	vue := domain.Dependency{Name: "vue", Version: "3.0.0", Direct: true, Ecosystem: domain.EcoNpm}
	react := domain.Dependency{Name: "react", Version: "17.0.2", Ecosystem: domain.EcoNpm}
	uaOld := domain.Dependency{Name: "ua-parser-js", Version: "0.7.28"}
	uaNew := domain.Dependency{Name: "ua-parser-js", Version: "0.7.29"}
	sp.OnSnapshotDiff(usecase.DiffReport{
		Entries: []usecase.DiffEntry{
			{Kind: usecase.DiffAdded, New: &vue, Verdict: domain.VerdictSafe},
			{Kind: usecase.DiffRemoved, Old: &react, Verdict: domain.VerdictSafe},
			{Kind: usecase.DiffUpgraded, Old: &uaOld, New: &uaNew, Verdict: domain.VerdictSafe},
		},
	})
	out := buf.String()
	for _, want := range []string{
		"+ added (1)",
		"vue@3.0.0",
		"(direct)",
		"- removed (1)",
		"react@17.0.2",
		"~ upgraded (1)",
		"ua-parser-js",
		"0.7.28 → 0.7.29",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestSnapshotPresenter_DiffShowsFlagsForBlockedEntry(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	uaOld := domain.Dependency{Name: "ua-parser-js", Version: "0.7.28"}
	uaNew := domain.Dependency{Name: "ua-parser-js", Version: "0.7.29"}
	sp.OnSnapshotDiff(usecase.DiffReport{
		AnyBlocked: true,
		Entries: []usecase.DiffEntry{{
			Kind:    usecase.DiffUpgraded,
			Old:     &uaOld,
			New:     &uaNew,
			Verdict: domain.VerdictBlock,
			Risk: domain.RiskAssessment{
				Score: 80,
				Flags: []domain.RiskFlag{
					{Code: "shell-spawn", Detail: "spawns subprocess", Weight: 20},
				},
			},
			Drift: domain.RiskAssessment{
				Score: 80,
				Flags: []domain.RiskFlag{
					{Code: "install-hook-added", Detail: "new postinstall hook (none in prior version)", Weight: 30},
				},
			},
		}},
	})
	out := buf.String()
	for _, want := range []string{
		"verdict=block",
		"risk=80",
		"drift=80",
		"shell-spawn",
		"install-hook-added",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}
