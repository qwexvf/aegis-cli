package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
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
	}, false)
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
	}, true)
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

func TestSnapshotPresenter_DiffEmpty(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotDiff(domain.SnapshotDelta{})
	if !strings.Contains(buf.String(), "no changes") {
		t.Errorf("expected 'no changes':\n%s", buf.String())
	}
}

func TestSnapshotPresenter_DiffMixed(t *testing.T) {
	sp, buf := snapshotPresenterTest(t)
	sp.OnSnapshotDiff(domain.SnapshotDelta{
		Added: []domain.Dependency{
			{Name: "vue", Version: "3.0.0", Direct: true, Ecosystem: domain.EcoNpm},
		},
		Removed: []domain.Dependency{
			{Name: "react", Version: "17.0.2", Ecosystem: domain.EcoNpm},
		},
		Upgraded: []domain.DepUpgrade{{
			Name: "ua-parser-js",
			Old:  domain.Dependency{Name: "ua-parser-js", Version: "0.7.28"},
			New:  domain.Dependency{Name: "ua-parser-js", Version: "0.7.29"},
		}},
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
