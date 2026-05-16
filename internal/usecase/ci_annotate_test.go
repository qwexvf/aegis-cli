package usecase

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestAnnotateAdvisories_VEXSuppressed(t *testing.T) {
	advs := []domain.Advisory{
		{ID: "CVE-2024-1", Aliases: []string{"GHSA-aaa"}},
		{ID: "CVE-2024-2"},
	}
	vex := map[string]struct{}{"CVE-2024-1": {}}
	got := annotateAdvisories(advs, nil, vex)
	if !got[0].VEXSuppressed {
		t.Errorf("expected CVE-2024-1 VEXSuppressed")
	}
	if got[1].VEXSuppressed {
		t.Errorf("expected CVE-2024-2 not VEXSuppressed")
	}
}

func TestAnnotateAdvisories_FunctionUnreachable(t *testing.T) {
	advs := []domain.Advisory{
		{ID: "A", AffectedFunctions: []string{"lodash.template"}},
		{ID: "B", AffectedFunctions: []string{"lodash.merge"}},
		{ID: "C", AffectedFunctions: nil}, // no function info → never unreachable
	}
	usedSymbols := []string{"lodash.merge", "lodash.cloneDeep"}
	got := annotateAdvisories(advs, usedSymbols, nil)
	if !got[0].FunctionUnreachable {
		t.Errorf("A: vulnerable fn (template) not used — expected FunctionUnreachable")
	}
	if got[1].FunctionUnreachable {
		t.Errorf("B: vulnerable fn (merge) IS used — should not be FunctionUnreachable")
	}
	if got[2].FunctionUnreachable {
		t.Errorf("C: no AffectedFunctions data → must not be FunctionUnreachable (absence of data != absence of risk)")
	}
}

func TestAnnotateAdvisories_NoUsedSymbols_NeverSuppress(t *testing.T) {
	advs := []domain.Advisory{
		{ID: "A", AffectedFunctions: []string{"foo.bar"}},
	}
	got := annotateAdvisories(advs, nil, nil)
	if got[0].FunctionUnreachable {
		t.Errorf("when UsedSymbols is empty, never claim unreachable — got %+v", got[0])
	}
}

func TestActiveOnly_FiltersBothSuppressionTypes(t *testing.T) {
	advs := []domain.Advisory{
		{ID: "A"},                            // active
		{ID: "B", VEXSuppressed: true},       // skip
		{ID: "C", FunctionUnreachable: true}, // skip
		{ID: "D", VEXSuppressed: true, FunctionUnreachable: true}, // skip
		{ID: "E"}, // active
	}
	active := activeOnly(advs)
	if len(active) != 2 {
		t.Fatalf("expected 2 active advisories, got %d", len(active))
	}
	if active[0].ID != "A" || active[1].ID != "E" {
		t.Errorf("wrong actives: %+v", active)
	}
}
