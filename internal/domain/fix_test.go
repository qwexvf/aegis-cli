package domain

import (
	"testing"
)

func TestCompareFixVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.10", "1.2.9", 1}, // numeric-aware: 10 > 9, not "10" < "9"
		{"v1.2.3", "1.2.4", -1},
		{"2.0.0", "1.99.99", 1},
		{"", "1.0.0", -1},
	}
	for _, tt := range tests {
		got := compareFixVersion(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareFixVersion(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestBuildFixPlan_SkipsDepsWithoutAdvisories(t *testing.T) {
	snap := Snapshot{Deps: []Dependency{
		{Ecosystem: EcoNpm, Name: "lodash", Version: "4.17.5"},
	}}
	plan := BuildFixPlan(snap)
	if !plan.Empty() {
		t.Fatalf("expected empty plan, got %d items", len(plan.Items))
	}
}

func TestBuildFixPlan_PicksHighestFixedIn(t *testing.T) {
	snap := Snapshot{Deps: []Dependency{
		{
			Ecosystem: EcoNpm, Name: "lodash", Version: "4.17.5",
			Advisories: []Advisory{
				{ID: "CVE-A", FixedIn: "4.17.10", Severity: SevHigh},
				{ID: "CVE-B", FixedIn: "4.17.21", Severity: SevCritical},
				{ID: "CVE-C", FixedIn: "4.17.15", Severity: SevMedium},
			},
		},
	}}
	plan := BuildFixPlan(snap)
	if len(plan.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(plan.Items))
	}
	if plan.Items[0].TargetVersion != "4.17.21" {
		t.Errorf("expected target 4.17.21, got %q", plan.Items[0].TargetVersion)
	}
	if len(plan.Items[0].ResolvedAdvisories) != 3 {
		t.Errorf("expected 3 resolved, got %d", len(plan.Items[0].ResolvedAdvisories))
	}
}

func TestBuildFixPlan_PartitionsResolvedVsUnresolved(t *testing.T) {
	snap := Snapshot{Deps: []Dependency{
		{
			Ecosystem: EcoNpm, Name: "lodash", Version: "4.17.5",
			Advisories: []Advisory{
				{ID: "CVE-A", FixedIn: "4.17.21", Severity: SevHigh},
				{ID: "CVE-B", FixedIn: "", Severity: SevMedium}, // no upstream fix
			},
		},
	}}
	plan := BuildFixPlan(snap)
	if len(plan.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(plan.Items))
	}
	it := plan.Items[0]
	if it.TargetVersion != "4.17.21" {
		t.Errorf("target = %q, want 4.17.21", it.TargetVersion)
	}
	if len(it.ResolvedAdvisories) != 1 || it.ResolvedAdvisories[0].ID != "CVE-A" {
		t.Errorf("resolved set wrong: %+v", it.ResolvedAdvisories)
	}
	if len(it.UnresolvedAdvisories) != 1 || it.UnresolvedAdvisories[0].ID != "CVE-B" {
		t.Errorf("unresolved set wrong: %+v", it.UnresolvedAdvisories)
	}
}

func TestBuildFixPlan_SkipsVEXSuppressed(t *testing.T) {
	snap := Snapshot{Deps: []Dependency{
		{
			Ecosystem: EcoNpm, Name: "lodash", Version: "4.17.5",
			Advisories: []Advisory{
				{ID: "CVE-A", FixedIn: "4.17.21", Severity: SevHigh, VEXSuppressed: true},
				{ID: "CVE-B", FixedIn: "4.17.15", Severity: SevMedium},
			},
		},
	}}
	plan := BuildFixPlan(snap)
	if len(plan.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(plan.Items))
	}
	if plan.Items[0].TargetVersion != "4.17.15" {
		t.Errorf("VEX-suppressed advisory should not contribute to target; got %q", plan.Items[0].TargetVersion)
	}
}

func TestUpgradeCommand_PinnedVsLatest(t *testing.T) {
	tests := []struct {
		name   string
		dep    Dependency
		target string
		want   string
	}{
		{"npm pinned", Dependency{Ecosystem: EcoNpm, Name: "lodash"}, "4.17.21", "npm install lodash@4.17.21"},
		{"npm latest", Dependency{Ecosystem: EcoNpm, Name: "lodash"}, "", "npm install lodash@latest"},
		{"pypi pinned", Dependency{Ecosystem: EcoPyPI, Name: "requests"}, "2.31.0", "pip install requests==2.31.0"},
		{"go pinned", Dependency{Ecosystem: EcoGo, Name: "golang.org/x/crypto"}, "v0.17.0", "go get golang.org/x/crypto@v0.17.0"},
		{"cargo pinned", Dependency{Ecosystem: EcoCrates, Name: "serde"}, "1.0.193", "cargo update -p serde --precise 1.0.193"},
		{"nuget pinned", Dependency{Ecosystem: EcoNuGet, Name: "Newtonsoft.Json"}, "13.0.3", "dotnet add package Newtonsoft.Json --version 13.0.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UpgradeCommand(tt.dep, tt.target)
			if got != tt.want {
				t.Errorf("UpgradeCommand = %q, want %q", got, tt.want)
			}
		})
	}
}
