package domain

import "testing"

func dep(name, ver string) Dependency {
	return Dependency{Ecosystem: EcoNpm, Name: name, Version: ver}
}

func TestDiffSnapshots_NoChange(t *testing.T) {
	a := Snapshot{Deps: []Dependency{dep("lodash", "4.17.21"), dep("react", "18.0.0")}}
	b := Snapshot{Deps: []Dependency{dep("react", "18.0.0"), dep("lodash", "4.17.21")}}
	d := DiffSnapshots(a, b)
	if !d.Empty() {
		t.Errorf("expected empty delta, got %+v", d)
	}
}

func TestDiffSnapshots_Added(t *testing.T) {
	a := Snapshot{Deps: []Dependency{dep("lodash", "4.17.21")}}
	b := Snapshot{Deps: []Dependency{dep("lodash", "4.17.21"), dep("react", "18.0.0")}}
	d := DiffSnapshots(a, b)
	if len(d.Added) != 1 || d.Added[0].Name != "react" {
		t.Errorf("expected react added; got %+v", d)
	}
	if len(d.Removed) != 0 || len(d.Upgraded) != 0 {
		t.Errorf("unexpected non-empty fields: %+v", d)
	}
}

func TestDiffSnapshots_Removed(t *testing.T) {
	a := Snapshot{Deps: []Dependency{dep("lodash", "4.17.21"), dep("react", "18.0.0")}}
	b := Snapshot{Deps: []Dependency{dep("lodash", "4.17.21")}}
	d := DiffSnapshots(a, b)
	if len(d.Removed) != 1 || d.Removed[0].Name != "react" {
		t.Errorf("expected react removed; got %+v", d)
	}
}

func TestDiffSnapshots_Upgraded(t *testing.T) {
	a := Snapshot{Deps: []Dependency{dep("ua-parser-js", "0.7.28")}}
	b := Snapshot{Deps: []Dependency{dep("ua-parser-js", "0.7.29")}}
	d := DiffSnapshots(a, b)
	if len(d.Upgraded) != 1 {
		t.Fatalf("expected 1 upgrade, got %+v", d)
	}
	u := d.Upgraded[0]
	if u.Old.Version != "0.7.28" || u.New.Version != "0.7.29" {
		t.Errorf("upgrade fields: %+v", u)
	}
}

func TestDiffSnapshots_Mixed(t *testing.T) {
	a := Snapshot{Deps: []Dependency{
		dep("lodash", "4.17.21"),
		dep("ua-parser-js", "0.7.28"),
		dep("react", "17.0.2"),
	}}
	b := Snapshot{Deps: []Dependency{
		dep("lodash", "4.17.21"),      // unchanged
		dep("ua-parser-js", "0.7.29"), // upgraded
		dep("vue", "3.0.0"),           // added
		// react removed
	}}
	d := DiffSnapshots(a, b)
	if len(d.Added) != 1 || d.Added[0].Name != "vue" {
		t.Errorf("added: %+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Name != "react" {
		t.Errorf("removed: %+v", d.Removed)
	}
	if len(d.Upgraded) != 1 || d.Upgraded[0].Name != "ua-parser-js" {
		t.Errorf("upgraded: %+v", d.Upgraded)
	}
}

func TestDiffSnapshots_DeterministicOrder(t *testing.T) {
	// Same diff computed two ways must produce identical output.
	a := Snapshot{Deps: []Dependency{dep("z", "1.0.0"), dep("a", "1.0.0")}}
	b := Snapshot{Deps: []Dependency{dep("a", "1.0.1"), dep("m", "1.0.0"), dep("z", "1.0.1")}}
	d1 := DiffSnapshots(a, b)
	d2 := DiffSnapshots(a, b)
	if d1.Added[0].Name != d2.Added[0].Name || d1.Upgraded[0].Name != d2.Upgraded[0].Name {
		t.Error("diff is not deterministic")
	}
	// Sorted by Key.
	if d1.Upgraded[0].Name != "a" || d1.Upgraded[1].Name != "z" {
		t.Errorf("upgrades not sorted by Key: %+v", d1.Upgraded)
	}
}

func TestDependency_Key(t *testing.T) {
	if dep("lodash", "4.17.21").Key() != "npm/lodash" {
		t.Errorf("Key not as expected")
	}
	if dep("lodash", "4.17.21").VersionedKey() != "npm/lodash@4.17.21" {
		t.Errorf("VersionedKey not as expected")
	}
}
