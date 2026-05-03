package domain

import "testing"

func TestPatchVersionDriftFlag(t *testing.T) {
	added := NewCapabilitySet(CapShellSpawn, CapNetEgress)
	empty := CapabilitySet{}

	tests := []struct {
		name    string
		prev    string
		next    string
		added   CapabilitySet
		wantOK  bool
		wantSev int // expected weight when ok
	}{
		// --- positive: same minor, different patch, gained caps ---
		{"1.2.3 → 1.2.4 with new caps", "1.2.3", "1.2.4", added, true, WeightPatchVersionDrift},
		{"v-prefix tolerated", "v1.2.3", "v1.2.4", added, true, WeightPatchVersionDrift},
		{"pre-release stripped", "1.2.3-beta", "1.2.4", added, true, WeightPatchVersionDrift},

		// --- negative ---
		{"1.2.3 → 1.2.4 but no new caps", "1.2.3", "1.2.4", empty, false, 0},
		{"minor bump (not patch)", "1.2.3", "1.3.0", added, false, 0},
		{"major bump (not patch)", "1.2.3", "2.0.0", added, false, 0},
		{"same exact version", "1.2.3", "1.2.3", added, false, 0},
		{"unparseable", "abc", "1.2.4", added, false, 0},
		{"empty prev", "", "1.2.4", added, false, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flag, ok := PatchVersionDriftFlag(tc.prev, tc.next, tc.added)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (flag=%+v)", ok, tc.wantOK, flag)
			}
			if ok && flag.Weight != tc.wantSev {
				t.Errorf("weight = %d, want %d", flag.Weight, tc.wantSev)
			}
		})
	}
}

func TestSplitSemver(t *testing.T) {
	tests := []struct {
		in                string
		major, minor, pat int
		ok                bool
	}{
		{"1.2.3", 1, 2, 3, true},
		{"v1.2.3", 1, 2, 3, true},
		{"1.2.3-beta.1", 1, 2, 3, true},
		{"1.2.3+build", 1, 2, 3, true},
		{"v1.2.3-beta+build", 1, 2, 3, true},
		{"10.20.30", 10, 20, 30, true},
		{"abc", 0, 0, 0, false},
		{"1.2", 0, 0, 0, false},
		{"", 0, 0, 0, false},
	}
	for _, tc := range tests {
		ma, mi, pa, ok := splitSemver(tc.in)
		if ok != tc.ok || (ok && (ma != tc.major || mi != tc.minor || pa != tc.pat)) {
			t.Errorf("splitSemver(%q) = (%d,%d,%d,%v); want (%d,%d,%d,%v)",
				tc.in, ma, mi, pa, ok, tc.major, tc.minor, tc.pat, tc.ok)
		}
	}
}
