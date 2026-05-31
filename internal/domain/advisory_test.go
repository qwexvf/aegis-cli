package domain

import "testing"

func TestAdvisoryQueryKey(t *testing.T) {
	q := AdvisoryQuery{Ecosystem: EcoNpm, Name: "lodash", Version: "4.17.21"}
	if got, want := q.Key(), "npm/lodash@4.17.21"; got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}
}

func TestMaxSeverity(t *testing.T) {
	tests := []struct {
		name string
		in   []Advisory
		want Severity
	}{
		{"empty", nil, SevInfo},
		{"only info", []Advisory{{Severity: SevInfo}}, SevInfo},
		{"low beats info", []Advisory{{Severity: SevInfo}, {Severity: SevLow}}, SevLow},
		{"medium beats low", []Advisory{{Severity: SevLow}, {Severity: SevMedium}}, SevMedium},
		{"high beats medium", []Advisory{{Severity: SevMedium}, {Severity: SevHigh}}, SevHigh},
		{"critical beats all", []Advisory{
			{Severity: SevHigh}, {Severity: SevCritical}, {Severity: SevLow},
		}, SevCritical},
		{"order independent", []Advisory{
			{Severity: SevCritical}, {Severity: SevInfo},
		}, SevCritical},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MaxSeverity(tc.in); got != tc.want {
				t.Errorf("MaxSeverity(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestVerdictForAdvisories(t *testing.T) {
	tests := []struct {
		name string
		in   []Advisory
		want VerdictKind
	}{
		{"empty → safe", nil, VerdictSafe},
		{"info → safe", []Advisory{{Severity: SevInfo}}, VerdictSafe},
		{"low → review", []Advisory{{Severity: SevLow}}, VerdictReview},
		{"medium → prompt", []Advisory{{Severity: SevMedium}}, VerdictPrompt},
		{"high → block", []Advisory{{Severity: SevHigh}}, VerdictBlock},
		{"critical → block", []Advisory{{Severity: SevCritical}}, VerdictBlock},
		{"max severity wins", []Advisory{
			{Severity: SevLow}, {Severity: SevHigh}, {Severity: SevInfo},
		}, VerdictBlock},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerdictForAdvisories(tc.in); got != tc.want {
				t.Errorf("VerdictForAdvisories = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityAtLeast(SevHigh, SevMedium) {
		t.Error("high >= medium")
	}
	if !SeverityAtLeast(SevHigh, SevHigh) {
		t.Error("high >= high")
	}
	if SeverityAtLeast(SevLow, SevCritical) {
		t.Error("low should not be >= critical")
	}
	if !SeverityAtLeast(SevCritical, SevInfo) {
		t.Error("critical >= info")
	}
}
