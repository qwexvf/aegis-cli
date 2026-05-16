package domain

import "testing"

func TestLicensePolicy_Empty(t *testing.T) {
	tests := []struct {
		name string
		p    LicensePolicy
		want bool
	}{
		{"both nil", LicensePolicy{}, true},
		{"allow only", LicensePolicy{Allow: []string{"MIT"}}, false},
		{"deny only", LicensePolicy{Deny: []string{"GPL-3.0"}}, false},
		{"both", LicensePolicy{Allow: []string{"MIT"}, Deny: []string{"GPL-3.0"}}, false},
	}
	for _, tt := range tests {
		if got := tt.p.Empty(); got != tt.want {
			t.Errorf("%s: Empty() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestLicensePolicy_Check_DenyMode(t *testing.T) {
	p := LicensePolicy{Deny: []string{"GPL-3.0", "AGPL-3.0"}}

	tests := []struct {
		license string
		want    string
	}{
		{"MIT", ""},                                // permitted
		{"Apache-2.0", ""},                         // permitted
		{"", ""},                                   // unknown OK in deny mode
		{"GPL-3.0", "denied license: GPL-3.0"},     // denied
		{"gpl-3.0", "denied license: gpl-3.0"},     // case-insensitive
		{"  GPL-3.0  ", "denied license: GPL-3.0"}, // trimmed
		{"AGPL-3.0", "denied license: AGPL-3.0"},   // second entry
	}
	for _, tt := range tests {
		if got := p.Check(tt.license); got != tt.want {
			t.Errorf("Check(%q) = %q, want %q", tt.license, got, tt.want)
		}
	}
}

func TestLicensePolicy_Check_AllowMode(t *testing.T) {
	p := LicensePolicy{Allow: []string{"MIT", "Apache-2.0", "BSD-3-Clause"}}

	tests := []struct {
		license string
		want    string
	}{
		{"MIT", ""},          // permitted
		{"apache-2.0", ""},   // case-insensitive
		{"BSD-3-Clause", ""}, // permitted
		{"GPL-3.0", "license GPL-3.0 not in allow-list"}, // not in allow
		{"", "license unknown — not in allow-list"},      // unknown blocked in allow mode
		{"  ", "license unknown — not in allow-list"},    // whitespace-only treated as empty
	}
	for _, tt := range tests {
		if got := p.Check(tt.license); got != tt.want {
			t.Errorf("Check(%q) = %q, want %q", tt.license, got, tt.want)
		}
	}
}

func TestLicensePolicy_Check_EmptyPolicy(t *testing.T) {
	p := LicensePolicy{}
	for _, lic := range []string{"MIT", "GPL-3.0", ""} {
		if got := p.Check(lic); got != "" {
			t.Errorf("empty policy should pass %q, got %q", lic, got)
		}
	}
}

func TestLicensePolicy_Check_DenyTakesPrecedenceOverAllow(t *testing.T) {
	// Per the design: when Deny is non-empty, allowlist mode is skipped.
	p := LicensePolicy{
		Allow: []string{"MIT"},
		Deny:  []string{"GPL-3.0"},
	}
	if got := p.Check("Apache-2.0"); got != "" {
		t.Errorf("with Deny non-empty, only Deny rules apply; Apache-2.0 should pass, got %q", got)
	}
	if got := p.Check("GPL-3.0"); got == "" {
		t.Errorf("GPL-3.0 must still be denied")
	}
}
