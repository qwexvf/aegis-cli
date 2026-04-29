package cli

import (
	"strings"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

func TestParseTestSpec_Cases(t *testing.T) {
	cases := []struct {
		in        string
		wantEco   domain.Ecosystem
		wantName  string
		wantVer   string
		wantError bool
	}{
		{"npm/lodash@4.17.21", domain.EcoNpm, "lodash", "4.17.21", false},
		{"npm/@scope/pkg@1.2.3", domain.EcoNpm, "@scope/pkg", "1.2.3", false},
		{"pypi/requests@2.31.0", domain.EcoPyPI, "requests", "2.31.0", false},
		{"crates/serde@1.0", domain.EcoCrates, "serde", "1.0", false},

		// Errors
		{"missing-slash", "", "", "", true},
		{"npm/no-version", "", "", "", true},
		{"npm/@scope/pkg", "", "", "", true}, // scoped, no version
		{"/leading-slash@1.0", "", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			eco, name, ver, err := parseTestSpec(c.in)
			if c.wantError {
				if err == nil {
					t.Errorf("expected error for %q, got eco=%q name=%q ver=%q", c.in, eco, name, ver)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eco != c.wantEco {
				t.Errorf("eco = %q, want %q", eco, c.wantEco)
			}
			if name != c.wantName {
				t.Errorf("name = %q, want %q", name, c.wantName)
			}
			if ver != c.wantVer {
				t.Errorf("ver = %q, want %q", ver, c.wantVer)
			}
		})
	}
}

func TestParseTestSpec_ErrorMessageMentionsInput(t *testing.T) {
	_, _, _, err := parseTestSpec("garbage")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "garbage") {
		t.Errorf("error should mention input, got %v", err)
	}
}

func TestCapabilityByName_Roundtrip(t *testing.T) {
	for _, c := range domain.AllCapabilities() {
		got, ok := capabilityByName(c.String())
		if !ok || got != c {
			t.Errorf("roundtrip failed for %s: ok=%v got=%v", c, ok, got)
		}
	}
}

func TestCapabilityByName_Unknown(t *testing.T) {
	if _, ok := capabilityByName("not-a-real-capability"); ok {
		t.Error("unknown name should return false")
	}
}
