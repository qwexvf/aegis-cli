package domain

import "testing"

func TestUpgradeCommand_RejectsShellInjection(t *testing.T) {
	tests := []struct {
		name, version string
	}{
		{"foo; rm -rf /", "1.0.0"},
		{"foo`evil`", "1.0.0"},
		{"foo$(evil)", "1.0.0"},
		{"foo|sh", "1.0.0"},
		{"foo&", "1.0.0"},
		{"foo bar", "1.0.0"},
		{"foo\"quote", "1.0.0"},
		{"foo'quote", "1.0.0"},
		{"normal", "1.0.0; rm -rf /"},
		{"normal", "1.0.0|sh"},
		{"normal", "1.0.0`evil`"},
	}
	for _, tt := range tests {
		got := UpgradeCommand(Dependency{Ecosystem: EcoNpm, Name: tt.name}, tt.version)
		if got != "" {
			t.Errorf("expected empty (rejected) for name=%q version=%q, got %q", tt.name, tt.version, got)
		}
	}
}

func TestUpgradeCommand_AcceptsBenign(t *testing.T) {
	tests := []struct {
		eco             Ecosystem
		name, ver, want string
	}{
		{EcoNpm, "lodash", "4.17.21", "npm install lodash@4.17.21"},
		{EcoNpm, "@types/node", "20.0.0", "npm install @types/node@20.0.0"},
		{EcoGo, "golang.org/x/crypto", "v0.17.0", "go get golang.org/x/crypto@v0.17.0"},
		{EcoPyPI, "requests", "2.31.0", "pip install requests==2.31.0"},
	}
	for _, tt := range tests {
		if got := UpgradeCommand(Dependency{Ecosystem: tt.eco, Name: tt.name}, tt.ver); got != tt.want {
			t.Errorf("UpgradeCommand(%s/%s, %s) = %q, want %q", tt.eco, tt.name, tt.ver, got, tt.want)
		}
	}
}
