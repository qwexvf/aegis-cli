package pmwrapper

import (
	"reflect"
	"testing"
)

func TestPnpm_IsInstallCommand(t *testing.T) {
	p := NewPnpm()
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"add", "lodash"}, true},
		{[]string{"install"}, true},
		{[]string{"i"}, true},
		{[]string{"add", "-g", "create-react-app"}, true},
		{[]string{"dlx", "create-vite"}, false},
		{[]string{"run", "build"}, false},
		{[]string{"exec", "tsc"}, false},
		{[]string{}, false},
	}
	for _, c := range cases {
		if got := p.IsInstallCommand(c.argv); got != c.want {
			t.Errorf("pnpm.IsInstallCommand(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

func TestPnpm_ParseInstallArgs(t *testing.T) {
	p := NewPnpm()
	cases := []struct {
		name string
		argv []string
		want []SpecToken
	}{
		{
			name: "add with version",
			argv: []string{"add", "lodash@4.17.21"},
			want: []SpecToken{{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}},
		},
		{
			name: "add with global short flag",
			argv: []string{"add", "-g", "create-react-app"},
			want: []SpecToken{{Name: "create-react-app", Raw: "create-react-app"}},
		},
		{
			name: "add with --filter value",
			argv: []string{"add", "--filter", "web", "lodash"},
			want: []SpecToken{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "add with -D flag",
			argv: []string{"add", "-D", "lodash"},
			want: []SpecToken{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "scoped",
			argv: []string{"add", "@bitwarden/cli@2026.4.0"},
			want: []SpecToken{{Name: "@bitwarden/cli", Version: "2026.4.0", Raw: "@bitwarden/cli@2026.4.0"}},
		},
		{
			name: "local path passthrough",
			argv: []string{"add", "./local"},
			want: []SpecToken{{Raw: "./local", NonRegistry: true}},
		},
		{
			name: "workspace protocol passthrough",
			argv: []string{"add", "workspace:*"},
			want: []SpecToken{{Raw: "workspace:*", NonRegistry: true}},
		},
		{
			name: "install no positionals",
			argv: []string{"install"},
			want: []SpecToken{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := p.ParseInstallArgs(c.argv)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("pnpm.ParseInstallArgs(%v):\n  got:  %#v\n  want: %#v", c.argv, got, c.want)
			}
		})
	}
}

func TestPnpm_NameAndEcosystem(t *testing.T) {
	p := NewPnpm()
	if p.Name() != "pnpm" {
		t.Errorf("Name() = %q, want %q", p.Name(), "pnpm")
	}
	if p.Ecosystem() != "npm" {
		t.Errorf("Ecosystem() = %q, want %q", p.Ecosystem(), "npm")
	}
}
