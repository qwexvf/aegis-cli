package pm

import (
	"reflect"
	"testing"
)

func TestNpm_IsInstallCommand(t *testing.T) {
	n := NewNpm()
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"install"}, true},
		{[]string{"i"}, true},
		{[]string{"in"}, true},
		{[]string{"ins"}, true},
		{[]string{"add"}, true},
		{[]string{"isntall"}, true}, // typo alias
		{[]string{"isnt"}, true},
		{[]string{"test"}, false},
		{[]string{"run", "build"}, false},
		{[]string{}, false},
	}
	for _, c := range cases {
		if got := n.IsInstallCommand(c.argv); got != c.want {
			t.Errorf("npm.IsInstallCommand(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

func TestNpm_ParseInstallArgs(t *testing.T) {
	n := NewNpm()
	cases := []struct {
		name string
		argv []string
		want []PackageSpec
	}{
		{
			name: "install with positional and flag",
			argv: []string{"install", "lodash", "--save-dev"},
			want: []PackageSpec{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "i alias with workspace flag value",
			argv: []string{"i", "-w", "frontend", "lodash@4.17.21"},
			want: []PackageSpec{{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}},
		},
		{
			name: "scoped",
			argv: []string{"add", "@bitwarden/cli@2026.4.0"},
			want: []PackageSpec{{Name: "@bitwarden/cli", Version: "2026.4.0", Raw: "@bitwarden/cli@2026.4.0"}},
		},
		{
			name: "install no positionals (package.json restore)",
			argv: []string{"install"},
			want: []PackageSpec{},
		},
		{
			name: "non-registry tarball",
			argv: []string{"install", "https://x/foo.tgz"},
			want: []PackageSpec{{Raw: "https://x/foo.tgz", NonRegistry: true}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := n.ParseInstallArgs(c.argv)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("npm.ParseInstallArgs(%v):\n  got:  %#v\n  want: %#v", c.argv, got, c.want)
			}
		})
	}
}
