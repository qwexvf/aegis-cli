package pm

import (
	"reflect"
	"testing"
)

func TestYarn_IsInstallCommand(t *testing.T) {
	y := NewYarn()
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"add", "lodash"}, true},
		{[]string{"install"}, true},
		{[]string{"global", "add", "create-react-app"}, true},
		{[]string{"global", "list"}, false},
		{[]string{"global"}, false},
		{[]string{"run", "build"}, false},
		{[]string{"dlx", "create-vite"}, false},
		{[]string{}, false},
	}
	for _, c := range cases {
		if got := y.IsInstallCommand(c.argv); got != c.want {
			t.Errorf("yarn.IsInstallCommand(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

func TestYarn_ParseInstallArgs(t *testing.T) {
	y := NewYarn()
	cases := []struct {
		name string
		argv []string
		want []PackageSpec
	}{
		{
			name: "add with version",
			argv: []string{"add", "lodash@4.17.21"},
			want: []PackageSpec{{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}},
		},
		{
			name: "global add",
			argv: []string{"global", "add", "ua-parser-js@0.7.29"},
			want: []PackageSpec{{Name: "ua-parser-js", Version: "0.7.29", Raw: "ua-parser-js@0.7.29"}},
		},
		{
			name: "add with --dev flag",
			argv: []string{"add", "--dev", "lodash"},
			want: []PackageSpec{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "add with --registry value",
			argv: []string{"add", "--registry", "https://r.example.com", "lodash"},
			want: []PackageSpec{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "berry portal protocol",
			argv: []string{"add", "portal:./pkg"},
			want: []PackageSpec{{Raw: "portal:./pkg", NonRegistry: true}},
		},
		{
			name: "berry patch protocol",
			argv: []string{"add", "patch:lodash@4.17.21#./fix.patch"},
			want: []PackageSpec{{Raw: "patch:lodash@4.17.21#./fix.patch", NonRegistry: true}},
		},
		{
			name: "berry npm: protocol",
			argv: []string{"add", "npm:@types/lodash@^4"},
			want: []PackageSpec{{Raw: "npm:@types/lodash@^4", NonRegistry: true}},
		},
		{
			name: "install no positionals",
			argv: []string{"install"},
			want: []PackageSpec{},
		},
		{
			name: "scoped global add",
			argv: []string{"global", "add", "@bitwarden/cli@2026.4.0"},
			want: []PackageSpec{{Name: "@bitwarden/cli", Version: "2026.4.0", Raw: "@bitwarden/cli@2026.4.0"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := y.ParseInstallArgs(c.argv)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("yarn.ParseInstallArgs(%v):\n  got:  %#v\n  want: %#v", c.argv, got, c.want)
			}
		})
	}
}

func TestYarn_NameAndEcosystem(t *testing.T) {
	y := NewYarn()
	if y.Name() != "yarn" {
		t.Errorf("Name() = %q, want %q", y.Name(), "yarn")
	}
	if y.Ecosystem() != "npm" {
		t.Errorf("Ecosystem() = %q, want %q", y.Ecosystem(), "npm")
	}
}
