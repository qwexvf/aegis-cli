package pm

import (
	"reflect"
	"testing"
)

func TestIsExactVersion(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"", false},
		{"4.17.21", true},
		{"2026.4.0", true},
		{"1.0.0-rc.1", true},
		{"1.2.3+build.45", true},
		{"^4.17.0", false},
		{"~1.2.3", false},
		{"latest", false},
		{"next", false},
		{">=1.0.0", false},
		{"1.x", false},
		{"4", false},
	}
	for _, c := range cases {
		got := PackageSpec{Version: c.version}.IsExactVersion()
		if got != c.want {
			t.Errorf("IsExactVersion(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestParseSpec(t *testing.T) {
	cases := []struct {
		token string
		want  PackageSpec
	}{
		{"lodash", PackageSpec{Name: "lodash", Raw: "lodash"}},
		{"lodash@4.17.21", PackageSpec{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}},
		{"lodash@^4.17.0", PackageSpec{Name: "lodash", Version: "^4.17.0", Raw: "lodash@^4.17.0"}},
		{"lodash@latest", PackageSpec{Name: "lodash", Version: "latest", Raw: "lodash@latest"}},
		{"@bitwarden/cli", PackageSpec{Name: "@bitwarden/cli", Raw: "@bitwarden/cli"}},
		{"@bitwarden/cli@2026.4.0", PackageSpec{Name: "@bitwarden/cli", Version: "2026.4.0", Raw: "@bitwarden/cli@2026.4.0"}},
		// Non-registry forms
		{"./vendor/foo", PackageSpec{Raw: "./vendor/foo", NonRegistry: true}},
		{"https://github.com/foo/bar/archive/v1.tgz", PackageSpec{Raw: "https://github.com/foo/bar/archive/v1.tgz", NonRegistry: true}},
		{"github:lodash/lodash", PackageSpec{Raw: "github:lodash/lodash", NonRegistry: true}},
		{"file:./local", PackageSpec{Raw: "file:./local", NonRegistry: true}},
		{"git+https://github.com/x/y.git", PackageSpec{Raw: "git+https://github.com/x/y.git", NonRegistry: true}},
		// Yarn berry / bun protocols
		{"link:../sibling", PackageSpec{Raw: "link:../sibling", NonRegistry: true}},
		{"workspace:*", PackageSpec{Raw: "workspace:*", NonRegistry: true}},
		{"patch:lodash@4.17.21#./fix.patch", PackageSpec{Raw: "patch:lodash@4.17.21#./fix.patch", NonRegistry: true}},
		{"portal:./pkg", PackageSpec{Raw: "portal:./pkg", NonRegistry: true}},
		{"npm:@types/lodash@^4", PackageSpec{Raw: "npm:@types/lodash@^4", NonRegistry: true}},
	}
	for _, c := range cases {
		got := parseSpec(c.token)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseSpec(%q):\n  got:  %#v\n  want: %#v", c.token, got, c.want)
		}
	}
}

func TestParseInstallArgsWith(t *testing.T) {
	// Use a permissive takesValue that recognizes a single test flag
	// — we want to verify the walker, not any specific PM's flag list.
	takesValue := func(flag string) bool { return flag == "-w" || flag == "--workspace" }

	cases := []struct {
		name string
		argv []string
		want []PackageSpec
	}{
		{
			name: "single",
			argv: []string{"lodash"},
			want: []PackageSpec{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "skips short and long flags",
			argv: []string{"--save-dev", "lodash", "-D", "react"},
			want: []PackageSpec{
				{Name: "lodash", Raw: "lodash"},
				{Name: "react", Raw: "react"},
			},
		},
		{
			name: "consumes value for known flag",
			argv: []string{"-w", "frontend", "lodash"},
			want: []PackageSpec{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "long form with glued value passes through",
			argv: []string{"--workspace=frontend", "lodash"},
			// --workspace=frontend is treated as a flag and skipped (no
			// separate value); lodash remains.
			want: []PackageSpec{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "no positionals",
			argv: []string{"--save-dev", "--no-fund"},
			want: []PackageSpec{},
		},
		{
			name: "empty",
			argv: []string{},
			want: []PackageSpec{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseInstallArgsWith(c.argv, takesValue)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("ParseInstallArgsWith(%v):\n  got:  %#v\n  want: %#v", c.argv, got, c.want)
			}
		})
	}
}
