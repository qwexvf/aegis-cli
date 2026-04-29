package wrap

import (
	"reflect"
	"testing"
)

func TestIsInstallSubcommand(t *testing.T) {
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"install"}, true},
		{[]string{"i"}, true},
		{[]string{"add"}, true},
		{[]string{"isntall"}, true},
		{[]string{"test"}, false},
		{[]string{}, false},
		{[]string{"--version"}, false},
	}
	for _, c := range cases {
		if got := IsInstallSubcommand(c.argv); got != c.want {
			t.Errorf("IsInstallSubcommand(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

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
		{"4", false}, // missing dots — treat as a tag-ish, not exact
	}
	for _, c := range cases {
		got := PackageSpec{Version: c.version}.IsExactVersion()
		if got != c.want {
			t.Errorf("IsExactVersion(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestParseInstallArgs(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want []PackageSpec
	}{
		{
			name: "single package no version",
			argv: []string{"lodash"},
			want: []PackageSpec{{Name: "lodash", Version: "", Raw: "lodash"}},
		},
		{
			name: "single package with version",
			argv: []string{"lodash@4.17.21"},
			want: []PackageSpec{{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}},
		},
		{
			name: "single package with range",
			argv: []string{"lodash@^4.17.0"},
			want: []PackageSpec{{Name: "lodash", Version: "^4.17.0", Raw: "lodash@^4.17.0"}},
		},
		{
			name: "tag",
			argv: []string{"lodash@latest"},
			want: []PackageSpec{{Name: "lodash", Version: "latest", Raw: "lodash@latest"}},
		},
		{
			name: "scoped package no version",
			argv: []string{"@bitwarden/cli"},
			want: []PackageSpec{{Name: "@bitwarden/cli", Version: "", Raw: "@bitwarden/cli"}},
		},
		{
			name: "scoped package with version",
			argv: []string{"@bitwarden/cli@2026.4.0"},
			want: []PackageSpec{{Name: "@bitwarden/cli", Version: "2026.4.0", Raw: "@bitwarden/cli@2026.4.0"}},
		},
		{
			name: "multiple packages with flags interleaved",
			argv: []string{"lodash", "--save-dev", "express@4", "-w", "frontend", "react"},
			want: []PackageSpec{
				{Name: "lodash", Raw: "lodash"},
				{Name: "express", Version: "4", Raw: "express@4"},
				{Name: "react", Raw: "react"},
			},
		},
		{
			name: "tarball url passes through",
			argv: []string{"https://github.com/foo/bar/archive/v1.tgz"},
			want: []PackageSpec{{Raw: "https://github.com/foo/bar/archive/v1.tgz", NonRegistry: true}},
		},
		{
			name: "local path passes through",
			argv: []string{"./vendor/foo"},
			want: []PackageSpec{{Raw: "./vendor/foo", NonRegistry: true}},
		},
		{
			name: "github shorthand passes through",
			argv: []string{"github:lodash/lodash"},
			want: []PackageSpec{{Raw: "github:lodash/lodash", NonRegistry: true}},
		},
		{
			name: "no positional args",
			argv: []string{"--save-dev", "--no-fund"},
			want: []PackageSpec{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseInstallArgs(c.argv)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("ParseInstallArgs(%v):\n  got:  %#v\n  want: %#v", c.argv, got, c.want)
			}
		})
	}
}
