package pmwrapper

import (
	"reflect"
	"testing"
)

// IsExactVersion lives on domain.PackageSpec — see domain/policy_test.go.

func TestParseSpec(t *testing.T) {
	cases := []struct {
		token string
		want  SpecToken
	}{
		{"lodash", SpecToken{Name: "lodash", Raw: "lodash"}},
		{"lodash@4.17.21", SpecToken{Name: "lodash", Version: "4.17.21", Raw: "lodash@4.17.21"}},
		{"lodash@^4.17.0", SpecToken{Name: "lodash", Version: "^4.17.0", Raw: "lodash@^4.17.0"}},
		{"lodash@latest", SpecToken{Name: "lodash", Version: "latest", Raw: "lodash@latest"}},
		{"@bitwarden/cli", SpecToken{Name: "@bitwarden/cli", Raw: "@bitwarden/cli"}},
		{"@bitwarden/cli@2026.4.0", SpecToken{Name: "@bitwarden/cli", Version: "2026.4.0", Raw: "@bitwarden/cli@2026.4.0"}},
		// Non-registry forms
		{"./vendor/foo", SpecToken{Raw: "./vendor/foo", NonRegistry: true}},
		{"https://github.com/foo/bar/archive/v1.tgz", SpecToken{Raw: "https://github.com/foo/bar/archive/v1.tgz", NonRegistry: true}},
		{"github:lodash/lodash", SpecToken{Raw: "github:lodash/lodash", NonRegistry: true}},
		{"file:./local", SpecToken{Raw: "file:./local", NonRegistry: true}},
		{"git+https://github.com/x/y.git", SpecToken{Raw: "git+https://github.com/x/y.git", NonRegistry: true}},
		// Yarn berry / bun protocols
		{"link:../sibling", SpecToken{Raw: "link:../sibling", NonRegistry: true}},
		{"workspace:*", SpecToken{Raw: "workspace:*", NonRegistry: true}},
		{"patch:lodash@4.17.21#./fix.patch", SpecToken{Raw: "patch:lodash@4.17.21#./fix.patch", NonRegistry: true}},
		{"portal:./pkg", SpecToken{Raw: "portal:./pkg", NonRegistry: true}},
		{"npm:@types/lodash@^4", SpecToken{Raw: "npm:@types/lodash@^4", NonRegistry: true}},
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
		want []SpecToken
	}{
		{
			name: "single",
			argv: []string{"lodash"},
			want: []SpecToken{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "skips short and long flags",
			argv: []string{"--save-dev", "lodash", "-D", "react"},
			want: []SpecToken{
				{Name: "lodash", Raw: "lodash"},
				{Name: "react", Raw: "react"},
			},
		},
		{
			name: "consumes value for known flag",
			argv: []string{"-w", "frontend", "lodash"},
			want: []SpecToken{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "long form with glued value passes through",
			argv: []string{"--workspace=frontend", "lodash"},
			// --workspace=frontend is treated as a flag and skipped (no
			// separate value); lodash remains.
			want: []SpecToken{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "no positionals",
			argv: []string{"--save-dev", "--no-fund"},
			want: []SpecToken{},
		},
		{
			name: "empty",
			argv: []string{},
			want: []SpecToken{},
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
