package pmwrapper

import (
	"reflect"
	"testing"
)

func TestBun_IsInstallCommand(t *testing.T) {
	b := NewBun()
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"install"}, true},
		{[]string{"i"}, true},
		{[]string{"add"}, true},
		{[]string{"a"}, true},
		{[]string{"run", "dev"}, false},
		{[]string{"test"}, false},
		{[]string{"x", "create-react-app"}, false},
		{[]string{}, false},
	}
	for _, c := range cases {
		if got := b.IsInstallCommand(c.argv); got != c.want {
			t.Errorf("bun.IsInstallCommand(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

func TestBun_ParseInstallArgs(t *testing.T) {
	b := NewBun()
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
			name: "a alias with multiple",
			argv: []string{"a", "lodash", "react"},
			want: []SpecToken{
				{Name: "lodash", Raw: "lodash"},
				{Name: "react", Raw: "react"},
			},
		},
		{
			name: "skips dev/exact short flags",
			argv: []string{"add", "-d", "lodash", "-E", "react"},
			want: []SpecToken{
				{Name: "lodash", Raw: "lodash"},
				{Name: "react", Raw: "react"},
			},
		},
		{
			name: "consumes --filter value",
			argv: []string{"install", "--filter", "frontend", "lodash"},
			want: []SpecToken{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "consumes --registry value",
			argv: []string{"add", "--registry", "https://r.example.com", "lodash"},
			want: []SpecToken{{Name: "lodash", Raw: "lodash"}},
		},
		{
			name: "local path passthrough",
			argv: []string{"add", "./local-pkg"},
			want: []SpecToken{{Raw: "./local-pkg", NonRegistry: true}},
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
			got := b.ParseInstallArgs(c.argv)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("bun.ParseInstallArgs(%v):\n  got:  %#v\n  want: %#v", c.argv, got, c.want)
			}
		})
	}
}

func TestBun_NameAndEcosystem(t *testing.T) {
	b := NewBun()
	if b.Name() != "bun" {
		t.Errorf("Name() = %q, want %q", b.Name(), "bun")
	}
	if b.Ecosystem() != "npm" {
		t.Errorf("Ecosystem() = %q, want %q", b.Ecosystem(), "npm")
	}
}
