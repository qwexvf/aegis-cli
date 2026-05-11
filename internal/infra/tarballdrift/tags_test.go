package tarballdrift

import (
	"reflect"
	"slices"
	"testing"
)

func TestParseRepository(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{"shorthand owner/repo", "lodash/lodash", "lodash", "lodash", false},
		{"github: prefix", "github:facebook/react", "facebook", "react", false},
		{"https git+", "git+https://github.com/vuejs/core.git", "vuejs", "core", false},
		{"plain https with .git", "https://github.com/expressjs/express.git", "expressjs", "express", false},
		{"plain https no suffix", "https://github.com/vitejs/vite", "vitejs", "vite", false},
		{"ssh git@", "git@github.com:nuxt/nuxt.git", "nuxt", "nuxt", false},
		{"ssh url form", "git+ssh://git@github.com/owner/repo.git", "owner", "repo", false},
		{"gitlab → unsupported", "https://gitlab.com/owner/repo.git", "", "", true},
		{"empty", "", "", "", true},
		{"single segment", "owner-only", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, r, err := ParseRepository(RepositoryField{Raw: tc.raw})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if o != tc.wantOwner || r != tc.wantRepo {
				t.Errorf("got %s/%s, want %s/%s", o, r, tc.wantOwner, tc.wantRepo)
			}
		})
	}
}

func TestTagCandidates(t *testing.T) {
	got := TagCandidates("lodash", "4.17.21")
	want := []string{"v4.17.21", "4.17.21", "lodash@4.17.21", "lodash-v4.17.21", "lodash-4.17.21"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTagCandidates_ScopedPackage(t *testing.T) {
	got := TagCandidates("@nuxt/cli", "3.0.0")
	// scoped name is stripped to `cli` for monorepo-style tags (changesets default).
	wantContains := []string{"v3.0.0", "3.0.0", "@nuxt/cli@3.0.0", "cli@3.0.0", "cli-v3.0.0"}
	for _, w := range wantContains {
		if !slices.Contains(got, w) {
			t.Errorf("missing candidate %q in %v", w, got)
		}
	}
}

func TestTagCandidates_EmptyVersionReturnsNil(t *testing.T) {
	if got := TagCandidates("x", ""); got != nil {
		t.Errorf("expected nil for empty version, got %v", got)
	}
}

func TestLooksLikeVersion(t *testing.T) {
	cases := map[string]bool{
		"1.2.3":          true,
		"v1.2.3":         true,
		"1.2.3-beta.4":   true,
		"1.2.3+build123": true,
		"main":           false,
		"HEAD":           false,
		"":               false,
		"1.2":            false,
	}
	for in, want := range cases {
		if got := LooksLikeVersion(in); got != want {
			t.Errorf("LooksLikeVersion(%q)=%v want %v", in, got, want)
		}
	}
}
