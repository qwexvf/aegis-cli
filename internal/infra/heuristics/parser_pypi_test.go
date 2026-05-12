package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestPyPIParser(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string][]byte
		wantVCS bool
	}{
		{
			name: "requirements.txt git+https",
			files: map[string][]byte{
				"requirements.txt": []byte("requests==2.31.0\nevil @ git+https://github.com/attacker/evil\n"),
			},
			wantVCS: true,
		},
		{
			name: "pyproject.toml git dep",
			files: map[string][]byte{
				"pyproject.toml": []byte(`[project]
dependencies = ["evil @ git+https://github.com/attacker/evil"]
`),
			},
			wantVCS: true,
		},
		{
			name: "setup.cfg git dep",
			files: map[string][]byte{
				"setup.cfg": []byte("[options]\ninstall_requires =\n    evil @ git+https://github.com/attacker/evil\n"),
			},
			wantVCS: true,
		},
		{
			name: "comment line not matched",
			files: map[string][]byte{
				"requirements.txt": []byte("# evil @ git+https://github.com/attacker/evil\nrequests==2.31.0\n"),
			},
			wantVCS: false,
		},
		{
			name: "clean requirements",
			files: map[string][]byte{
				"requirements.txt": []byte("requests==2.31.0\nflask>=2.0\n"),
			},
			wantVCS: false,
		},
		{
			name: "non-dep file ignored",
			files: map[string][]byte{
				"docs/conf.py": []byte("# git+https://example.com/foo\n"),
			},
			wantVCS: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &pypiParser{}
			pkg := p.Parse("mylib", nil, domain.PackageSource{Files: tc.files})
			hasVCS := false
			for _, dep := range pkg.Deps {
				if dep.Source == DepSourceVCS {
					hasVCS = true
				}
			}
			if tc.wantVCS && !hasVCS {
				t.Error("want VCS dep, got none")
			}
			if !tc.wantVCS && hasVCS {
				t.Errorf("unexpected VCS dep: %v", pkg.Deps)
			}
		})
	}
}

func TestExtractPyPIDepName(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"evil @ git+https://github.com/attacker/evil", "evil"},
		{"git+https://github.com/attacker/evil", ""},
		{"  mylib @ git+https://...", "mylib"},
	}
	for _, tc := range cases {
		got := extractPyPIDepName(tc.line)
		if got != tc.want {
			t.Errorf("extractPyPIDepName(%q) = %q want %q", tc.line, got, tc.want)
		}
	}
}
