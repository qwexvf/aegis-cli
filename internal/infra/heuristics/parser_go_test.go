package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestGoParser(t *testing.T) {
	cases := []struct {
		name      string
		gomod     string
		wantVCS   bool
		wantLocal bool
	}{
		{
			name: "external replace flagged as VCS",
			gomod: `module example.com/mymod
go 1.22
require example.com/foo v1.0.0
replace example.com/foo => github.com/attacker/foo v1.0.0
`,
			wantVCS: true,
		},
		{
			name: "local replace flagged as Local",
			gomod: `module example.com/mymod
go 1.22
replace example.com/foo => ./local/foo
`,
			wantLocal: true,
		},
		{
			name: "block replace mixed",
			gomod: `module example.com/mymod
go 1.22
replace (
	example.com/a => github.com/evil/a v0.0.1
	example.com/b => ../sibling/b
)
`,
			wantVCS:   true,
			wantLocal: true,
		},
		{
			name: "clean module no replace",
			gomod: `module example.com/mymod
go 1.22
require (
	github.com/spf13/cobra v1.8.0
)
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &goParser{}
			pkg := p.Parse("example.com/mymod", nil, domain.PackageSource{
				Files: map[string][]byte{"go.mod": []byte(tc.gomod)},
			})
			hasVCS, hasLocal := false, false
			for _, dep := range pkg.Deps {
				if dep.Source == DepSourceVCS {
					hasVCS = true
				}
				if dep.Source == DepSourceLocal {
					hasLocal = true
				}
			}
			if tc.wantVCS && !hasVCS {
				t.Error("want VCS dep, got none")
			}
			if !tc.wantVCS && hasVCS {
				t.Errorf("unexpected VCS dep: %v", pkg.Deps)
			}
			if tc.wantLocal && !hasLocal {
				t.Error("want Local dep, got none")
			}
		})
	}
}
