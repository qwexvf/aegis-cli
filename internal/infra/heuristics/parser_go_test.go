package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestGoRetract(t *testing.T) {
	t.Run("retracted version triggers CapVersionUnpublished", func(t *testing.T) {
		gomod := `module example.com/mymod
go 1.22
retract v1.0.0 // security vulnerability
`
		pkg := NormalizedPackage{
			Eco:     domain.EcoGo,
			Version: "v1.0.0",
			RetractedVersions: func() []string {
				p := &goParser{}
				n := p.Parse("example.com/mymod", nil, domain.PackageSource{
					Files: map[string][]byte{"go.mod": []byte(gomod)},
				})
				return n.RetractedVersions
			}(),
		}
		got := checkGoRetract(pkg)
		if !hasCap(got, domain.CapVersionUnpublished) {
			t.Errorf("want CapVersionUnpublished for retracted v1.0.0, got %v", got)
		}
	})

	t.Run("non-retracted version does not fire", func(t *testing.T) {
		gomod := `module example.com/mymod
go 1.22
retract v1.0.0
`
		p := &goParser{}
		n := p.Parse("example.com/mymod", nil, domain.PackageSource{
			Files: map[string][]byte{"go.mod": []byte(gomod)},
		})
		n.Version = "v1.1.0" // different from retracted v1.0.0
		got := checkGoRetract(n)
		if hasCap(got, domain.CapVersionUnpublished) {
			t.Errorf("v1.1.0 is not retracted, should not fire")
		}
	})

	t.Run("no version set is no-op", func(t *testing.T) {
		pkg := NormalizedPackage{
			Eco:               domain.EcoGo,
			RetractedVersions: []string{"v1.0.0"},
			// Version intentionally empty
		}
		if got := checkGoRetract(pkg); len(got) != 0 {
			t.Errorf("no version set should be no-op, got %v", got)
		}
	})

	t.Run("range retract fires when version in range", func(t *testing.T) {
		gomod := `module example.com/mymod
go 1.22
retract [v1.0.0, v1.2.0] // affected range
`
		p := &goParser{}
		n := p.Parse("example.com/mymod", nil, domain.PackageSource{
			Files: map[string][]byte{"go.mod": []byte(gomod)},
		})
		n.Version = "v1.1.0" // inside [v1.0.0, v1.2.0]
		got := checkGoRetract(n)
		if !hasCap(got, domain.CapVersionUnpublished) {
			t.Errorf("v1.1.0 in range [v1.0.0, v1.2.0]: want CapVersionUnpublished, got %v", got)
		}
	})

	t.Run("range retract does not fire when version above range", func(t *testing.T) {
		gomod := `module example.com/mymod
go 1.22
retract [v1.0.0, v1.2.0]
`
		p := &goParser{}
		n := p.Parse("example.com/mymod", nil, domain.PackageSource{
			Files: map[string][]byte{"go.mod": []byte(gomod)},
		})
		n.Version = "v1.3.0"
		if got := checkGoRetract(n); hasCap(got, domain.CapVersionUnpublished) {
			t.Errorf("v1.3.0 above range should not fire")
		}
	})

	t.Run("block-form retract single versions", func(t *testing.T) {
		gomod := `module example.com/mymod
go 1.22
retract (
	v1.0.0 // first bad version
	v1.1.0 // second bad version
)
`
		p := &goParser{}
		n := p.Parse("example.com/mymod", nil, domain.PackageSource{
			Files: map[string][]byte{"go.mod": []byte(gomod)},
		})
		n.Version = "v1.1.0"
		got := checkGoRetract(n)
		if !hasCap(got, domain.CapVersionUnpublished) {
			t.Errorf("block-form retract v1.1.0: want CapVersionUnpublished, got %v", got)
		}
	})

	t.Run("block-form retract range", func(t *testing.T) {
		gomod := `module example.com/mymod
go 1.22
retract (
	[v1.2.0, v1.4.0] // range in block
)
`
		p := &goParser{}
		n := p.Parse("example.com/mymod", nil, domain.PackageSource{
			Files: map[string][]byte{"go.mod": []byte(gomod)},
		})
		n.Version = "v1.3.0"
		got := checkGoRetract(n)
		if !hasCap(got, domain.CapVersionUnpublished) {
			t.Errorf("block-form retract range [v1.2.0, v1.4.0]: want CapVersionUnpublished for v1.3.0, got %v", got)
		}
	})

	t.Run("via Run() pipeline with matching version", func(t *testing.T) {
		gomod := `module example.com/vuln
go 1.22
retract v2.0.0
`
		src := domain.PackageSource{
			Files: map[string][]byte{"go.mod": []byte(gomod)},
		}
		caps := Run(domain.EcoGo, "example.com/vuln", "v2.0.0", nil, src)
		if !hasCap(caps, domain.CapVersionUnpublished) {
			t.Errorf("Run() with retracted version: want CapVersionUnpublished, got %v", caps)
		}
	})
}

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
