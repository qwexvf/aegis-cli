package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestRubyParser(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string][]byte
		wantVCS bool
	}{
		{
			name: "Gemfile git: keyword",
			files: map[string][]byte{
				"Gemfile": []byte(`source "https://rubygems.org"
gem "evil", git: "https://github.com/attacker/evil"
`),
			},
			wantVCS: true,
		},
		{
			name: "Gemfile :git => hash rocket",
			files: map[string][]byte{
				"Gemfile": []byte(`gem "evil", :git => "https://github.com/attacker/evil"`),
			},
			wantVCS: true,
		},
		{
			name: "comment git dep not matched",
			files: map[string][]byte{
				"Gemfile": []byte(`# gem "evil", git: "https://github.com/attacker/evil"
gem "rails", "~> 7.0"
`),
			},
			wantVCS: false,
		},
		{
			name: "clean Gemfile",
			files: map[string][]byte{
				"Gemfile": []byte(`source "https://rubygems.org"
gem "rails", "~> 7.0"
gem "rspec", group: :test
`),
			},
			wantVCS: false,
		},
		{
			name: "gem name extracted",
			files: map[string][]byte{
				"Gemfile": []byte(`gem "mylib", git: "https://github.com/example/mylib"`),
			},
			wantVCS: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &rubyParser{}
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
