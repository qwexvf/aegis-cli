package sbomcdx

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestPURL(t *testing.T) {
	cases := []struct {
		name string
		dep  domain.Dependency
		want string
	}{
		{"npm-bare", domain.Dependency{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21"}, "pkg:npm/lodash@4.17.21"},
		{"npm-scoped", domain.Dependency{Ecosystem: domain.EcoNpm, Name: "@types/node", Version: "20.0.0"}, "pkg:npm/%40types/node@20.0.0"},
		{"pypi", domain.Dependency{Ecosystem: domain.EcoPyPI, Name: "requests", Version: "2.31.0"}, "pkg:pypi/requests@2.31.0"},
		{"cargo", domain.Dependency{Ecosystem: domain.EcoCrates, Name: "serde", Version: "1.0.0"}, "pkg:cargo/serde@1.0.0"},
		{"golang", domain.Dependency{Ecosystem: domain.EcoGo, Name: "github.com/spf13/cobra", Version: "v1.8.0"}, "pkg:golang/github.com/spf13/cobra@v1.8.0"},
		{"maven", domain.Dependency{Ecosystem: domain.EcoMaven, Name: "com.google.guava:guava", Version: "33.0.0-jre"}, "pkg:maven/com.google.guava/guava@33.0.0-jre"},
		{"gem", domain.Dependency{Ecosystem: domain.EcoRubyGems, Name: "rails", Version: "7.1.0"}, "pkg:gem/rails@7.1.0"},
		{"composer", domain.Dependency{Ecosystem: domain.EcoPackagist, Name: "symfony/console", Version: "6.4.0"}, "pkg:composer/symfony/console@6.4.0"},
		{"nuget", domain.Dependency{Ecosystem: domain.EcoNuGet, Name: "Newtonsoft.Json", Version: "13.0.3"}, "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{"hex", domain.Dependency{Ecosystem: domain.EcoGleam, Name: "gleam_stdlib", Version: "0.42.0"}, "pkg:hex/gleam_stdlib@0.42.0"},
		{"neovim-plain", domain.Dependency{Ecosystem: domain.EcoNeovim, Name: "telescope.nvim", Version: "a4ed6831b7748a2ddc4e3d6207baf3df56cba6dd"}, "pkg:generic/telescope.nvim@a4ed6831b7748a2ddc4e3d6207baf3df56cba6dd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PURL(tc.dep)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestPURL_UnknownEcosystem(t *testing.T) {
	got := PURL(domain.Dependency{Ecosystem: "bogus", Name: "x", Version: "1"})
	if got != "" {
		t.Fatalf("expected empty for unknown eco, got %q", got)
	}
}
