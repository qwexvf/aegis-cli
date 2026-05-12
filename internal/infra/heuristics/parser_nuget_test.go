package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestNuGetParser(t *testing.T) {
	t.Run("custom NuGet feed flagged as VCS", func(t *testing.T) {
		cfg := []byte(`<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="PrivateFeed" value="https://custom.feed.example.com/nuget/v3/index.json" />
  </packageSources>
</configuration>`)
		p := &nugetParser{}
		pkg := p.Parse("mylib", nil, domain.PackageSource{
			Files: map[string][]byte{"NuGet.Config": cfg},
		})
		if len(pkg.Deps) == 0 {
			t.Fatal("want dep for custom feed, got none")
		}
		if pkg.Deps[0].Source != DepSourceVCS {
			t.Errorf("source: got %v want DepSourceVCS", pkg.Deps[0].Source)
		}
	})

	t.Run("official nuget.org feed not flagged", func(t *testing.T) {
		cfg := []byte(`<configuration><packageSources>
  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
</packageSources></configuration>`)
		p := &nugetParser{}
		pkg := p.Parse("mylib", nil, domain.PackageSource{
			Files: map[string][]byte{"NuGet.Config": cfg},
		})
		if len(pkg.Deps) != 0 {
			t.Errorf("unexpected dep for official feed: %v", pkg.Deps)
		}
	})

	t.Run("HintPath in csproj becomes local dep", func(t *testing.T) {
		csproj := []byte(`<Project>
  <ItemGroup>
    <Reference Include="LocalLib">
      <HintPath>..\lib\LocalLib.dll</HintPath>
    </Reference>
  </ItemGroup>
</Project>`)
		p := &nugetParser{}
		pkg := p.Parse("myapp", nil, domain.PackageSource{
			Files: map[string][]byte{"MyApp.csproj": csproj},
		})
		if len(pkg.Deps) == 0 {
			t.Fatal("want local dep, got none")
		}
		if pkg.Deps[0].Source != DepSourceLocal {
			t.Errorf("source: got %v want DepSourceLocal", pkg.Deps[0].Source)
		}
	})
}
