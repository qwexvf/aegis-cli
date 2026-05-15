// Package licensefetch provides a combined LicenseFetcher that dispatches
// to per-ecosystem registry clients.
package licensefetch

import (
	"context"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/cratesregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/npmregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/nugetregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/pypiregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/rubygemsregistry"
)

// Fetcher dispatches license lookups to per-ecosystem registry clients.
// Ecosystems without a configured client return "" silently.
type Fetcher struct {
	npm    *npmregistry.Client
	pypi   *pypiregistry.Client
	crates *cratesregistry.Client
	ruby   *rubygemsregistry.Client
	nuget  *nugetregistry.Client
}

// New creates a Fetcher. Any client may be nil; that ecosystem returns ""
// without an error, so license data degrades gracefully.
func New(
	npm *npmregistry.Client,
	pypi *pypiregistry.Client,
	crates *cratesregistry.Client,
	ruby *rubygemsregistry.Client,
	nuget *nugetregistry.Client,
) *Fetcher {
	return &Fetcher{npm: npm, pypi: pypi, crates: crates, ruby: ruby, nuget: nuget}
}

// FetchLicense implements usecase.LicenseFetcher.
func (f *Fetcher) FetchLicense(ctx context.Context, eco domain.Ecosystem, name, version string) (string, error) {
	switch eco {
	case domain.EcoNpm:
		if f.npm == nil {
			return "", nil
		}
		return f.npm.FetchLicense(ctx, name, version)
	case domain.EcoPyPI:
		if f.pypi == nil {
			return "", nil
		}
		return f.pypi.FetchLicense(ctx, name, version)
	case domain.EcoCrates:
		if f.crates == nil {
			return "", nil
		}
		return f.crates.FetchLicense(ctx, name, version)
	case domain.EcoRubyGems:
		if f.ruby == nil {
			return "", nil
		}
		return f.ruby.FetchLicense(ctx, name, version)
	case domain.EcoNuGet:
		if f.nuget == nil {
			return "", nil
		}
		return f.nuget.FetchLicense(ctx, name, version)
	default:
		return "", nil
	}
}
