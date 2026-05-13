// Package licensefetch provides a combined LicenseFetcher that dispatches
// to per-ecosystem registry clients.
package licensefetch

import (
	"context"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/npmregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/pypiregistry"
)

// Fetcher dispatches license lookups to per-ecosystem registry clients.
// Ecosystems without a configured client return "" silently.
type Fetcher struct {
	npm  *npmregistry.Client
	pypi *pypiregistry.Client
}

// New creates a Fetcher with the given ecosystem clients. Either may be nil.
func New(npm *npmregistry.Client, pypi *pypiregistry.Client) *Fetcher {
	return &Fetcher{npm: npm, pypi: pypi}
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
	default:
		return "", nil
	}
}
