package npmregistry

import (
	"context"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Resolver adapts a Client to the usecase.VersionResolver port. It
// only knows how to talk to the npm registry, so it errors on any
// non-EcoNpm ecosystem rather than silently lying.
type Resolver struct{ c *Client }

// NewResolver builds a Resolver backed by a fresh Client.
func NewResolver(opts ...Option) *Resolver {
	return &Resolver{c: New(opts...)}
}

// Resolve implements usecase.VersionResolver.
func (r *Resolver) Resolve(ctx context.Context, eco domain.Ecosystem, name, rangeOrTag string) (string, error) {
	if eco != domain.EcoNpm {
		return "", fmt.Errorf("npmregistry: cannot resolve ecosystem %q", eco)
	}
	return r.c.Resolve(ctx, name, rangeOrTag)
}

// PublishedAt implements usecase.PublishedAtResolver. Returns the npm
// registry's `time[version]` value for a (name, version), or "" when
// the registry doesn't expose it. Errors propagate so the caller can
// log "skipped" without bubbling up.
func (r *Resolver) PublishedAt(ctx context.Context, eco domain.Ecosystem, name, version string) (string, error) {
	if eco != domain.EcoNpm {
		return "", fmt.Errorf("npmregistry: cannot resolve ecosystem %q", eco)
	}
	return r.c.PublishedAt(ctx, name, version)
}

// FetchMaintainerSignal implements usecase.MaintainerSignalFetcher.
// Returns a zero-value signal (no error) for non-npm ecosystems so
// the maintainer-hijack heuristic degrades gracefully on Python /
// Rust / Go / Ruby deps until those ecosystems get their own
// adapters. Lives on Resolver so the composition root has one
// object satisfying VersionResolver, PublishedAtResolver, and
// MaintainerSignalFetcher in one go.
func (r *Resolver) FetchMaintainerSignal(ctx context.Context, eco domain.Ecosystem, name, version string) (domain.MaintainerSignal, error) {
	if eco != domain.EcoNpm {
		return domain.MaintainerSignal{}, nil
	}
	sig, err := r.c.FetchMaintainerSignal(ctx, name, version)
	if err != nil {
		return domain.MaintainerSignal{}, err
	}
	return domain.MaintainerSignal{
		PublishedAt:         sig.PublishedAt,
		WeeklyDownloads:     sig.WeeklyDownloads,
		PreviousVersion:     sig.PreviousVersion,
		PreviousPublishedAt: sig.PreviousPublishedAt,
	}, nil
}
