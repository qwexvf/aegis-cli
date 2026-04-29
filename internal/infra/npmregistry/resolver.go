package npmregistry

import (
	"context"
	"fmt"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
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
