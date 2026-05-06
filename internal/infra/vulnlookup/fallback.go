// Package vulnlookup provides composition helpers around the
// usecase.VulnLookup interface so callers can stack multiple sources
// (Aegis API + OSV.dev) without the use-case layer caring how many
// upstreams there are.
//
// The default policy: try the primary source first, fall through to
// the secondary on error. There is no merging — the first successful
// response wins, so the secondary acts purely as a backstop. This
// matches what callers actually want for a "free fallback when the
// curated feed is down" deployment.
package vulnlookup

import (
	"context"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// Fallback is a usecase.VulnLookup that tries Primary first, and
// returns Secondary's result on error. nil entries are skipped — a
// Fallback with both nils returns (nil, nil) like an empty lookup.
//
// Callers attach a Logger if they want to know which source actually
// answered; default is silent.
type Fallback struct {
	Primary, Secondary usecase.VulnLookup
	Logger             func(format string, args ...any) // optional
}

// Lookup implements usecase.VulnLookup.
func (f Fallback) Lookup(ctx context.Context, queries []domain.AdvisoryQuery) (map[string][]domain.Advisory, error) {
	if f.Primary == nil && f.Secondary == nil {
		return nil, nil
	}
	if f.Primary == nil {
		return f.Secondary.Lookup(ctx, queries)
	}
	out, err := f.Primary.Lookup(ctx, queries)
	if err == nil {
		return out, nil
	}
	if f.Secondary == nil {
		return nil, err
	}
	if f.Logger != nil {
		f.Logger("vulnlookup: primary failed (%v); falling back to secondary", err)
	}
	out2, err2 := f.Secondary.Lookup(ctx, queries)
	if err2 != nil {
		return nil, fmt.Errorf("primary: %w; secondary: %v", err, err2)
	}
	return out2, nil
}
