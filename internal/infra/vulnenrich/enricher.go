// Package vulnenrich composes post-lookup advisory enrichment:
// EPSS probability scores (FIRST.org) and KEV catalog membership (CISA).
// Implements usecase.AdvisoryEnricher.
package vulnenrich

import (
	"context"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/epss"
	"github.com/qwexvf/aegis-cli/internal/infra/kev"
)

// Enricher fills EPSS scores and KEV membership onto advisories that
// carry CVE IDs. Non-CVE advisories (pure GHSA, MAL-…) are unchanged.
type Enricher struct {
	epssClient *epss.Client
	kevCatalog *kev.Catalog
}

// NewWithClients constructs an Enricher from pre-built sub-clients.
// The preferred constructor at the composition root where the shared
// http.Client and cache directories are already known.
func NewWithClients(epssClient *epss.Client, kevCatalog *kev.Catalog) *Enricher {
	return &Enricher{epssClient: epssClient, kevCatalog: kevCatalog}
}

// Enrich implements usecase.AdvisoryEnricher. Fills EPSS + InKEV on
// advisories that have a CVE alias. Best-effort: network failures
// leave the advisory unchanged.
func (e *Enricher) Enrich(ctx context.Context, advs []domain.Advisory) []domain.Advisory {
	enriched := e.epssClient.EnrichAdvisories(ctx, advs)
	for i := range enriched {
		cve := findCVEID(enriched[i])
		if cve == "" {
			continue
		}
		enriched[i].InKEV = e.kevCatalog.IsKEV(ctx, cve)
	}
	return enriched
}

func findCVEID(a domain.Advisory) string {
	if strings.HasPrefix(a.ID, "CVE-") {
		return a.ID
	}
	for _, alias := range a.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return ""
}
