package aegisapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

// Lookup implements usecase.VulnLookup against the Aegis API. It POSTs
// the batch of (ecosystem, name, version) tuples to
// /api/v1/vuln/lookup and returns advisories keyed by the same
// AdvisoryQuery.Key() the caller used.
//
// Wire format:
//
//	POST /api/v1/vuln/lookup
//	X-API-Key: <key>
//	Content-Type: application/json
//
//	{
//	  "queries": [
//	    {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
//	    ...
//	  ]
//	}
//
//	200 OK
//	{
//	  "results": [
//	    {
//	      "ecosystem": "npm",
//	      "name": "lodash",
//	      "version": "4.17.21",
//	      "advisories": [
//	        {
//	          "id": "GHSA-jvqj-7wpc-9bqp",
//	          "summary": "...",
//	          "severity": "high",
//	          "cvss_score": 7.5,
//	          "fixed_in": "4.17.21",
//	          "references": ["https://..."],
//	          "published": "2021-02-15T19:00:00Z"
//	        }
//	      ]
//	    },
//	    ...
//	  ]
//	}
//
// The response shape mirrors what infra/osv produces from OSV.dev's
// vulnerability records, so the rest of the pipeline is source-
// agnostic. Server side may sync from OSV + GHSA + npm advisories +
// custom curation; client doesn't care.
//
// Tuples with no known advisories MUST appear in `results` with an
// empty `advisories` slice (NOT omitted), per the VulnLookup contract.
func (c *Client) Lookup(ctx context.Context, queries []domain.AdvisoryQuery) (map[string][]domain.Advisory, error) {
	if len(queries) == 0 {
		return nil, nil
	}
	if c.apiKey == "" {
		return nil, fmt.Errorf("aegis api: AEGIS_API_KEY is required for vuln lookup")
	}

	type queryDTO struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Version   string `json:"version"`
	}
	dtos := make([]queryDTO, 0, len(queries))
	for _, q := range queries {
		dtos = append(dtos, queryDTO{
			Ecosystem: string(q.Ecosystem),
			Name:      q.Name,
			Version:   q.Version,
		})
	}

	body, err := json.Marshal(map[string]any{"queries": dtos})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/vuln/lookup", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return nil, fmt.Errorf("aegis api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("aegis api: 401 — check AEGIS_API_KEY")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("aegis api: vuln lookup returned %d", resp.StatusCode)
	}

	raw, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read vuln lookup: %w", err)
	}

	var wire vulnLookupResponse
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("decode vuln lookup: %w", err)
	}

	out := make(map[string][]domain.Advisory, len(queries))
	// Initialise every query key with an empty slice so consumers can
	// distinguish "looked up, none found" from "not yet looked up" per
	// the VulnLookup contract.
	for _, q := range queries {
		out[q.Key()] = []domain.Advisory{}
	}
	for _, r := range wire.Results {
		key := domain.AdvisoryQuery{
			Ecosystem: domain.Ecosystem(r.Ecosystem),
			Name:      r.Name,
			Version:   r.Version,
		}.Key()
		advs := make([]domain.Advisory, 0, len(r.Advisories))
		for _, a := range r.Advisories {
			advs = append(advs, a.toDomain())
		}
		out[key] = advs
	}
	return out, nil
}

type vulnLookupResponse struct {
	Results []vulnResultDTO `json:"results"`
}

type vulnResultDTO struct {
	Ecosystem  string        `json:"ecosystem"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	Advisories []advisoryDTO `json:"advisories"`
}

type advisoryDTO struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Summary  string   `json:"summary"`
	Severity string   `json:"severity"`
	URL      string   `json:"url,omitempty"`
}

func (a advisoryDTO) toDomain() domain.Advisory {
	return domain.Advisory{
		ID:       a.ID,
		Aliases:  a.Aliases,
		Severity: domain.Severity(a.Severity),
		Summary:  a.Summary,
		URL:      a.URL,
		Source:   "aegis",
	}
}
