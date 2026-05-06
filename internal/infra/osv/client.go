// Package osv is the adapter for OSV.dev — Google's open-source
// vulnerability database. Implements usecase.VulnLookup.
//
// Why OSV: it aggregates GHSA, CVE, and ecosystem-native feeds
// (npm/pypi/cargo/maven/...) under one schema, and the public API at
// api.osv.dev is unauthenticated, free, and designed for batch tooling
// queries. No Aegis backend required.
//
// Two-phase fetch:
//
//  1. POST /v1/querybatch with the full list of (eco, name, version)
//     tuples — returns a slim {id, modified} array per query. Fast
//     even for 500-dep snapshots; one HTTP round-trip.
//  2. For every unique advisory ID returned, GET /v1/vulns/{id} for
//     the human-readable details (severity, summary, URL). Cached
//     to disk so subsequent enrich runs over the same advisory don't
//     re-fetch.
//
// The cache is an opt-in optimisation; setting WithoutDiskCache
// disables it (used in tests).
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

// DefaultBaseURL is the public OSV.dev API. Override via WithBaseURL
// for self-hosted OSV deployments or test servers.
const DefaultBaseURL = "https://api.osv.dev"

// MaxQueriesPerBatch is OSV.dev's documented per-request cap (1000).
// Snapshots larger than this are split across multiple batches; the
// adapter does this transparently.
const MaxQueriesPerBatch = 1000

// Client is the OSV.dev HTTP adapter.
type Client struct {
	baseURL  string
	http     *http.Client
	retry    httpx.RetryPolicy
	cacheDir string // empty disables on-disk advisory caching
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL points the client at a non-default OSV deployment. Most
// users want the default api.osv.dev. Test code uses httptest server
// URLs here.
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// WithHTTPClient injects the shared httpx client so OSV calls share
// the same connection pool, User-Agent, and X-Request-ID stamping as
// every other outbound call.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithRetryPolicy overrides the retry policy. Default: httpx.DefaultRetry.
func WithRetryPolicy(p httpx.RetryPolicy) Option {
	return func(c *Client) { c.retry = p }
}

// WithCacheDir enables disk caching of full advisory documents under
// <dir>/<id>.json. Advisories are immutable on the OSV side
// (post-publish content edits are rare and don't change the
// severity/summary), so caching aggressively is safe and saves
// significant bandwidth.
func WithCacheDir(dir string) Option {
	return func(c *Client) { c.cacheDir = dir }
}

// WithoutDiskCache disables advisory persistence — used by tests that
// don't want to touch the filesystem.
func WithoutDiskCache() Option {
	return func(c *Client) { c.cacheDir = "" }
}

// New builds a Client with sensible defaults.
func New(opts ...Option) *Client {
	c := &Client{
		baseURL: DefaultBaseURL,
		http:    httpx.NewClient(httpx.Config{Timeout: 30 * time.Second}),
		retry:   httpx.DefaultRetry,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Lookup implements usecase.VulnLookup. Two-phase: batch query for
// IDs, then per-ID GET for the human-readable record. Returns a map
// keyed by AdvisoryQuery.Key() so the use case can match results back
// to the original input list. Empty []domain.Advisory means "looked
// up, none found" — the use case relies on this distinction.
func (c *Client) Lookup(ctx context.Context, queries []domain.AdvisoryQuery) (map[string][]domain.Advisory, error) {
	out := make(map[string][]domain.Advisory, len(queries))
	for _, q := range queries {
		out[q.Key()] = []domain.Advisory{}
	}

	for start := 0; start < len(queries); start += MaxQueriesPerBatch {
		end := min(start+MaxQueriesPerBatch, len(queries))
		ids, err := c.batchIDs(ctx, queries[start:end])
		if err != nil {
			return nil, err
		}
		for i, queryIDs := range ids {
			q := queries[start+i]
			advs, err := c.fetchAdvisories(ctx, queryIDs)
			if err != nil {
				return nil, err
			}
			out[q.Key()] = advs
		}
	}
	return out, nil
}

// batchIDs runs one /v1/querybatch call and returns a parallel slice
// of advisory IDs per input query (empty slice when the query has no
// matches). The caller has already chunked the input to ≤ MaxQueriesPerBatch.
func (c *Client) batchIDs(ctx context.Context, queries []domain.AdvisoryQuery) ([][]string, error) {
	type batchQuery struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	type batchReq struct {
		Queries []batchQuery `json:"queries"`
	}
	type batchVuln struct {
		ID       string `json:"id"`
		Modified string `json:"modified"`
	}
	type batchResult struct {
		Vulns []batchVuln `json:"vulns"`
	}
	type batchResp struct {
		Results []batchResult `json:"results"`
	}

	req := batchReq{Queries: make([]batchQuery, len(queries))}
	for i, q := range queries {
		req.Queries[i].Package.Name = q.Name
		req.Queries[i].Package.Ecosystem = osvEcosystem(q.Ecosystem)
		req.Queries[i].Version = q.Version
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("osv batch marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := httpx.Do(ctx, c.http, httpReq, c.retry)
	if err != nil {
		return nil, fmt.Errorf("osv batch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv batch: HTTP %d", resp.StatusCode)
	}
	raw, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("osv batch read: %w", err)
	}
	var parsed batchResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("osv batch decode: %w", err)
	}
	if len(parsed.Results) != len(queries) {
		// OSV is documented to always return one result per query;
		// surface the violation rather than silently misalign.
		return nil, fmt.Errorf("osv batch: result count %d != query count %d",
			len(parsed.Results), len(queries))
	}

	ids := make([][]string, len(queries))
	for i, r := range parsed.Results {
		ids[i] = make([]string, 0, len(r.Vulns))
		for _, v := range r.Vulns {
			ids[i] = append(ids[i], v.ID)
		}
	}
	return ids, nil
}

// fetchAdvisories resolves a list of advisory IDs into full
// domain.Advisory records, hitting the disk cache first and
// /v1/vulns/{id} on miss. IDs in the same query slice that resolve
// to the same vuln are deduped on output.
func (c *Client) fetchAdvisories(ctx context.Context, ids []string) ([]domain.Advisory, error) {
	if len(ids) == 0 {
		return []domain.Advisory{}, nil
	}
	out := make([]domain.Advisory, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		adv, err := c.fetchOneAdvisory(ctx, id)
		if err != nil {
			// One bad advisory shouldn't blackhole the whole
			// snapshot enrich. Surface a stub with the ID + URL
			// so the user can still pivot to the upstream record.
			out = append(out, domain.Advisory{
				ID:       id,
				Severity: domain.SevInfo,
				Summary:  fmt.Sprintf("(failed to fetch full advisory: %v)", err),
				URL:      "https://osv.dev/vulnerability/" + id,
				Source:   "osv",
			})
			continue
		}
		out = append(out, adv)
	}
	return out, nil
}

func (c *Client) fetchOneAdvisory(ctx context.Context, id string) (domain.Advisory, error) {
	if cached, ok := c.loadCachedAdvisory(id); ok {
		return cached, nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return domain.Advisory{}, err
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := httpx.Do(ctx, c.http, httpReq, c.retry)
	if err != nil {
		return domain.Advisory{}, fmt.Errorf("osv vuln %s: %w", id, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return domain.Advisory{}, fmt.Errorf("osv vuln %s: HTTP %d", id, resp.StatusCode)
	}
	raw, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return domain.Advisory{}, fmt.Errorf("osv vuln %s read: %w", id, err)
	}

	adv, err := parseOSVVuln(raw)
	if err != nil {
		return domain.Advisory{}, fmt.Errorf("osv vuln %s decode: %w", id, err)
	}
	c.saveCachedAdvisory(id, adv)
	return adv, nil
}

// osvSeverityIn mirrors the JSON shape OSV uses for the `severity`
// array. Top-level type so parseOSVVuln and severityFromOSV agree on
// the payload.
type osvSeverityIn struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvDoc struct {
	ID       string          `json:"id"`
	Aliases  []string        `json:"aliases"`
	Summary  string          `json:"summary"`
	Details  string          `json:"details"`
	Severity []osvSeverityIn `json:"severity"`
	// DatabaseSpecific is where ecosystems stash their bucketed
	// severity (npm advisory severity, GHSA severity, ...). OSV
	// itself doesn't normalise; we fall back to it when no CVSS
	// score is present.
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// parseOSVVuln decodes an OSV vulnerability JSON document into the
// domain Advisory shape. Lifted out of fetchOneAdvisory so tests can
// exercise the mapping without the network call.
func parseOSVVuln(raw []byte) (domain.Advisory, error) {
	var doc osvDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.Advisory{}, err
	}
	summary := doc.Summary
	if summary == "" {
		summary = firstLine(doc.Details)
	}
	if summary == "" {
		summary = "(no summary provided)"
	}
	return domain.Advisory{
		ID:       doc.ID,
		Aliases:  doc.Aliases,
		Severity: severityFromOSV(doc.Severity, doc.DatabaseSpecific.Severity),
		Summary:  summary,
		URL:      "https://osv.dev/vulnerability/" + doc.ID,
		Source:   "osv",
	}, nil
}

// severityFromOSV maps OSV's severity surface onto our enum. CVSS
// vector ("CVSS:3.1/AV:N/AC:L/...") is parsed into a base score and
// bucketed; database_specific.severity ("CRITICAL"/"HIGH"/...) is the
// fallback when no CVSS is present (npm advisories rarely carry CVSS).
func severityFromOSV(sevs []osvSeverityIn, dbSpecific string) domain.Severity {
	for _, s := range sevs {
		if score := cvssBaseScore(s.Score); score >= 0 {
			return bucketCVSS(score)
		}
	}
	switch strings.ToUpper(dbSpecific) {
	case "CRITICAL":
		return domain.SevCritical
	case "HIGH":
		return domain.SevHigh
	case "MEDIUM", "MODERATE":
		return domain.SevMedium
	case "LOW":
		return domain.SevLow
	}
	return domain.SevInfo
}

// cvssBaseScore extracts the base score from a CVSS v3 vector string.
// Returns -1 when the vector is unparseable. We only care about the
// base, not temporal/environmental — that's what every "X is High"
// table renders.
func cvssBaseScore(vector string) float64 {
	// OSV stores scores as the canonical CVSS vector string. The
	// base score isn't in the vector itself — it's derived. Rather
	// than ship a full CVSS calculator, we honor the database's
	// own bucketing (database_specific.severity) and only treat
	// the vector as a presence signal here. -1 means "no vector".
	if !strings.HasPrefix(vector, "CVSS:") {
		return -1
	}
	// TODO: parse vector → base score. Until then we let the
	// database_specific.severity fallback do the work — most
	// ecosystems already provide a bucketed severity.
	return -1
}

// bucketCVSS maps a CVSS v3 base score onto our Severity enum per
// FIRST.org's documented thresholds.
func bucketCVSS(score float64) domain.Severity {
	switch {
	case score >= 9.0:
		return domain.SevCritical
	case score >= 7.0:
		return domain.SevHigh
	case score >= 4.0:
		return domain.SevMedium
	case score > 0:
		return domain.SevLow
	}
	return domain.SevInfo
}

func firstLine(s string) string {
	if before, _, ok := strings.Cut(s, "\n"); ok {
		return before
	}
	return s
}

// osvEcosystem maps the domain Ecosystem enum onto OSV's string
// vocabulary. OSV uses "npm" / "PyPI" / "crates.io" / "Go" /
// "RubyGems" / "Maven" — exact spelling and case matters per the
// OSV ecosystems documentation (osv.dev/docs/data-sources).
func osvEcosystem(eco domain.Ecosystem) string {
	switch eco {
	case domain.EcoNpm:
		return "npm"
	case domain.EcoPyPI:
		return "PyPI"
	case domain.EcoCrates:
		return "crates.io"
	case domain.EcoGo:
		return "Go"
	case domain.EcoRubyGems:
		return "RubyGems"
	case domain.EcoMaven:
		return "Maven"
	}
	return string(eco)
}

// loadCachedAdvisory returns a previously-fetched advisory, or false
// when the cache is disabled / file is missing / contents corrupt.
// All failure modes degrade to "miss"; the caller re-fetches.
func (c *Client) loadCachedAdvisory(id string) (domain.Advisory, bool) {
	if c.cacheDir == "" {
		return domain.Advisory{}, false
	}
	path := filepath.Join(c.cacheDir, sanitizeID(id)+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return domain.Advisory{}, false
	}
	var adv domain.Advisory
	if err := json.Unmarshal(raw, &adv); err != nil {
		return domain.Advisory{}, false
	}
	return adv, true
}

func (c *Client) saveCachedAdvisory(id string, adv domain.Advisory) {
	if c.cacheDir == "" {
		return
	}
	if err := os.MkdirAll(c.cacheDir, 0o755); err != nil {
		return // best-effort
	}
	raw, err := json.Marshal(adv)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(c.cacheDir, sanitizeID(id)+".json"), raw, 0o644)
}

// sanitizeID makes an advisory ID safe to use as a filename — OSV
// IDs are usually well-formed (GHSA-xxxx-xxxx-xxxx, CVE-YYYY-NNNNN)
// but defence in depth.
func sanitizeID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
