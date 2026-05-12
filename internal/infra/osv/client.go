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
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
			// Defense in depth: OSV is trusted, but the ID flows
			// into URL paths (osv.dev/vulnerability/<id>) and
			// /v1/vulns/<id>. Reject anything outside the
			// documented GHSA-/CVE-/MAL- alphabet.
			if !isValidOSVID(v.ID) {
				continue
			}
			ids[i] = append(ids[i], v.ID)
		}
	}
	return ids, nil
}

// validOSVID matches the documented OSV ID alphabet: GHSA-xxxx-xxxx-xxxx,
// CVE-YYYY-NNNNN, MAL-YYYY-NNNN, plus a few ecosystem-specific
// prefixes that all use [A-Za-z0-9._:-].
var validOSVID = regexp.MustCompile(`^[A-Za-z0-9_.\-:]+$`)

func isValidOSVID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	return validOSVID.MatchString(id)
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

	if !isValidOSVID(id) {
		return domain.Advisory{}, fmt.Errorf("osv vuln: invalid id %q", id)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v1/vulns/"+url.PathEscape(id), nil)
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
	if !isValidOSVID(doc.ID) {
		return domain.Advisory{}, fmt.Errorf("osv vuln: invalid id %q in response", doc.ID)
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

// cvssBaseScore computes the CVSS v3.x base score from a vector string
// (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"). Returns -1
// when the vector is absent or unparseable.
func cvssBaseScore(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:") {
		return -1
	}
	parts := strings.Split(vector, "/")
	if len(parts) < 9 { // version + 8 base metrics
		return -1
	}
	m := make(map[string]string, len(parts)-1)
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return -1
		}
		m[k] = v
	}

	get := func(key string, table map[string]float64) (float64, bool) {
		v, ok := table[m[key]]
		return v, ok
	}

	av, ok := get("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20})
	if !ok {
		return -1
	}
	ac, ok := get("AC", map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return -1
	}
	ui, ok := get("UI", map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return -1
	}

	scope := m["S"]
	scopeChanged := scope == "C"
	if !scopeChanged && scope != "U" {
		return -1
	}

	var prVals map[string]float64
	if scopeChanged {
		prVals = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	} else {
		prVals = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	}
	pr, ok := get("PR", prVals)
	if !ok {
		return -1
	}

	impactVals := map[string]float64{"N": 0.00, "L": 0.22, "H": 0.56}
	conf, ok := get("C", impactVals)
	if !ok {
		return -1
	}
	integ, ok := get("I", impactVals)
	if !ok {
		return -1
	}
	avail, ok := get("A", impactVals)
	if !ok {
		return -1
	}

	iss := 1 - (1-conf)*(1-integ)*(1-avail)

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var raw float64
	if scopeChanged {
		raw = math.Min(1.08*(impact+exploitability), 10)
	} else {
		raw = math.Min(impact+exploitability, 10)
	}
	// CVSS roundup: smallest value to 1 decimal place >= input
	return math.Ceil(raw*10) / 10
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
	if err := os.MkdirAll(c.cacheDir, 0o700); err != nil {
		return // best-effort
	}
	raw, err := json.Marshal(adv)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(c.cacheDir, sanitizeID(id)+".json"), raw, 0o600)
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
