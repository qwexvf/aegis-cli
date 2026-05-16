// Package epss queries the FIRST.org EPSS API for Exploit Prediction
// Scoring System probabilities. EPSS scores quantify how likely a CVE
// is to be exploited in the next 30 days based on threat intelligence
// signals — higher score = more dangerous in practice.
//
// API: https://api.first.org/data/v1/epss?cve=CVE-x,CVE-y
// No auth required. Batch up to 100 CVEs per request.
package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

const (
	defaultBaseURL  = "https://api.first.org"
	maxCVEsPerBatch = 100
)

// Client queries the FIRST.org EPSS API.
type Client struct {
	baseURL string
	http    *http.Client
	retry   httpx.RetryPolicy
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient injects the shared HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithBaseURL overrides the default base URL (for tests).
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// New returns a Client with sensible defaults.
func New(opts ...Option) *Client {
	c := &Client{
		baseURL: defaultBaseURL,
		http:    httpx.NewClient(httpx.Config{Timeout: 15 * time.Second}),
		retry:   httpx.DefaultRetry,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type epssResp struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// EnrichAdvisories fills EPSS and EPSSPercentile on advisories that
// carry a CVE ID (either as the primary ID or in Aliases). Advisories
// with no CVE alias are unchanged. Network errors degrade gracefully —
// the un-enriched advisories are returned rather than an error, so the
// caller's scan continues.
func (c *Client) EnrichAdvisories(ctx context.Context, advs []domain.Advisory) []domain.Advisory {
	// Build CVE → advisory index. One advisory may map to multiple CVEs
	// (rare), but we just take the first CVE alias found per advisory.
	cveIndex := make(map[string]int, len(advs)) // CVE ID → advisory index
	var cveIDs []string
	for i, a := range advs {
		cve := findCVEID(a)
		if cve == "" {
			continue
		}
		if _, dup := cveIndex[cve]; !dup {
			cveIDs = append(cveIDs, cve)
			cveIndex[cve] = i
		}
	}
	if len(cveIDs) == 0 {
		return advs
	}

	scores := c.fetchBatch(ctx, cveIDs)
	out := make([]domain.Advisory, len(advs))
	copy(out, advs)
	for cve, score := range scores {
		if idx, ok := cveIndex[cve]; ok {
			out[idx].EPSS = score.epss
			out[idx].EPSSPercentile = score.percentile
		}
	}
	return out
}

type epssScore struct {
	epss       float64
	percentile float64
}

func (c *Client) fetchBatch(ctx context.Context, cveIDs []string) map[string]epssScore {
	result := make(map[string]epssScore, len(cveIDs))
	for start := 0; start < len(cveIDs); start += maxCVEsPerBatch {
		end := min(start+maxCVEsPerBatch, len(cveIDs))
		batch := cveIDs[start:end]
		partial, err := c.fetchOneBatch(ctx, batch)
		if err != nil {
			continue // best-effort; remaining CVEs get no score
		}
		maps.Copy(result, partial)
	}
	return result
}

func (c *Client) fetchOneBatch(ctx context.Context, cveIDs []string) (map[string]epssScore, error) {
	url := fmt.Sprintf("%s/data/v1/epss?cve=%s", c.baseURL, strings.Join(cveIDs, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return nil, fmt.Errorf("epss batch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss batch: HTTP %d", resp.StatusCode)
	}
	raw, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("epss batch read: %w", err)
	}
	var parsed epssResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("epss batch decode: %w", err)
	}

	out := make(map[string]epssScore, len(parsed.Data))
	for _, d := range parsed.Data {
		epss, err := strconv.ParseFloat(d.EPSS, 64)
		if err != nil {
			continue // malformed entry; skip rather than store 0.0
		}
		pct, err := strconv.ParseFloat(d.Percentile, 64)
		if err != nil {
			continue
		}
		out[d.CVE] = epssScore{epss: epss, percentile: pct}
	}
	return out, nil
}

// findCVEID returns the CVE ID from the advisory, checking the primary
// ID first then Aliases. Returns "" when no CVE ID is present.
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
