// Package aegisapi is the HTTP adapter for the Aegis supply-chain
// API. It satisfies usecase.DecisionChecker by translating the wire
// JSON shape into domain.Decision values.
package aegisapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/httpx"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

// DefaultURL is the default Aegis API base URL. Override with AEGIS_API_URL.
const DefaultURL = "http://localhost:4000"

// Client is the Aegis API HTTP client.
type Client struct {
	baseURL string
	http    *http.Client
	apiKey  string
	retry   httpx.RetryPolicy
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey attaches a server-issued submit API key to the client.
// The key travels via the X-API-Key header on endpoints that require
// it (currently only the report-submit POST). An empty key is a
// no-op — the request still goes out and the API returns 401, which
// the existing CLI error path surfaces as "submit failed: HTTP 401".
func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = key }
}

// WithHTTPClient overrides the underlying *http.Client. Tests inject
// httptest-backed clients here; the composition root passes a shared
// httpx.NewClient so all outbound calls share connection pooling and
// header injection.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithRetryPolicy overrides the retry policy used by Check/Submit.
// Default: httpx.DefaultRetry (4 attempts with backoff). Pass
// httpx.NoRetry to disable.
func WithRetryPolicy(p httpx.RetryPolicy) Option {
	return func(c *Client) { c.retry = p }
}

// New builds a Client with sensible defaults. Reads AEGIS_API_URL from
// the environment if set, otherwise uses DefaultURL. Options layer
// on top.
func New(opts ...Option) *Client {
	base := os.Getenv("AEGIS_API_URL")
	if base == "" {
		base = DefaultURL
	}
	c := &Client{
		baseURL: strings.TrimRight(base, "/"),
		http:    httpx.NewClient(httpx.Config{}),
		retry:   httpx.DefaultRetry,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// BaseURL returns the configured API base. Used by `aegis doctor`
// for diagnostic output ("which endpoint did we just probe?").
func (c *Client) BaseURL() string { return c.baseURL }

// Ping does a cheap reachability check against the API. It HEADs the
// /check endpoint — most servers reply with 405 (Method Not Allowed)
// to a HEAD on a POST route, which is a perfectly fine "I'm alive"
// signal. Returns nil if the connection succeeded with any HTTP
// status; the caller can decide whether 5xx counts as healthy.
func (c *Client) Ping(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead,
		c.baseURL+"/api/v1/supply-chain/check", nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("ping %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// Check implements usecase.DecisionChecker. It posts a supply-chain
// check request, decodes the response DTO, and translates to a domain
// Decision (Spec/Resolved/Source are filled by the use case).
func (c *Client) Check(ctx context.Context, eco domain.Ecosystem, pkg, version string) (domain.Decision, error) {
	body, err := json.Marshal(map[string]string{
		"ecosystem": string(eco),
		"package":   pkg,
		"version":   version,
	})
	if err != nil {
		return domain.Decision{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/supply-chain/check", bytes.NewReader(body))
	if err != nil {
		return domain.Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return domain.Decision{}, fmt.Errorf("aegis api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return domain.Decision{}, fmt.Errorf("aegis api: returned %d", resp.StatusCode)
	}

	var dto decisionDTO
	body, err = httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return domain.Decision{}, fmt.Errorf("read decision: %w", err)
	}
	if err := json.Unmarshal(body, &dto); err != nil {
		return domain.Decision{}, fmt.Errorf("decode decision: %w", err)
	}
	return dto.toDomain(), nil
}

// decisionDTO is the wire shape returned by /api/v1/supply-chain/check.
// Lives inside the adapter so the rest of the codebase never sees JSON
// tags on a domain type.
type decisionDTO struct {
	Decision     string      `json:"decision"`
	Severity     string      `json:"severity"`
	Reasons      []reasonDTO `json:"reasons"`
	AdvisoryID   string      `json:"advisory_id,omitempty"`
	IncidentDate string      `json:"incident_date,omitempty"`
	Summary      string      `json:"summary,omitempty"`
	References   []string    `json:"references,omitempty"`
}

type reasonDTO struct {
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

// FetchAllowlist implements allowlist.AllowlistFetcher. Pulls the
// org-wide allowlist YAML from the API. The server uses the X-API-Key
// header to identify the org — there's no orgId parameter.
//
// Returns the raw YAML bytes; the caller (ServerLoader) validates +
// persists. Caps the response at httpx.MaxYAMLResponseBytes so a
// hostile or runaway server can't fill the user's disk.
func (c *Client) FetchAllowlist(ctx context.Context) ([]byte, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("aegis api: AEGIS_API_KEY is required for allowlist sync")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/api/v1/allowlist", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/yaml")
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return nil, fmt.Errorf("aegis api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("aegis api: 401 — check AEGIS_API_KEY")
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("aegis api: 403 — key is not org-scoped (re-issue from /admin?tab=api-keys)")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("aegis api: returned %d", resp.StatusCode)
	}

	body, err := httpx.ReadCapped(resp.Body, httpx.MaxYAMLResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	return body, nil
}

// SubmitReport implements usecase.ReportSubmitter. Posts a community
// report to /api/v1/supply-chain/reports and returns the API's ack.
func (c *Client) SubmitReport(ctx context.Context, r usecase.PackageReportRequest) (usecase.PackageReportAck, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return usecase.PackageReportAck{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/supply-chain/reports", bytes.NewReader(body))
	if err != nil {
		return usecase.PackageReportAck{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return usecase.PackageReportAck{}, fmt.Errorf("aegis api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return usecase.PackageReportAck{}, fmt.Errorf("aegis api: report submit returned %d", resp.StatusCode)
	}

	var ack usecase.PackageReportAck
	body, err = httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return usecase.PackageReportAck{}, fmt.Errorf("read ack: %w", err)
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return usecase.PackageReportAck{}, fmt.Errorf("decode ack: %w", err)
	}
	return ack, nil
}

func (d decisionDTO) toDomain() domain.Decision {
	out := domain.Decision{
		Kind:     domain.DecisionKind(d.Decision),
		Severity: domain.Severity(d.Severity),
	}
	if len(d.Reasons) > 0 {
		out.Reasons = make([]domain.Reason, len(d.Reasons))
		for i, r := range d.Reasons {
			out.Reasons[i] = domain.Reason{Category: r.Category, Detail: r.Detail}
		}
	}
	if d.AdvisoryID != "" || d.IncidentDate != "" || d.Summary != "" || len(d.References) > 0 {
		out.Incident = &domain.Incident{
			AdvisoryID: d.AdvisoryID,
			Date:       d.IncidentDate,
			Summary:    d.Summary,
			References: filterValidURLs(d.References),
		}
	}
	return out
}

// filterValidURLs drops any reference that isn't an http(s) URL. The
// API is trusted, but advisories arrive at it from third-party sources
// (GHSA, OSV, internal feeds); refusing to surface non-URL strings to
// users keeps the audit log and presenter free of injected payloads.
func filterValidURLs(refs []string) []string {
	if len(refs) == 0 {
		return nil
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		u, err := url.Parse(r)
		if err != nil {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		if u.Host == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}
