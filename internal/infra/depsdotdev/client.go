// Package depsdotdev is the adapter for deps.dev (Google) —
// a dependency insight service that exposes advisory data alongside
// dependency graph and license information.
//
// API reference: https://docs.deps.dev/api/v3alpha/
//
// Two-phase fetch (mirrors the OSV adapter):
//
//  1. GET /systems/{system}/packages/{name}/versions/{version}
//     Returns a list of advisory keys for the exact version.
//  2. GET /advisories/{id} for each key — returns severity + summary.
//
// No auth required. Rate limits are generous for tooling use.
// Supported ecosystems: npm, pypi, cargo, go, maven, nuget.
// Unsupported (rubygems, packagist, gleam) are silently skipped.
package depsdotdev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

const defaultBaseURL = "https://api.deps.dev"

// Client is the deps.dev HTTP adapter.
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
		http:    httpx.NewClient(httpx.Config{Timeout: 30 * time.Second}),
		retry:   httpx.DefaultRetry,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Lookup implements usecase.VulnLookup.
func (c *Client) Lookup(ctx context.Context, queries []domain.AdvisoryQuery) (map[string][]domain.Advisory, error) {
	out := make(map[string][]domain.Advisory, len(queries))
	for _, q := range queries {
		out[q.Key()] = []domain.Advisory{}
	}
	for _, q := range queries {
		if ctx.Err() != nil {
			break
		}
		sys := depsSystem(q.Ecosystem)
		if sys == "" {
			continue // unsupported ecosystem
		}
		advs, err := c.fetchAdvisories(ctx, sys, q.Name, q.Version)
		if err != nil {
			// non-fatal: skip this package, continue with others
			continue
		}
		out[q.Key()] = advs
	}
	return out, nil
}

type versionResp struct {
	Version struct {
		AdvisoryKeys []struct {
			ID string `json:"id"`
		} `json:"advisoryKeys"`
		IsDeprecated     bool   `json:"isDeprecated"`
		DeprecatedReason string `json:"deprecatedReason"`
	} `json:"version"`
}

type advisoryResp struct {
	Advisory struct {
		AdvisoryKey struct {
			ID string `json:"id"`
		} `json:"advisoryKey"`
		URL      string `json:"url"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Aliases  []struct {
			ID string `json:"id"`
		} `json:"aliases"`
	} `json:"advisory"`
}

func (c *Client) fetchAdvisories(ctx context.Context, system, name, version string) ([]domain.Advisory, error) {
	endpoint := fmt.Sprintf("%s/v3alpha/systems/%s/packages/%s/versions/%s",
		c.baseURL,
		url.PathEscape(system),
		url.PathEscape(name),
		url.PathEscape(version),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return nil, fmt.Errorf("deps.dev version %s/%s@%s: %w", system, name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return []domain.Advisory{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deps.dev version %s/%s@%s: HTTP %d", system, name, version, resp.StatusCode)
	}
	raw, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return nil, err
	}
	var vr versionResp
	if err := json.Unmarshal(raw, &vr); err != nil {
		return nil, fmt.Errorf("deps.dev decode: %w", err)
	}

	out := make([]domain.Advisory, 0, len(vr.Version.AdvisoryKeys))
	for _, key := range vr.Version.AdvisoryKeys {
		adv, err := c.fetchOneAdvisory(ctx, key.ID)
		if err != nil {
			out = append(out, domain.Advisory{
				ID:       key.ID,
				Severity: domain.SevInfo,
				Summary:  fmt.Sprintf("(failed to fetch advisory details: %v)", err),
				Source:   "deps.dev",
			})
			continue
		}
		out = append(out, adv)
	}
	return out, nil
}

func (c *Client) fetchOneAdvisory(ctx context.Context, id string) (domain.Advisory, error) {
	endpoint := fmt.Sprintf("%s/v3alpha/advisories/%s", c.baseURL, url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.Advisory{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return domain.Advisory{}, fmt.Errorf("deps.dev advisory %s: %w", id, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return domain.Advisory{}, fmt.Errorf("deps.dev advisory %s: HTTP %d", id, resp.StatusCode)
	}
	raw, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return domain.Advisory{}, err
	}
	var ar advisoryResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		return domain.Advisory{}, fmt.Errorf("deps.dev advisory decode: %w", err)
	}
	a := ar.Advisory
	aliases := make([]string, 0, len(a.Aliases))
	for _, al := range a.Aliases {
		if al.ID != "" && al.ID != a.AdvisoryKey.ID {
			aliases = append(aliases, al.ID)
		}
	}
	return domain.Advisory{
		ID:       a.AdvisoryKey.ID,
		Aliases:  aliases,
		Severity: parseSeverity(a.Severity),
		Summary:  a.Title,
		URL:      a.URL,
		Source:   "deps.dev",
	}, nil
}

func parseSeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
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

// FetchDeprecated implements usecase.PackageHealthFetcher.
// Returns (deprecated, reason, nil) for supported ecosystems; (false, "", nil)
// for unsupported ones or 404s. Uses the same version endpoint as
// fetchAdvisories — connection reuse keeps the cost low.
func (c *Client) FetchDeprecated(ctx context.Context, eco domain.Ecosystem, name, version string) (bool, string, error) {
	sys := depsSystem(eco)
	if sys == "" {
		return false, "", nil
	}
	endpoint := fmt.Sprintf("%s/v3alpha/systems/%s/packages/%s/versions/%s",
		c.baseURL,
		url.PathEscape(sys),
		url.PathEscape(name),
		url.PathEscape(version),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return false, "", fmt.Errorf("deps.dev health %s/%s@%s: %w", sys, name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return false, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("deps.dev health %s/%s@%s: HTTP %d", sys, name, version, resp.StatusCode)
	}
	raw, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return false, "", err
	}
	var vr versionResp
	if err := json.Unmarshal(raw, &vr); err != nil {
		return false, "", fmt.Errorf("deps.dev health decode: %w", err)
	}
	return vr.Version.IsDeprecated, vr.Version.DeprecatedReason, nil
}

// depsSystem maps domain.Ecosystem to the deps.dev system name.
// Returns "" for unsupported ecosystems.
func depsSystem(eco domain.Ecosystem) string {
	switch eco {
	case domain.EcoNpm:
		return "npm"
	case domain.EcoPyPI:
		return "pypi"
	case domain.EcoCrates:
		return "cargo"
	case domain.EcoGo:
		return "go"
	case domain.EcoMaven:
		return "maven"
	case domain.EcoNuGet:
		return "nuget"
	}
	return ""
}
