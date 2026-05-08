// Package ghsalookup is the adapter for the GitHub Advisory Database
// REST API (api.github.com/advisories). Implements usecase.VulnLookup.
//
// Why GitHub Advisory direct (given OSV already aggregates GHSA):
//   - Freshness: new advisories appear on GitHub hours before OSV
//     picks them up via its hourly sync.
//   - Coverage: GitHub publishes GHSA records not yet in OSV's index.
//
// API: GET /advisories?affects={eco}/{name}&per_page=100
// The response lists advisories that affect the named package. We then
// check each advisory's affected version ranges against the queried
// version using semver — only ranges that match are returned.
//
// Auth: optional GitHub personal access token (public_repo scope).
// Without a token the API is rate-limited to 60 req/hour; with one
// it's 5000/hour. Set via config token or GITHUB_TOKEN env var.
package ghsalookup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

const defaultBaseURL = "https://api.github.com"

// Client is the GitHub Advisory Database HTTP adapter.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
	retry   httpx.RetryPolicy
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient injects the shared HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithToken sets the GitHub personal access token for higher rate limits.
func WithToken(token string) Option {
	return func(c *Client) { c.token = token }
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

	// Group queries by (ecosystem, package) to avoid redundant API
	// calls when multiple versions of the same package are in the
	// snapshot.
	type ecoName struct{ eco, name string }
	byPkg := make(map[ecoName][]domain.AdvisoryQuery)
	for _, q := range queries {
		if ghsaEco(q.Ecosystem) == "" {
			continue
		}
		key := ecoName{string(q.Ecosystem), q.Name}
		byPkg[key] = append(byPkg[key], q)
	}

	for key, qs := range byPkg {
		eco := domain.Ecosystem(key.eco)
		advisories, err := c.fetchForPackage(ctx, eco, key.name)
		if err != nil {
			continue // non-fatal
		}
		for _, q := range qs {
			matched := filterByVersion(advisories, q.Version)
			out[q.Key()] = matched
		}
	}
	return out, nil
}

type ghsaAdvisory struct {
	GHSAID          string `json:"ghsa_id"`
	CVEID           string `json:"cve_id"`
	Summary         string `json:"summary"`
	Severity        string `json:"severity"`
	HTMLURL         string `json:"html_url"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    string `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

func (c *Client) fetchForPackage(ctx context.Context, eco domain.Ecosystem, name string) ([]ghsaAdvisory, error) {
	ghEco := ghsaEco(eco)
	if ghEco == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("%s/advisories?affects=%s/%s&per_page=100",
		c.baseURL,
		url.PathEscape(ghEco),
		url.PathEscape(name),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := httpx.Do(ctx, c.http, req, c.retry)
	if err != nil {
		return nil, fmt.Errorf("ghsa %s/%s: %w", ghEco, name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ghsa %s/%s: HTTP %d", ghEco, name, resp.StatusCode)
	}
	raw, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return nil, err
	}
	var advs []ghsaAdvisory
	if err := json.Unmarshal(raw, &advs); err != nil {
		return nil, fmt.Errorf("ghsa decode: %w", err)
	}
	return advs, nil
}

// filterByVersion returns only advisories whose vulnerable version
// range contains the queried version. Advisories with an unparseable
// or empty range are included conservatively.
func filterByVersion(advs []ghsaAdvisory, version string) []domain.Advisory {
	v, parseErr := semver.NewVersion(version)
	var out []domain.Advisory
	for _, a := range advs {
		if matchesVersion(a, v, parseErr != nil) {
			out = append(out, toAdvisory(a))
		}
	}
	return out
}

func matchesVersion(a ghsaAdvisory, v *semver.Version, unparseable bool) bool {
	for _, vuln := range a.Vulnerabilities {
		r := vuln.VulnerableVersionRange
		if r == "" || unparseable {
			return true // conservative
		}
		c, err := semver.NewConstraint(r)
		if err != nil {
			return true // conservative
		}
		if c.Check(v) {
			return true
		}
	}
	return len(a.Vulnerabilities) == 0 // no range = affects all
}

func toAdvisory(a ghsaAdvisory) domain.Advisory {
	var aliases []string
	if a.CVEID != "" {
		aliases = []string{a.CVEID}
	}
	return domain.Advisory{
		ID:       a.GHSAID,
		Aliases:  aliases,
		Severity: parseSeverity(a.Severity),
		Summary:  a.Summary,
		URL:      a.HTMLURL,
		Source:   "github",
	}
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

// ghsaEco maps domain.Ecosystem to the GitHub Advisory ecosystem string.
func ghsaEco(eco domain.Ecosystem) string {
	switch eco {
	case domain.EcoNpm:
		return "npm"
	case domain.EcoPyPI:
		return "pip"
	case domain.EcoCrates:
		return "rust"
	case domain.EcoGo:
		return "go"
	case domain.EcoRubyGems:
		return "rubygems"
	case domain.EcoMaven:
		return "maven"
	case domain.EcoPackagist:
		return "composer"
	case domain.EcoNuGet:
		return "nuget"
	}
	return ""
}
