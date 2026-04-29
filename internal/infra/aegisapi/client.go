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
	"os"
	"strings"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// DefaultURL is the default Aegis API base URL. Override with AEGIS_API_URL.
const DefaultURL = "http://localhost:4000"

// Client is the Aegis API HTTP client.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client with sensible defaults. Reads AEGIS_API_URL from
// the environment if set, otherwise uses DefaultURL.
func New() *Client {
	base := os.Getenv("AEGIS_API_URL")
	if base == "" {
		base = DefaultURL
	}
	return &Client{
		baseURL: strings.TrimRight(base, "/"),
		http:    &http.Client{Timeout: 5 * time.Second},
	}
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
	req.Header.Set("User-Agent", "aegis-cli/0.1.0-demo")

	resp, err := c.http.Do(req)
	if err != nil {
		return domain.Decision{}, fmt.Errorf("aegis api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return domain.Decision{}, fmt.Errorf("aegis api: returned %d", resp.StatusCode)
	}

	var dto decisionDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
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
			References: d.References,
		}
	}
	return out
}
