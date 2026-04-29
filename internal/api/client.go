// Package api implements the HTTP client used to talk to the Aegis API.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultURL is the default Aegis API base URL. Override with AEGIS_API_URL.
const DefaultURL = "http://localhost:4000"

// Reason is a single justification attached to a Decision.
type Reason struct {
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

// Decision is what the API returns for a supply-chain check.
type Decision struct {
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Decision  string   `json:"decision"` // allow | warn | block | prompt
	Severity  string   `json:"severity"` // critical | high | medium | low | info
	Cached    bool     `json:"cached"`
	Reasons   []Reason `json:"reasons"`
}

// Client is the Aegis API client.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client with sensible defaults. It reads AEGIS_API_URL from the
// environment if set, otherwise uses DefaultURL.
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

// Check posts a supply-chain check request for one package@version.
func (c *Client) Check(ctx context.Context, ecosystem, pkg, version string) (*Decision, error) {
	body, err := json.Marshal(map[string]string{
		"ecosystem": ecosystem,
		"package":   pkg,
		"version":   version,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/supply-chain/check", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aegis-cli/0.1.0-demo")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aegis api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("aegis api: returned %d", resp.StatusCode)
	}

	var d Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("decode decision: %w", err)
	}
	return &d, nil
}
