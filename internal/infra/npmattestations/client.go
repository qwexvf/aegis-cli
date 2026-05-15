// Package npmattestations fetches and structurally parses npm provenance
// attestations from the public npm registry attestations endpoint.
//
// MVP scope: DSSE envelope decode + JSON extraction of source URI and git
// commit from SLSA v1 predicates. Cryptographic signature verification
// (sigstore-go) is explicitly out of scope — see follow-up issue #75.
package npmattestations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

const (
	defaultBaseURL = "https://registry.npmjs.org"

	// slsaPredicateType is the SLSA Provenance v1 predicate URI.
	// Contains build repo + git commit SHA in buildDefinition.
	slsaPredicateType = "https://slsa.dev/provenance/v1"

	// publishPredicateType is the npm publish attestation URI.
	// Confirms the package was published from the npm CLI but does not
	// carry the source repo or git commit (publish-only, no build provenance).
	publishPredicateType = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
)

// Client fetches npm provenance attestations with no in-memory cache.
// Results are best-effort; errors are non-fatal to the enrich pipeline.
type Client struct {
	baseURL string
	http    *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client used for requests.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithBaseURL overrides the registry base URL (useful for testing).
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// New creates an attestation client.
func New(opts ...Option) *Client {
	c := &Client{
		baseURL: defaultBaseURL,
		http:    http.DefaultClient,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ---------------------------------------------------------------------------
// Narrow API response structs — only the fields needed for MVP.
// ---------------------------------------------------------------------------

type attestationResponse struct {
	Attestations []attestationEntry `json:"attestations"`
}

type attestationEntry struct {
	PredicateType string     `json:"predicateType"`
	Bundle        dsseBundle `json:"bundle"`
}

type dsseBundle struct {
	DsseEnvelope dsseEnvelope `json:"dsseEnvelope"`
}

// dsseEnvelope is the Dead Simple Signing Envelope. Only the base64-encoded
// payload is needed; signatures are verified by sigstore (out of scope for MVP).
type dsseEnvelope struct {
	Payload string `json:"payload"` // base64-encoded in-toto statement JSON
}

// slsaStatement is the decoded DSSE payload (in-toto Statement v0.1).
// Only the predicate path to source + commit is decoded.
type slsaStatement struct {
	Predicate slsaPredicate `json:"predicate"`
}

// slsaPredicate contains the SLSA v1 build definition.
// The nested path mirrors the actual API shape.
type slsaPredicate struct {
	BuildDefinition struct {
		ExternalParameters struct {
			Workflow struct {
				Repository string `json:"repository"`
				Ref        string `json:"ref"`
				SHA        string `json:"sha"`
			} `json:"workflow"`
		} `json:"externalParameters"`
	} `json:"buildDefinition"`
}

// ---------------------------------------------------------------------------
// FetchProvenance implements usecase.ProvenanceFetcher.
// ---------------------------------------------------------------------------

// FetchProvenance fetches the npm provenance attestation for name@version.
// Returns {Status:"missing"} on 404 or empty attestations array.
// Returns {Status:"error"} + non-nil error on HTTP or parse failure.
// Scoped packages (@scope/pkg) are URL-encoded correctly.
func (c *Client) FetchProvenance(ctx context.Context, name, version string) (usecase.ProvenanceResult, error) {
	reqURL := c.baseURL + "/-/npm/v1/attestations/" + encodePackageID(name, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return usecase.ProvenanceResult{Status: "error"}, err
	}

	resp, err := httpx.Do(ctx, c.http, req, httpx.DefaultRetry)
	if err != nil {
		return usecase.ProvenanceResult{Status: "error"},
			fmt.Errorf("attestation fetch %s@%s: %w", name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return usecase.ProvenanceResult{Status: "missing"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return usecase.ProvenanceResult{Status: "error"},
			fmt.Errorf("attestation fetch %s@%s: HTTP %d", name, version, resp.StatusCode)
	}

	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return usecase.ProvenanceResult{Status: "error"},
			fmt.Errorf("read attestation %s@%s: %w", name, version, err)
	}
	return parseAttestationResponse(body)
}

// encodePackageID returns the URL path segment for name@version.
// Scoped packages (@scope/pkg) encode the slash as %2F so the registry
// treats the whole name as one path component.
func encodePackageID(name, version string) string {
	encoded := name
	if strings.HasPrefix(name, "@") {
		// @scope/pkg → @scope%2Fpkg
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			encoded = parts[0] + "%2F" + url.PathEscape(parts[1])
		}
	} else {
		encoded = url.PathEscape(name)
	}
	return encoded + "@" + url.PathEscape(version)
}

// parseAttestationResponse decodes the registry response and extracts
// provenance metadata. Prefers SLSA v1 (has source + commit) over
// publish-only attestations. Returns {Status:"attested"} even when the
// SLSA predicate is absent (publish-only attestation still confirms
// the package came from the npm CLI).
func parseAttestationResponse(body []byte) (usecase.ProvenanceResult, error) {
	var ar attestationResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return usecase.ProvenanceResult{Status: "error"},
			fmt.Errorf("decode attestations: %w", err)
	}
	if len(ar.Attestations) == 0 {
		return usecase.ProvenanceResult{Status: "missing"}, nil
	}

	// Prefer the SLSA v1 predicate — it carries source repo + git SHA.
	for _, att := range ar.Attestations {
		if att.PredicateType != slsaPredicateType {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(att.Bundle.DsseEnvelope.Payload)
		if err != nil {
			continue // malformed — try next entry
		}
		var stmt slsaStatement
		if err := json.Unmarshal(payload, &stmt); err != nil {
			continue
		}
		wf := stmt.Predicate.BuildDefinition.ExternalParameters.Workflow
		return usecase.ProvenanceResult{
			Status:    "attested",
			SourceURI: wf.Repository,
			Commit:    wf.SHA,
		}, nil
	}

	// Has attestations but none are SLSA v1.
	// If a publish attestation is present the package is still "attested" —
	// it came from the npm CLI but without git-level build provenance.
	for _, att := range ar.Attestations {
		if att.PredicateType == publishPredicateType {
			return usecase.ProvenanceResult{Status: "attested"}, nil
		}
	}
	// Unknown predicate types only — treat as attested (conservative).
	return usecase.ProvenanceResult{Status: "attested"}, nil
}
