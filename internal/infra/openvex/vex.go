// Package openvex parses OpenVEX documents (https://openvex.dev) and
// produces a suppression set for the CI scorer.
//
// VEX (Vulnerability Exploitability eXchange) lets package authors
// assert that a known vulnerability does NOT affect their product —
// e.g. because the vulnerable code path is never reached, or a
// compensating control is in place. Status "not_affected" with a
// documented justification means the advisory can be safely suppressed.
//
// aegis supports the common use case: point `--vex` at a local VEX
// file and any advisory ID that appears with status "not_affected" is
// suppressed from verdict scoring. Product-level matching (per-package
// suppression) is not yet enforced — all "not_affected" statements
// are treated as project-wide suppressions.
package openvex

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Status mirrors the OpenVEX status vocabulary.
type Status string

const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// Document is the top-level OpenVEX JSON-LD object.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

// Statement is one VEX assertion.
type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Products        []Product     `json:"products"`
	Status          Status        `json:"status"`
	Justification   string        `json:"justification"`
	ImpactStatement string        `json:"impact_statement"`
}

// Vulnerability names the affected CVE / advisory.
type Vulnerability struct {
	// ID is the canonical identifier, e.g. "CVE-2021-44228".
	// "@id" in the JSON-LD form is also parsed here via Aliases.
	ID      string   `json:"name"`
	AtID    string   `json:"@id"`
	Aliases []string `json:"aliases"`
}

// Product is the affected product PURL or identifier.
type Product struct {
	AtID string `json:"@id"`
}

// LoadFile reads and parses a VEX document from disk.
//
// security: path is operator-supplied via the CLI --vex flag. aegis
// runs as the invoking user, so reading user-readable files is
// trivially within their privilege — not a path-traversal exploit
// vector. gosec G304 marker added for future audits.
func LoadFile(path string) (*Document, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path; user-owned process
	if err != nil {
		return nil, fmt.Errorf("vex: read %s: %w", path, err)
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("vex: parse %s: %w", path, err)
	}
	return &doc, nil
}

// SuppressedAdvisories returns the set of advisory IDs that the VEX
// document asserts are "not_affected". The returned map is safe to use
// as a fast lookup: `_, ok := set[advisoryID]`.
//
// IDs are normalised to uppercase so "cve-2021-44228" and
// "CVE-2021-44228" both match.
func SuppressedAdvisories(doc *Document) map[string]struct{} {
	out := make(map[string]struct{})
	if doc == nil {
		return out
	}
	for _, s := range doc.Statements {
		if s.Status != StatusNotAffected {
			continue
		}
		v := s.Vulnerability
		for _, id := range vulnIDs(v) {
			out[strings.ToUpper(id)] = struct{}{}
		}
	}
	return out
}

// vulnIDs extracts every identifier from a Vulnerability: the name
// field, the @id field (stripped of its URL prefix if present), and
// any aliases.
func vulnIDs(v Vulnerability) []string {
	var ids []string
	if v.ID != "" {
		ids = append(ids, v.ID)
	}
	if atID := idFromAtID(v.AtID); atID != "" {
		ids = append(ids, atID)
	}
	ids = append(ids, v.Aliases...)
	return ids
}

// idFromAtID strips a URL prefix from an OpenVEX @id like
// "https://osv.dev/GHSA-xxxx-xxxx-xxxx" → "GHSA-xxxx-xxxx-xxxx".
// Returns the raw string when no "/" is found.
func idFromAtID(atID string) string {
	if atID == "" {
		return ""
	}
	if i := strings.LastIndex(atID, "/"); i >= 0 {
		return atID[i+1:]
	}
	return atID
}
