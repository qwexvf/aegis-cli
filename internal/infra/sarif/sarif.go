// Package sarif produces SARIF 2.1.0 output from aegis scan results.
// SARIF (Static Analysis Results Interchange Format) is the OASIS standard
// consumed by GitHub Code Scanning, VS Code, and most CI security dashboards.
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
package sarif

import "encoding/json"

const (
	// Version210 is the only SARIF version aegis emits.
	Version210 = "2.1.0"
	schema210  = "https://json.schemastore.org/sarif-2.1.0.json"
)

// Log is the root SARIF document.
type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run represents one invocation of one tool.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool identifies the scanner that produced the run.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the tool binary.
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

// Rule describes one detector. Rules are referenced by results.
type Rule struct {
	ID               string             `json:"id"`
	ShortDescription Message            `json:"shortDescription"`
	FullDescription  *Message           `json:"fullDescription,omitempty"`
	DefaultConfig    *RuleDefaultConfig `json:"defaultConfiguration,omitempty"`
	Properties       map[string]any     `json:"properties,omitempty"`
}

// RuleDefaultConfig sets the default level for a rule.
type RuleDefaultConfig struct {
	Level string `json:"level"` // "error" | "warning" | "note" | "none"
}

// Result is one finding.
type Result struct {
	RuleID       string        `json:"ruleId"`
	Level        string        `json:"level"` // "error" | "warning" | "note" | "none"
	Message      Message       `json:"message"`
	Locations    []Location    `json:"locations,omitempty"`
	Suppressions []Suppression `json:"suppressions,omitempty"`
}

// Message is a human-readable string in SARIF's message object.
type Message struct {
	Text string `json:"text"`
}

// Location points to the file and line where the finding was detected.
// For package-scanner results, PhysicalLocation may be absent and
// LogicalLocations carries the package identity instead.
type Location struct {
	PhysicalLocation PhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// LogicalLocation identifies a package, module, or namespace rather than
// a specific source file. Used by the package scanner (no file:line).
type LogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"` // "package", "module", etc.
}

// PhysicalLocation identifies a source file and optional region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation is a URI (relative to the repo root via uriBaseId).
type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// Region is a source range within an artifact.
type Region struct {
	StartLine int `json:"startLine,omitempty"`
}

// Suppression marks a result as suppressed (e.g. via an allowlist rule).
type Suppression struct {
	Kind          string `json:"kind"` // "inSource" | "external"
	Justification string `json:"justification,omitempty"`
}

// Marshal serialises a Log to indented JSON bytes.
func Marshal(log Log) ([]byte, error) {
	return json.MarshalIndent(log, "", "  ")
}
