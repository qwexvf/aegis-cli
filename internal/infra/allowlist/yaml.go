// Package allowlist loads and persists the layered allowlist YAML
// files (user + project) and merges them with the bundled defaults.
//
// File format (intentionally tiny — we want diffs of this file to be
// reviewable on a PR):
//
//	version: 1
//	rules:
//	  - ecosystem: npm
//	    name: lodash         # required, "*" allowed for any
//	    version: "^4"        # optional (default "*")
//	    capability: dynamic-eval  # optional (default "*")
//	    reason: "lodash template compiler uses Function()"
package allowlist

import (
	"bytes"
	"fmt"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"gopkg.in/yaml.v3"
)

// SchemaVersion is the on-disk version this binary writes.
//
// Bump policy:
//   - Adding a new OPTIONAL field to ruleYAML → no bump (older
//     readers reject unknowns via KnownFields=true, so we'll need
//     a future "lenient mode for forward-compat" path; for now,
//     prefer not to add fields without a bump).
//   - Removing or renaming a field, or changing a default → bump.
//
// version: 0 (i.e., key omitted in YAML — Go's zero value) is
// grandfathered as v1: this is the only version a binary has ever
// written, so any in-the-wild file without an explicit version came
// from a v1 binary. Future v2+ binaries MUST require explicit
// `version: <N>` and reject v0.
const SchemaVersion = 1

// fileSchema is the on-disk YAML shape.
type fileSchema struct {
	Version int        `yaml:"version"`
	Rules   []ruleYAML `yaml:"rules"`
}

type ruleYAML struct {
	Ecosystem  string `yaml:"ecosystem"`
	Name       string `yaml:"name"`
	Version    string `yaml:"version,omitempty"`
	Capability string `yaml:"capability,omitempty"`
	Reason     string `yaml:"reason,omitempty"`
}

// decodeFile parses a YAML body into domain.AllowRule values, with
// the given source label stamped onto each.
func decodeFile(body []byte, source string) ([]domain.AllowRule, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true) // reject unknown keys so typos surface
	var f fileSchema
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("yaml decode: %w", err)
	}
	if f.Version != 0 && f.Version != SchemaVersion {
		return nil, fmt.Errorf("allowlist schema version %d not supported (this binary expects v%d)",
			f.Version, SchemaVersion)
	}
	out := make([]domain.AllowRule, 0, len(f.Rules))
	for i, r := range f.Rules {
		eco := domain.Ecosystem(r.Ecosystem)
		if eco == "" {
			return nil, fmt.Errorf("rule %d: ecosystem is required", i)
		}
		var cap domain.Capability
		if r.Capability != "" && r.Capability != "*" {
			c, ok := capabilityFromString(r.Capability)
			if !ok {
				return nil, fmt.Errorf("rule %d: unknown capability %q", i, r.Capability)
			}
			cap = c
		}
		out = append(out, domain.AllowRule{
			Ecosystem:    eco,
			Name:         r.Name,
			VersionRange: r.Version,
			Capability:   cap,
			Reason:       r.Reason,
			Source:       source,
		})
	}
	return out, nil
}

// encodeFile serializes domain rules to the YAML on-disk shape.
func encodeFile(rules []domain.AllowRule) ([]byte, error) {
	out := fileSchema{
		Version: SchemaVersion,
		Rules:   make([]ruleYAML, 0, len(rules)),
	}
	for _, r := range rules {
		y := ruleYAML{
			Ecosystem: string(r.Ecosystem),
			Name:      r.Name,
			Version:   r.VersionRange,
			Reason:    r.Reason,
		}
		if r.Capability != 0 {
			y.Capability = r.Capability.String()
		}
		out.Rules = append(out.Rules, y)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// capabilityFromString maps the YAML string form back to the enum.
// Mirrors domain.Capability.String() but inverted.
func capabilityFromString(s string) (domain.Capability, bool) {
	for _, c := range domain.AllCapabilities() {
		if c.String() == s {
			return c, true
		}
	}
	return 0, false
}
