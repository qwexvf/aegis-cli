package domain

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

// AllowRule declares one (ecosystem, name, version-range, capability)
// tuple whose risk-flag contribution should be suppressed. Rules come
// from three layers (builtin, user, project) merged into a single
// AllowSet at the composition root.
//
// Wildcards:
//   Name == "*"            : matches any package in the ecosystem
//   VersionRange == ""/"*" : matches any version
//   Capability == 0        : matches any capability
//
// Example matching for `lodash@4.17.21`'s `dynamic-eval` flag:
//   {Eco:EcoNpm, Name:"lodash", VersionRange:"^4", Capability:CapDynamicEval}
//   matches because: ecosystem equal, name equal, semver constraint
//   ^4 admits 4.17.21, capability equal.
type AllowRule struct {
	Ecosystem    Ecosystem
	Name         string
	VersionRange string
	Capability   Capability
	Reason       string
	// Source identifies which layer the rule came from
	// ("builtin" | "user" | "project"). Used by the presenter for
	// display and by Loader.Remove for scope-targeted removal.
	Source string
}

// AllowSet is an immutable, pre-compiled rule list. Construct with
// NewAllowSet (validates and pre-parses semver constraints).
type AllowSet struct {
	compiled []compiledRule
}

type compiledRule struct {
	rule    AllowRule
	version *semver.Constraints // nil when the rule matches any version
}

// NewAllowSet validates and compiles a list of rules. It returns the
// first error encountered; if any rule has an invalid VersionRange or
// missing Ecosystem, the whole set is rejected so the user discovers
// the typo immediately rather than silently mismatching.
func NewAllowSet(rules []AllowRule) (AllowSet, error) {
	out := AllowSet{compiled: make([]compiledRule, 0, len(rules))}
	for i, r := range rules {
		if r.Ecosystem == "" {
			return AllowSet{}, fmt.Errorf("allowlist rule %d: ecosystem is required", i)
		}
		if r.Name == "" {
			return AllowSet{}, fmt.Errorf("allowlist rule %d: name is required (use \"*\" for any)", i)
		}
		c := compiledRule{rule: r}
		if r.VersionRange != "" && r.VersionRange != "*" {
			parsed, err := semver.NewConstraint(r.VersionRange)
			if err != nil {
				return AllowSet{}, fmt.Errorf("allowlist rule %d (%s/%s): invalid version range %q: %w",
					i, r.Ecosystem, r.Name, r.VersionRange, err)
			}
			c.version = parsed
		}
		out.compiled = append(out.compiled, c)
	}
	return out, nil
}

// EmptyAllowSet returns a usable zero-rule set. Helpful when callers
// can't (or don't want to) supply rules.
func EmptyAllowSet() AllowSet { return AllowSet{} }

// Rules returns the rule list (decompiled). Order preserves the input.
func (s AllowSet) Rules() []AllowRule {
	out := make([]AllowRule, len(s.compiled))
	for i, c := range s.compiled {
		out[i] = c.rule
	}
	return out
}

// Len reports the number of rules.
func (s AllowSet) Len() int { return len(s.compiled) }

// Suppresses reports whether any rule matches (eco, name, version, c).
// When matched, the second return is the rule (so callers can show
// the reason). When no rule matches, the second return is the zero
// AllowRule.
//
// "version" can be empty — a rule with VersionRange != "*" then
// won't match (unparsed input can't satisfy a constraint).
func (s AllowSet) Suppresses(eco Ecosystem, name, version string, c Capability) (bool, AllowRule) {
	if len(s.compiled) == 0 {
		return false, AllowRule{}
	}
	for _, cr := range s.compiled {
		if !ruleMatches(cr, eco, name, version, c) {
			continue
		}
		return true, cr.rule
	}
	return false, AllowRule{}
}

func ruleMatches(cr compiledRule, eco Ecosystem, name, version string, c Capability) bool {
	r := cr.rule
	if r.Ecosystem != eco {
		return false
	}
	if r.Name != "*" && r.Name != name {
		return false
	}
	if r.Capability != 0 && r.Capability != c {
		return false
	}
	if cr.version != nil {
		if version == "" {
			return false
		}
		v, err := semver.NewVersion(version)
		if err != nil {
			return false
		}
		if !cr.version.Check(v) {
			return false
		}
	}
	return true
}
