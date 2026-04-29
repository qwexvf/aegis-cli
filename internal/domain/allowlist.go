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
//
//	Name == "*"            : matches any package in the ecosystem
//	VersionRange == ""/"*" : matches any version
//	Capability == 0        : matches any capability
//
// Example matching for `lodash@4.17.21`'s `dynamic-eval` flag:
//
//	{Eco:EcoNpm, Name:"lodash", VersionRange:"^4", Capability:CapDynamicEval}
//	matches because: ecosystem equal, name equal, semver constraint
//	^4 admits 4.17.21, capability equal.
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
//
// Internally, rules are partitioned into two structures for fast
// lookup: an `index` keyed by (ecosystem, name) for exact-name rules,
// and `wildcards` for rules with Name == "*". Suppresses then probes
// the index in O(1) for the typical specific-package rule and only
// falls back to a wildcards scan for the small set of broad rules.
//
// `compiled` preserves input order — kept for Rules() and MatchAll
// stability.
type AllowSet struct {
	compiled  []compiledRule
	index     map[allowKey][]compiledRule
	wildcards []compiledRule
}

// allowKey is the index key for exact-name rules. We don't include
// VersionRange or Capability — multiple rules with the same
// (ecosystem, name) and different versions/caps land in the same
// bucket and are walked linearly inside Suppresses (typically a
// 1-3 element list).
type allowKey struct {
	Ecosystem Ecosystem
	Name      string
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
	out := AllowSet{
		compiled: make([]compiledRule, 0, len(rules)),
		index:    map[allowKey][]compiledRule{},
	}
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
		if r.Name == "*" {
			out.wildcards = append(out.wildcards, c)
		} else {
			k := allowKey{Ecosystem: r.Ecosystem, Name: r.Name}
			out.index[k] = append(out.index[k], c)
		}
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
// Match order:
//  1. Exact-name rules (index lookup, typically 1-3 entries) — the
//     specific case wins early and avoids a full scan.
//  2. Wildcard-name rules (linear scan over a small slice).
//
// "version" can be empty — a rule with VersionRange != "*" then
// won't match (unparsed input can't satisfy a constraint).
func (s AllowSet) Suppresses(eco Ecosystem, name, version string, c Capability) (bool, AllowRule) {
	if len(s.compiled) == 0 {
		return false, AllowRule{}
	}
	if rules, ok := s.index[allowKey{Ecosystem: eco, Name: name}]; ok {
		for _, cr := range rules {
			if ruleMatches(cr, eco, name, version, c) {
				return true, cr.rule
			}
		}
	}
	for _, cr := range s.wildcards {
		if ruleMatches(cr, eco, name, version, c) {
			return true, cr.rule
		}
	}
	return false, AllowRule{}
}

// MatchKind distinguishes a rule that targets a specific Capability
// from one that targets "any capability" (Capability == 0). The
// presenter uses this to print a single "matches any capability" line
// instead of one match per Capability in AllCapabilities().
type MatchKind int

const (
	// MatchSpecific: the rule targets exactly one Capability.
	MatchSpecific MatchKind = iota + 1
	// MatchAny: the rule had Capability == 0, so it suppresses any
	// flag for the matched (eco, name, version) tuple.
	MatchAny
)

// Match describes one rule's relevance to a (eco, name, version)
// tuple, returned by MatchAll.
type Match struct {
	Kind       MatchKind
	Capability Capability // zero when Kind == MatchAny
	Rule       AllowRule
}

// MatchAll returns every rule whose (ecosystem, name, version)
// matches the given tuple, regardless of Capability. Used by
// `aegis allowlist test` to enumerate matching rules without
// probing each Capability one by one.
//
// Order: exact-name rules first (in their input order), then
// wildcard-name rules (in their input order). This keeps "more
// specific first" behaviour the user intuitively expects.
func (s AllowSet) MatchAll(eco Ecosystem, name, version string) []Match {
	if len(s.compiled) == 0 {
		return nil
	}
	var out []Match
	if rules, ok := s.index[allowKey{Ecosystem: eco, Name: name}]; ok {
		for _, cr := range rules {
			if ruleMatchesIgnoringCapability(cr, eco, name, version) {
				out = append(out, makeMatch(cr))
			}
		}
	}
	for _, cr := range s.wildcards {
		if ruleMatchesIgnoringCapability(cr, eco, name, version) {
			out = append(out, makeMatch(cr))
		}
	}
	return out
}

func makeMatch(cr compiledRule) Match {
	m := Match{Rule: cr.rule}
	if cr.rule.Capability == 0 {
		m.Kind = MatchAny
	} else {
		m.Kind = MatchSpecific
		m.Capability = cr.rule.Capability
	}
	return m
}

func ruleMatches(cr compiledRule, eco Ecosystem, name, version string, c Capability) bool {
	if !ruleMatchesIgnoringCapability(cr, eco, name, version) {
		return false
	}
	r := cr.rule
	if r.Capability != 0 && r.Capability != c {
		return false
	}
	return true
}

// ruleMatchesIgnoringCapability checks ecosystem, name, and version
// constraints. The Capability check is layered on top in ruleMatches.
func ruleMatchesIgnoringCapability(cr compiledRule, eco Ecosystem, name, version string) bool {
	r := cr.rule
	if r.Ecosystem != eco {
		return false
	}
	if r.Name != "*" && r.Name != name {
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
