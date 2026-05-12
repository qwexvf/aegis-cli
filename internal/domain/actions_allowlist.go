package domain

import "strings"

// ActionsIgnoreRule suppresses a WorkflowFindingKind in a given workflow file.
// Kind "*" matches all finding kinds; File "*" or "" matches all files.
type ActionsIgnoreRule struct {
	Kind   string // "unpinned_ref", "write_all_permissions", "*", etc.
	File   string // workflow file path or glob suffix; "" / "*" = all
	Reason string // human-readable explanation stored in SuppressBy
}

// ActionsIgnoreSet is an ordered list of ignore rules applied to
// WorkflowFindings after heuristics run. Findings are marked Suppressed
// rather than removed so output remains transparent.
type ActionsIgnoreSet struct {
	rules []ActionsIgnoreRule
}

// NewActionsIgnoreSet constructs a set from the given rules.
// Passing nil returns an empty (no-op) set.
func NewActionsIgnoreSet(rules []ActionsIgnoreRule) ActionsIgnoreSet {
	return ActionsIgnoreSet{rules: rules}
}

// Suppress marks any finding that matches a rule as Suppressed=true and
// stores the rule's Reason in SuppressBy. Returns a new slice; does not
// mutate the input.
func (s ActionsIgnoreSet) Suppress(findings []WorkflowFinding) []WorkflowFinding {
	if len(s.rules) == 0 || len(findings) == 0 {
		return findings
	}
	out := make([]WorkflowFinding, len(findings))
	copy(out, findings)
	for i := range out {
		for _, rule := range s.rules {
			if s.matches(rule, out[i]) {
				out[i].Suppressed = true
				out[i].SuppressBy = rule.Reason
				break
			}
		}
	}
	return out
}

// IsEmpty reports whether the set has no rules (no-op).
func (s ActionsIgnoreSet) IsEmpty() bool { return len(s.rules) == 0 }

func (s ActionsIgnoreSet) matches(rule ActionsIgnoreRule, f WorkflowFinding) bool {
	kindMatch := rule.Kind == "*" || rule.Kind == "" || rule.Kind == f.Kind.String()
	fileMatch := rule.File == "*" || rule.File == "" ||
		f.File == rule.File ||
		strings.HasSuffix(f.File, "/"+rule.File) ||
		strings.HasSuffix(f.File, rule.File)
	return kindMatch && fileMatch
}
