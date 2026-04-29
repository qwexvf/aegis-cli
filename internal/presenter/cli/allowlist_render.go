package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// AllowlistPresenter renders allowlist CLI subcommand output. It
// shares the base Presenter for color/TTY handling so output style
// matches the rest of the CLI.
type AllowlistPresenter struct{ p *Presenter }

// NewAllowlistPresenter wraps a base Presenter.
func NewAllowlistPresenter(p *Presenter) *AllowlistPresenter {
	return &AllowlistPresenter{p: p}
}

// OnList prints the merged rule list as a tab-aligned table. Source
// column shows where each rule came from (builtin/user/project).
func (ap *AllowlistPresenter) OnList(rules []domain.AllowRule) {
	if len(rules) == 0 {
		fmt.Fprintln(ap.p.w, "(no rules)")
		return
	}
	tw := tabwriter.NewWriter(ap.p.w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ECO\tNAME\tVERSION\tCAPABILITY\tSOURCE\tREASON")
	for _, r := range rules {
		ver := r.VersionRange
		if ver == "" {
			ver = "*"
		}
		cap := "*"
		if r.Capability != 0 {
			cap = r.Capability.String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Ecosystem, r.Name, ver, cap, r.Source, r.Reason)
	}
	tw.Flush()
}

// OnTest reports which allowlist rules apply to a (eco, name, version)
// — used by `aegis allowlist test`.
func (ap *AllowlistPresenter) OnTest(eco domain.Ecosystem, name, version string, matches []matchedRule) {
	header := fmt.Sprintf("%s[aegis]%s testing %s/%s@%s\n",
		ap.p.dim(), ap.p.reset(), eco, name, version)
	fmt.Fprint(ap.p.w, header)

	if len(matches) == 0 {
		fmt.Fprintf(ap.p.w, "%s[aegis]%s no allowlist rules apply\n", ap.p.dim(), ap.p.reset())
		return
	}

	for _, m := range matches {
		fmt.Fprintf(ap.p.w, "%s[aegis]%s %s%s%s suppresses %s%s%s — %s  %s(%s)%s\n",
			ap.p.dim(), ap.p.reset(),
			ap.p.green(), "✓", ap.p.reset(),
			ap.p.bold(), m.Capability.String(), ap.p.reset(),
			m.Rule.Reason,
			ap.p.dim(), m.Rule.Source, ap.p.reset())
	}
}

// MatchedRule pairs a Capability with the AllowRule that matched it.
// Exported through the OnTest method.
type matchedRule struct {
	Capability domain.Capability
	Rule       domain.AllowRule
}

// MatchedRule is the public alias so the interface package can build
// these without internal naming collisions.
type MatchedRule = matchedRule

// NewMatchedRule constructs a matchedRule. The caller (CLI command)
// builds the list by probing AllowSet.Suppresses for each Capability.
func NewMatchedRule(c domain.Capability, r domain.AllowRule) MatchedRule {
	return matchedRule{Capability: c, Rule: r}
}

// OnRuleAdded prints "added <eco>/<name>: <reason>".
func (ap *AllowlistPresenter) OnRuleAdded(scope string, r domain.AllowRule) {
	cap := "any"
	if r.Capability != 0 {
		cap = r.Capability.String()
	}
	fmt.Fprintf(ap.p.w, "%s[aegis]%s added %s rule: %s/%s (%s) — %s\n",
		ap.p.dim(), ap.p.reset(),
		scope, r.Ecosystem, r.Name, cap, r.Reason)
}

// OnRuleRemoved prints "removed N rule(s) from <scope>".
func (ap *AllowlistPresenter) OnRuleRemoved(scope string, n int) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s removed %d rule(s) from %s\n",
		ap.p.dim(), ap.p.reset(), n, scope)
}

// OnInfo is a generic single-line status message.
func (ap *AllowlistPresenter) OnInfo(message string) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s %s\n", ap.p.dim(), ap.p.reset(), message)
}

// OnError prints a single-line error.
func (ap *AllowlistPresenter) OnError(err error) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s %s%s! %v%s\n",
		ap.p.dim(), ap.p.reset(),
		ap.p.red(), ap.p.bold(), err, ap.p.reset())
}
