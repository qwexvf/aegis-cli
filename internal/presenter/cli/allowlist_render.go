package cli

import (
	"fmt"
	"strings"
	"time"
	"text/tabwriter"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// AllowlistPresenter renders allowlist CLI subcommand output. It
// shares the base Presenter for color/TTY handling so output style
// matches the rest of the CLI.
type AllowlistPresenter struct{ p *Presenter }

// NewAllowlistPresenter wraps a base Presenter.
func NewAllowlistPresenter(p *Presenter) *AllowlistPresenter {
	return &AllowlistPresenter{p: p}
}

// MatchedRule pairs a Capability with the AllowRule that matched it.
// The CLI command builds these by probing AllowSet.Suppresses for
// each Capability and feeds the list into OnTest for rendering.
//
// CapabilityAny is used when the matched rule had Capability=0 (any).
// We don't enumerate every Capability against an "any" rule to avoid
// flooding `aegis allowlist test` with N near-identical lines.
type MatchedRule struct {
	Capability    domain.Capability // 0 when CapabilityAny is true
	CapabilityAny bool
	Rule          domain.AllowRule
}

// OnList prints the merged rule list as a tab-aligned table. Source
// column shows where each rule came from (builtin/user/project).
//
// Tabs in the Reason column would corrupt the table layout, so we
// replace any embedded tabs with spaces before printing.
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
		capName := "*"
		if r.Capability != 0 {
			capName = r.Capability.String()
		}
		reason := strings.ReplaceAll(r.Reason, "\t", " ")
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Ecosystem, r.Name, ver, capName, r.Source, reason)
	}
	tw.Flush()
}

// OnTest reports which allowlist rules apply to a (eco, name, version)
// — used by `aegis allowlist test`.
func (ap *AllowlistPresenter) OnTest(eco domain.Ecosystem, name, version string, matches []MatchedRule) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s testing %s/%s@%s\n",
		ap.p.dim(), ap.p.reset(), eco, name, version)

	if len(matches) == 0 {
		fmt.Fprintf(ap.p.w, "%s[aegis]%s no allowlist rules apply\n", ap.p.dim(), ap.p.reset())
		return
	}

	for _, m := range matches {
		capLabel := m.Capability.String()
		if m.CapabilityAny {
			capLabel = "any capability"
		}
		fmt.Fprintf(ap.p.w, "%s[aegis]%s %s✓%s suppresses %s%s%s — %s  %s(%s)%s\n",
			ap.p.dim(), ap.p.reset(),
			ap.p.green(), ap.p.reset(),
			ap.p.bold(), capLabel, ap.p.reset(),
			m.Rule.Reason,
			ap.p.dim(), m.Rule.Source, ap.p.reset())
	}
}

// OnRuleAdded prints "added <eco>/<name>: <reason>".
func (ap *AllowlistPresenter) OnRuleAdded(scope string, r domain.AllowRule) {
	capLabel := "any"
	if r.Capability != 0 {
		capLabel = r.Capability.String()
	}
	fmt.Fprintf(ap.p.w, "%s[aegis]%s added %s rule: %s/%s (%s) — %s\n",
		ap.p.dim(), ap.p.reset(),
		scope, r.Ecosystem, r.Name, capLabel, r.Reason)
}

// OnRuleReplaced prints "replaced <eco>/<name>: <reason>" — fired
// when AddRule overwrote an existing entry with the same key.
func (ap *AllowlistPresenter) OnRuleReplaced(scope string, r domain.AllowRule) {
	capLabel := "any"
	if r.Capability != 0 {
		capLabel = r.Capability.String()
	}
	fmt.Fprintf(ap.p.w, "%s[aegis]%s replaced %s rule: %s/%s (%s) — %s\n",
		ap.p.dim(), ap.p.reset(),
		scope, r.Ecosystem, r.Name, capLabel, r.Reason)
}

// OnRuleRemoved prints "removed N rule(s) from <scope>".
func (ap *AllowlistPresenter) OnRuleRemoved(scope string, n int) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s removed %d rule(s) from %s\n",
		ap.p.dim(), ap.p.reset(), n, scope)
}

// OnVerifyOK reports a successful verify against a path.
func (ap *AllowlistPresenter) OnVerifyOK(path string, n int) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s %s%s%s %s — %d rule(s) parsed\n",
		ap.p.dim(), ap.p.reset(),
		ap.p.green(), "✓", ap.p.reset(),
		path, n)
}

// OnVerifyFailed reports a parse or validation error against a file.
func (ap *AllowlistPresenter) OnVerifyFailed(path string, err error) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s %s%s✗%s %s — %v\n",
		ap.p.dim(), ap.p.reset(),
		ap.p.red(), ap.p.bold(), ap.p.reset(),
		path, err)
}

// OnInfo is a generic single-line status message.
func (ap *AllowlistPresenter) OnInfo(message string) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s %s\n", ap.p.dim(), ap.p.reset(), message)
}

// OnSyncOK reports a successful server-allowlist fetch + cache write.
func (ap *AllowlistPresenter) OnSyncOK(ruleCount int, cachePath string) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s %s✓%s synced %d server rule(s) → %s\n",
		ap.p.dim(), ap.p.reset(),
		ap.p.green(), ap.p.reset(),
		ruleCount, cachePath)
}

// OnSyncSkipped reports that the cache was reused because it's still
// fresh. The user can pass --force to bypass.
func (ap *AllowlistPresenter) OnSyncSkipped(age time.Duration) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s cache is fresh (%s old); skipping fetch — pass --force to refresh\n",
		ap.p.dim(), ap.p.reset(),
		formatAge(age))
}

func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// OnError prints a single-line error.
func (ap *AllowlistPresenter) OnError(err error) {
	fmt.Fprintf(ap.p.w, "%s[aegis]%s %s%s! %v%s\n",
		ap.p.dim(), ap.p.reset(),
		ap.p.red(), ap.p.bold(), err, ap.p.reset())
}
