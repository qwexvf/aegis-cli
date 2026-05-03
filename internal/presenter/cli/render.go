// Package cli implements the terminal-facing presenter for the install
// gate. It satisfies usecase.Presenter by translating domain values
// into ANSI-colored stderr output. The renderer never reaches into the
// API/cache/audit layers — it only formats domain types.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// ANSI color codes. We honor NO_COLOR (https://no-color.org) and skip
// colors when the writer is not a terminal.
const (
	resetCode  = "\x1b[0m"
	dimCode    = "\x1b[2m"
	greenCode  = "\x1b[32m"
	yellowCode = "\x1b[33m"
	redCode    = "\x1b[31m"
	boldCode   = "\x1b[1m"
)

// Presenter renders gate progress and outcomes to an io.Writer.
type Presenter struct {
	w io.Writer
}

// New builds a Presenter that writes to stderr. For tests, prefer
// NewWith to inject a buffer.
func New() *Presenter { return &Presenter{w: os.Stderr} }

// NewWith builds a Presenter that writes to an explicit destination.
func NewWith(w io.Writer) *Presenter { return &Presenter{w: w} }

// OnResolveStart logs "checking name@version ..." (or "(cached)" when
// the decision came from disk cache).
func (p *Presenter) OnResolveStart(spec domain.PackageSpec, resolved string, fromCache bool) {
	suffix := ""
	if fromCache {
		suffix = " (cached)"
	}
	fmt.Fprintf(p.w, "%s[aegis]%s checking %s@%s%s ...\n",
		p.dim(), p.reset(), spec.Name, resolved, suffix)
}

// OnResolveError signals a registry resolution failure (range/tag could
// not be resolved). The gate still passes through to the underlying PM.
func (p *Presenter) OnResolveError(spec domain.PackageSpec, err error) {
	fmt.Fprintf(p.w, "%s[aegis]%s could not resolve %s: %v (passthrough)\n",
		p.dim(), p.reset(), spec.Raw, err)
}

// OnSkipped reports that a non-registry spec was passed through.
func (p *Presenter) OnSkipped(spec domain.PackageSpec) {
	fmt.Fprintf(p.w, "%s[aegis]%s passthrough: %s (non-registry, skipping check)\n",
		p.dim(), p.reset(), spec.Raw)
}

// OnAPIError signals that the gate could not reach the API. Fail-open:
// the install still proceeds.
func (p *Presenter) OnAPIError(spec domain.PackageSpec, version string, err error) {
	fmt.Fprintf(p.w, "%s[aegis]%s %s%s! could not check %s@%s: %v — passing through%s\n",
		p.dim(), p.reset(),
		p.yellow(), p.bold(),
		spec.Name, version, err,
		p.reset())
}

// OnDecision renders the API's verdict (allow/warn/block/prompt). It
// does NOT decide anything itself — that's domain.Evaluate.
func (p *Presenter) OnDecision(d domain.Decision) {
	switch d.Kind {
	case domain.DecisionAllow:
		p.renderAllow(d)
	case domain.DecisionWarn:
		p.renderWarn(d)
	case domain.DecisionBlock:
		p.renderBlock(d)
	case domain.DecisionPrompt:
		p.renderPrompt(d)
	default:
		fmt.Fprintf(p.w, "[aegis] %s@%s — unknown decision %q (passing through)\n",
			d.Spec.Name, d.Resolved, d.Kind)
	}
}

// OnOutcome adds context lines that depend on policy: override hints,
// CI promotions, user prompt resolutions.
func (p *Presenter) OnOutcome(o domain.Outcome, pmName, installVerb string) {
	switch {
	case o.OverrideUsed && o.OverrideReason == "user-allowed":
		fmt.Fprintf(p.w, "%s[aegis]%s   user allowed — proceeding (audited)\n", p.dim(), p.reset())
	case o.OverrideUsed:
		fmt.Fprintf(p.w, "%s[aegis]%s   AEGIS_OVERRIDE=allow set (reason: %q) — proceeding (audited)\n",
			p.dim(), p.reset(), o.OverrideReason)
	case o.PromotedFromPrompt:
		fmt.Fprintf(p.w, "%s[aegis]%s   prompt promoted to block (CI or no TTY)\n", p.dim(), p.reset())
	}
	// Override hint shown only on hard blocks (not on user-denied prompts).
	if o.Action == domain.ActionBlock && !o.PromotedFromPrompt {
		fmt.Fprintf(p.w, "%s[aegis]%s   override: %sAEGIS_OVERRIDE=allow AEGIS_OVERRIDE_REASON=<reason> aegis %s %s %s@%s%s\n",
			p.dim(), p.reset(), p.dim(),
			pmName, installVerb,
			o.Decision.Spec.Name, o.Decision.Resolved,
			p.reset())
	}
}

// OnInfo prints a one-line plain-text message (audit warnings,
// override-refusal notice, etc.).
func (p *Presenter) OnInfo(message string) {
	fmt.Fprintf(p.w, "%s[aegis]%s %s\n", p.dim(), p.reset(), message)
}

// --- per-decision rendering --------------------------------------------

func (p *Presenter) renderAllow(d domain.Decision) {
	suffix := ""
	if d.Source != domain.SourceCache {
		suffix = " (first time we've seen this — capturing in background)"
	}
	fmt.Fprintf(p.w, "%s[aegis]%s %s@%s %s%s\n",
		p.dim(), p.reset(),
		d.Spec.Name, d.Resolved,
		p.green()+"✓ allowed"+p.reset(),
		suffix)
}

func (p *Presenter) renderWarn(d domain.Decision) {
	fmt.Fprintf(p.w, "%s[aegis]%s %s%s⚠ %s@%s — proceed with caution%s\n",
		p.dim(), p.reset(),
		p.yellow(), p.bold(),
		d.Spec.Name, d.Resolved, p.reset())
	p.renderReasons(d, p.yellow())
	p.renderIncident(d)
}

func (p *Presenter) renderBlock(d domain.Decision) {
	fmt.Fprintf(p.w, "%s[aegis]%s %s%s✗ %s@%s — BLOCKED (%s)%s\n",
		p.dim(), p.reset(),
		p.red(), p.bold(),
		d.Spec.Name, d.Resolved,
		strings.ToUpper(string(d.Severity)),
		p.reset())
	p.renderIncident(d)
	p.renderReasons(d, p.red())
	p.renderReferences(d)
}

func (p *Presenter) renderPrompt(d domain.Decision) {
	fmt.Fprintf(p.w, "%s[aegis]%s %s%s⚠ %s@%s — REVIEW REQUIRED (%s)%s\n",
		p.dim(), p.reset(),
		p.red(), p.bold(),
		d.Spec.Name, d.Resolved,
		strings.ToUpper(string(d.Severity)),
		p.reset())
	p.renderIncident(d)
	p.renderReasons(d, p.red())
	p.renderReferences(d)
}

func (p *Presenter) renderIncident(d domain.Decision) {
	if d.Incident == nil {
		return
	}
	if d.Incident.AdvisoryID != "" {
		fmt.Fprintf(p.w, "%s[aegis]%s   advisory: %s\n", p.dim(), p.reset(), d.Incident.AdvisoryID)
	}
	if d.Incident.Date != "" {
		fmt.Fprintf(p.w, "%s[aegis]%s   incident: %s\n", p.dim(), p.reset(), d.Incident.Date)
	}
	if d.Incident.Summary != "" {
		fmt.Fprintf(p.w, "%s[aegis]%s   summary:  %s\n", p.dim(), p.reset(), d.Incident.Summary)
	}
}

func (p *Presenter) renderReasons(d domain.Decision, color string) {
	for _, r := range d.Reasons {
		fmt.Fprintf(p.w, "%s[aegis]%s   %s%s%s — %s\n",
			p.dim(), p.reset(), color, r.Category, p.reset(), r.Detail)
	}
}

func (p *Presenter) renderReferences(d domain.Decision) {
	if d.Incident == nil || len(d.Incident.References) == 0 {
		return
	}
	fmt.Fprintf(p.w, "%s[aegis]%s   refs:\n", p.dim(), p.reset())
	for _, ref := range d.Incident.References {
		fmt.Fprintf(p.w, "%s[aegis]%s     %s%s%s\n", p.dim(), p.reset(), p.dim(), ref, p.reset())
	}
}

// --- color helpers ----------------------------------------------------

func (p *Presenter) useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := p.w.(*os.File)
	if !ok {
		return false
	}
	return isTerminal(f.Fd())
}

func (p *Presenter) wrap(code string) string {
	if p.useColor() {
		return code
	}
	return ""
}

func (p *Presenter) reset() string  { return p.wrap(resetCode) }
func (p *Presenter) dim() string    { return p.wrap(dimCode) }
func (p *Presenter) green() string  { return p.wrap(greenCode) }
func (p *Presenter) yellow() string { return p.wrap(yellowCode) }
func (p *Presenter) red() string    { return p.wrap(redCode) }
func (p *Presenter) bold() string   { return p.wrap(boldCode) }
