package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// RecheckPresenter satisfies usecase.RecheckPresenter. Mirrors the
// CIPresenter shape: human (default), --quiet (summary only), --json
// (one stdout object).
type RecheckPresenter struct {
	p        *Presenter
	jsonOut  io.Writer
	jsonMode bool
	quiet    bool
}

// NewRecheckPresenter wraps a base Presenter for stderr; JSON goes
// to stdout.
func NewRecheckPresenter(base *Presenter) *RecheckPresenter {
	return &RecheckPresenter{p: base, jsonOut: os.Stdout}
}

func (rp *RecheckPresenter) SetJSONMode(on bool) *RecheckPresenter  { rp.jsonMode = on; return rp }
func (rp *RecheckPresenter) SetQuietMode(on bool) *RecheckPresenter { rp.quiet = on; return rp }
func (rp *RecheckPresenter) SetJSONWriter(w io.Writer) *RecheckPresenter {
	rp.jsonOut = w
	return rp
}

// OnRecheckBegin prints the count of deps about to be probed.
func (rp *RecheckPresenter) OnRecheckBegin(total int) {
	if rp.jsonMode || rp.quiet {
		return
	}
	fmt.Fprintf(rp.p.w, "%s[aegis]%s rechecking %d deps via /check ...\n",
		rp.p.dim(), rp.p.reset(), total)
}

// OnRecheckProgress is called per dep. Verbose by default, suppressed
// in JSON or --quiet mode.
func (rp *RecheckPresenter) OnRecheckProgress(done, total int, name string) {
	if rp.jsonMode || rp.quiet {
		return
	}
	fmt.Fprintf(rp.p.w, "%s[aegis]%s [%d/%d] %s\n",
		rp.p.dim(), rp.p.reset(), done, total, name)
}

// OnRecheckError surfaces a scan/setup failure.
func (rp *RecheckPresenter) OnRecheckError(err error) {
	if rp.jsonMode {
		_ = json.NewEncoder(rp.jsonOut).Encode(map[string]string{"error": err.Error()})
		return
	}
	fmt.Fprintf(rp.p.w, "%s[aegis]%s %s%s! %v%s\n",
		rp.p.dim(), rp.p.reset(),
		rp.p.red(), rp.p.bold(), err, rp.p.reset())
}

// OnRecheckResult prints findings + summary or one JSON object.
func (rp *RecheckPresenter) OnRecheckResult(r usecase.RecheckResult) {
	if rp.jsonMode {
		_ = json.NewEncoder(rp.jsonOut).Encode(toRecheckJSON(r))
		return
	}
	if !rp.quiet {
		for _, f := range r.Findings {
			rp.renderFinding(f)
		}
	}
	rp.renderSummary(r)
}

// renderFinding prints one above-threshold dep with the API's reasons.
func (rp *RecheckPresenter) renderFinding(f usecase.RecheckFinding) {
	marker, color := "✗", rp.p.red()
	if f.Decision.Kind == "prompt" {
		marker, color = "⚠", rp.p.red()
	}
	fmt.Fprintf(rp.p.w, "\n%s%s%s %s/%s@%s — %s%s%s",
		color, marker, rp.p.reset(),
		f.Dep.Ecosystem, f.Dep.Name, f.Dep.Version,
		color, f.Decision.Kind, rp.p.reset())
	if f.Decision.Severity != "" {
		fmt.Fprintf(rp.p.w, " (%s)", f.Decision.Severity)
	}
	fmt.Fprintln(rp.p.w)
	if f.Decision.Incident != nil && f.Decision.Incident.AdvisoryID != "" {
		fmt.Fprintf(rp.p.w, "  advisory: %s\n", f.Decision.Incident.AdvisoryID)
	}
	for _, reason := range f.Decision.Reasons {
		fmt.Fprintf(rp.p.w, "  %s%s%s — %s\n",
			color, reason.Category, rp.p.reset(), reason.Detail)
	}
}

// renderSummary prints the final PASS/FAIL line.
func (rp *RecheckPresenter) renderSummary(r usecase.RecheckResult) {
	s := r.Summary
	bucket := fmt.Sprintf("%d total • %d allowed • %d warned • %d prompt • %d block • %d errored",
		s.Total, s.Allowed, s.Warned, s.Prompts, s.Blocked, s.Errors)
	if r.Passed {
		fmt.Fprintf(rp.p.w, "\n%s[aegis]%s %s%sPASS%s — %s\n",
			rp.p.dim(), rp.p.reset(),
			rp.p.green(), rp.p.bold(), rp.p.reset(),
			bucket)
		return
	}
	fmt.Fprintf(rp.p.w, "\n%s[aegis]%s %s%sFAIL%s — %d finding(s)  (%s)\n",
		rp.p.dim(), rp.p.reset(),
		rp.p.red(), rp.p.bold(), rp.p.reset(),
		len(r.Findings), bucket)
}

// --- JSON shape --------------------------------------------------------

type recheckJSON struct {
	Passed   bool                  `json:"passed"`
	Summary  recheckSummaryJSON    `json:"summary"`
	Findings []recheckFindingJSON  `json:"findings"`
}

type recheckSummaryJSON struct {
	Total   int `json:"total"`
	Allowed int `json:"allowed"`
	Warned  int `json:"warned"`
	Prompts int `json:"prompts"`
	Blocked int `json:"blocked"`
	Errors  int `json:"errors"`
}

type recheckFindingJSON struct {
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Direct     bool     `json:"direct"`
	Decision   string   `json:"decision"`
	Severity   string   `json:"severity,omitempty"`
	AdvisoryID string   `json:"advisory_id,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
}

func toRecheckJSON(r usecase.RecheckResult) recheckJSON {
	out := recheckJSON{
		Passed: r.Passed,
		Summary: recheckSummaryJSON{
			Total:   r.Summary.Total,
			Allowed: r.Summary.Allowed,
			Warned:  r.Summary.Warned,
			Prompts: r.Summary.Prompts,
			Blocked: r.Summary.Blocked,
			Errors:  r.Summary.Errors,
		},
		Findings: make([]recheckFindingJSON, 0, len(r.Findings)),
	}
	for _, f := range r.Findings {
		reasons := make([]string, 0, len(f.Decision.Reasons))
		for _, reason := range f.Decision.Reasons {
			reasons = append(reasons, reason.Category+": "+reason.Detail)
		}
		entry := recheckFindingJSON{
			Ecosystem: string(f.Dep.Ecosystem),
			Name:      f.Dep.Name,
			Version:   f.Dep.Version,
			Direct:    f.Dep.Direct,
			Decision:  string(f.Decision.Kind),
			Severity:  string(f.Decision.Severity),
			Reasons:   reasons,
		}
		if f.Decision.Incident != nil {
			entry.AdvisoryID = f.Decision.Incident.AdvisoryID
		}
		out.Findings = append(out.Findings, entry)
	}
	return out
}
