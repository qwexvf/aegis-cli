package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// CIPresenter satisfies usecase.CIPresenter. Renders the CI audit
// header, per-finding detail, and a one-line PASS/FAIL summary to
// stderr in human mode, or a single JSON object to stdout in JSON
// mode.
type CIPresenter struct {
	p        *Presenter
	jsonOut  io.Writer // typically os.Stdout — kept separate from p.w (stderr)
	jsonMode bool
	quiet    bool
}

// NewCIPresenter wraps a base Presenter for stderr output and
// targets stdout for JSON. Use SetJSONMode / SetQuietMode at the CLI
// layer once flags parse.
func NewCIPresenter(base *Presenter) *CIPresenter {
	return &CIPresenter{p: base, jsonOut: os.Stdout}
}

// SetJSONMode toggles JSON output. Returns the receiver for chaining.
func (cp *CIPresenter) SetJSONMode(on bool) *CIPresenter {
	cp.jsonMode = on
	return cp
}

// SetQuietMode toggles per-finding suppression (only summary lines
// remain in human mode). No effect in JSON mode.
func (cp *CIPresenter) SetQuietMode(on bool) *CIPresenter {
	cp.quiet = on
	return cp
}

// SetJSONWriter overrides the JSON destination. Tests inject a buffer.
func (cp *CIPresenter) SetJSONWriter(w io.Writer) *CIPresenter {
	cp.jsonOut = w
	return cp
}

// OnCIBegin prints the audit header. JSON mode keeps stderr quiet so
// downstream `| jq` pipes stay clean.
func (cp *CIPresenter) OnCIBegin(projectDir string, failOn domain.VerdictKind, enrich bool) {
	if cp.jsonMode || cp.quiet {
		return
	}
	mode := "audit (save → enrich → score)"
	if !enrich {
		mode = "audit (save → score, --no-enrich)"
	}
	fmt.Fprintf(cp.p.w, "%s[aegis]%s CI %s\n", cp.p.dim(), cp.p.reset(), mode)
	fmt.Fprintf(cp.p.w, "%s[aegis]%s   project:    %s\n",
		cp.p.dim(), cp.p.reset(), projectDir)
	fmt.Fprintf(cp.p.w, "%s[aegis]%s   threshold:  %s\n",
		cp.p.dim(), cp.p.reset(), failOn)
}

// OnCIError surfaces a save / enrich / score failure.
func (cp *CIPresenter) OnCIError(err error) {
	if cp.jsonMode {
		_ = json.NewEncoder(cp.jsonOut).Encode(ciErrorJSON{Error: err.Error()})
		return
	}
	fmt.Fprintf(cp.p.w, "%s[aegis]%s %s%s! %v%s\n",
		cp.p.dim(), cp.p.reset(),
		cp.p.red(), cp.p.bold(), err, cp.p.reset())
}

// OnCIResult prints the audit verdict. In JSON mode, marshals to one
// stdout object. In human mode, lists findings (unless --quiet) and
// prints a one-line PASS/FAIL summary.
func (cp *CIPresenter) OnCIResult(r usecase.CIResult) {
	if cp.jsonMode {
		_ = json.NewEncoder(cp.jsonOut).Encode(toCIJSONResult(r))
		return
	}

	if !cp.quiet {
		for _, f := range r.Findings {
			cp.renderFinding(f)
		}
	}
	cp.renderSummary(r)
}

// renderFinding prints one above-threshold dep with its risk + drift
// flag groups. Risk = "absolute capabilities of this version"; drift
// = "what changed vs the baseline version". Both are useful and
// answer different questions, so both render when non-zero.
func (cp *CIPresenter) renderFinding(f usecase.CIFinding) {
	marker, color := analyzeVerdictMarker(cp.p, f.Verdict) // reuse from analyze_render.go
	fmt.Fprintf(cp.p.w, "\n%s%s%s %s/%s@%s — %sverdict=%s%s  risk=%d",
		color, marker, cp.p.reset(),
		f.Dep.Ecosystem, f.Dep.Name, f.Dep.Version,
		color, f.Verdict, cp.p.reset(),
		f.Risk.Score)
	if f.Drift.Score > 0 {
		fmt.Fprintf(cp.p.w, "  drift=%d", f.Drift.Score)
	}
	fmt.Fprintln(cp.p.w)

	cp.renderFlagBlock("Risk flags", "+", f.Risk.Flags)
	cp.renderFlagBlock("Drift flags (vs baseline)", "Δ", f.Drift.Flags)
}

// renderFlagBlock prints one labeled list of risk flags. Suppressed
// flags are skipped — the user's seen them in `aegis explain`.
// No-op when there are no non-suppressed flags to show.
func (cp *CIPresenter) renderFlagBlock(label, marker string, flags []domain.RiskFlag) {
	visible := 0
	for _, fl := range flags {
		if !fl.Suppressed {
			visible++
		}
	}
	if visible == 0 {
		return
	}
	fmt.Fprintf(cp.p.w, "  %s%s:%s\n", cp.p.dim(), label, cp.p.reset())
	for _, fl := range flags {
		if fl.Suppressed {
			continue
		}
		fmt.Fprintf(cp.p.w, "    %s%s %s%s%s — %s  %s(+%d)%s\n",
			cp.p.dim(), marker,
			cp.p.yellow(), fl.Code, cp.p.reset(),
			fl.Detail,
			cp.p.dim(), fl.Weight, cp.p.reset())
	}
}

// renderSummary prints the final PASS/FAIL line with per-bucket counts.
func (cp *CIPresenter) renderSummary(r usecase.CIResult) {
	s := r.Summary
	bucket := fmt.Sprintf("%d total • %d safe • %d review • %d prompt • %d block",
		s.Total, s.Safe, s.Review, s.Prompt, s.Blocked)
	if r.Passed {
		fmt.Fprintf(cp.p.w, "\n%s[aegis]%s %s%sPASS%s — %s (threshold: %s)\n",
			cp.p.dim(), cp.p.reset(),
			cp.p.green(), cp.p.bold(), cp.p.reset(),
			bucket, r.FailOn)
		return
	}
	fmt.Fprintf(cp.p.w, "\n%s[aegis]%s %s%sFAIL%s — %d finding(s) ≥ %s  (%s)\n",
		cp.p.dim(), cp.p.reset(),
		cp.p.red(), cp.p.bold(), cp.p.reset(),
		len(r.Findings), r.FailOn, bucket)
}

// --- JSON shapes --------------------------------------------------------

type ciJSONResult struct {
	Project  string         `json:"project"`
	FailOn   string         `json:"fail_on"`
	Enriched bool           `json:"enriched"`
	Passed   bool           `json:"passed"`
	Summary  ciSummaryJSON  `json:"summary"`
	Findings []ciFindingJSON `json:"findings"`
}

type ciSummaryJSON struct {
	Total   int `json:"total"`
	Safe    int `json:"safe"`
	Review  int `json:"review"`
	Prompt  int `json:"prompt"`
	Blocked int `json:"blocked"`
}

type ciFindingJSON struct {
	Ecosystem  string              `json:"ecosystem"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	Direct     bool                `json:"direct"`
	Verdict    string              `json:"verdict"`
	RiskScore  int                 `json:"risk_score"`
	DriftScore int                 `json:"drift_score,omitempty"`
	Flags      []ciFindingFlagJSON `json:"flags,omitempty"`
	DriftFlags []ciFindingFlagJSON `json:"drift_flags,omitempty"`
}

type ciFindingFlagJSON struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Weight int    `json:"weight"`
}

type ciErrorJSON struct {
	Error string `json:"error"`
}

// flagsToJSON drops suppressed flags and copies the rest to the
// JSON shape. Suppressed flags are an explanation aid for `aegis
// explain`, not a finding the CI consumer should act on.
func flagsToJSON(flags []domain.RiskFlag) []ciFindingFlagJSON {
	out := make([]ciFindingFlagJSON, 0, len(flags))
	for _, fl := range flags {
		if fl.Suppressed {
			continue
		}
		out = append(out, ciFindingFlagJSON{
			Code: fl.Code, Detail: fl.Detail, Weight: fl.Weight,
		})
	}
	return out
}

func toCIJSONResult(r usecase.CIResult) ciJSONResult {
	out := ciJSONResult{
		Project:  r.ProjectName,
		FailOn:   r.FailOn.String(),
		Enriched: r.Enriched,
		Passed:   r.Passed,
		Summary: ciSummaryJSON{
			Total:   r.Summary.Total,
			Safe:    r.Summary.Safe,
			Review:  r.Summary.Review,
			Prompt:  r.Summary.Prompt,
			Blocked: r.Summary.Blocked,
		},
		Findings: make([]ciFindingJSON, 0, len(r.Findings)),
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, ciFindingJSON{
			Ecosystem:  string(f.Dep.Ecosystem),
			Name:       f.Dep.Name,
			Version:    f.Dep.Version,
			Direct:     f.Dep.Direct,
			Verdict:    f.Verdict.String(),
			RiskScore:  f.Risk.Score,
			DriftScore: f.Drift.Score,
			Flags:      flagsToJSON(f.Risk.Flags),
			DriftFlags: flagsToJSON(f.Drift.Flags),
		})
	}
	return out
}
