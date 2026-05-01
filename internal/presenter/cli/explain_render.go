package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

// ExplainPresenter satisfies usecase.ExplainPresenter. The human
// renderer leans into capability descriptions and per-flag breakdown
// so a non-security person can read the output and understand why
// a dep was flagged.
type ExplainPresenter struct {
	p        *Presenter
	jsonOut  io.Writer
	jsonMode bool
}

// NewExplainPresenter wraps a base Presenter for stderr; JSON to stdout.
func NewExplainPresenter(base *Presenter) *ExplainPresenter {
	return &ExplainPresenter{p: base, jsonOut: os.Stdout}
}

func (ep *ExplainPresenter) SetJSONMode(on bool) *ExplainPresenter { ep.jsonMode = on; return ep }
func (ep *ExplainPresenter) SetJSONWriter(w io.Writer) *ExplainPresenter {
	ep.jsonOut = w
	return ep
}

// OnExplainError surfaces a fetch / lookup failure.
func (ep *ExplainPresenter) OnExplainError(eco domain.Ecosystem, name, version string, err error) {
	if ep.jsonMode {
		_ = json.NewEncoder(ep.jsonOut).Encode(map[string]string{
			"ecosystem": string(eco), "name": name, "version": version,
			"error": err.Error(),
		})
		return
	}
	fmt.Fprintf(ep.p.w, "%s[aegis]%s %s%s! %s/%s@%s — %v%s\n",
		ep.p.dim(), ep.p.reset(),
		ep.p.red(), ep.p.bold(),
		eco, name, version, err, ep.p.reset())
}

// OnExplainResult prints the deep dive: header, capabilities with
// descriptions, hooks, env reads, evidence (if present), source size.
func (ep *ExplainPresenter) OnExplainResult(r usecase.ExplainResult) {
	if ep.jsonMode {
		_ = json.NewEncoder(ep.jsonOut).Encode(toExplainJSON(r))
		return
	}

	marker, color := analyzeVerdictMarker(ep.p, r.Verdict) // shared with analyze
	fmt.Fprintf(ep.p.w, "%s%s%s %s/%s@%s — %sverdict=%s%s  risk=%d  %s(source: %s)%s\n",
		color, marker, ep.p.reset(),
		r.Ecosystem, r.Name, r.Version,
		color, r.Verdict, ep.p.reset(),
		r.Risk.Score,
		ep.p.dim(), r.Source, ep.p.reset())

	caps := []domain.Capability{}
	for _, c := range r.Fingerprint.Capabilities {
		caps = append(caps, c)
	}
	if len(caps) > 0 {
		fmt.Fprintf(ep.p.w, "\n%sCapabilities%s — what this package can do:\n",
			ep.p.bold(), ep.p.reset())
		for _, c := range caps {
			fmt.Fprintf(ep.p.w, "  %s•%s %s%s%s\n      %s\n",
				ep.p.dim(), ep.p.reset(),
				ep.p.bold(), c.String(), ep.p.reset(),
				c.Description())
		}
	}

	if len(r.Risk.Flags) > 0 {
		fmt.Fprintf(ep.p.w, "\n%sRisk flags%s — score breakdown (suppressed flags shown but not counted):\n",
			ep.p.bold(), ep.p.reset())
		for _, f := range r.Risk.Flags {
			ep.renderFlag(f)
		}
	}

	if len(r.Fingerprint.Hooks) > 0 {
		fmt.Fprintf(ep.p.w, "\n%sInstall hooks%s — scripts the package manager runs automatically:\n",
			ep.p.bold(), ep.p.reset())
		for _, h := range r.Fingerprint.Hooks {
			fmt.Fprintf(ep.p.w, "  %s•%s %s  %s",
				ep.p.dim(), ep.p.reset(), h.Phase, h.Source)
			if h.Sha256 != "" {
				fmt.Fprintf(ep.p.w, "  sha256:%s", shortHash(h.Sha256))
			}
			fmt.Fprintln(ep.p.w)
		}
	}

	if len(r.Fingerprint.EnvReads) > 0 {
		fmt.Fprintf(ep.p.w, "\n%sEnv reads%s — process environment variables this package reads:\n",
			ep.p.bold(), ep.p.reset())
		for _, e := range r.Fingerprint.EnvReads {
			fmt.Fprintf(ep.p.w, "  %s•%s %s\n", ep.p.dim(), ep.p.reset(), e)
		}
	}

	if len(r.Evidence) > 0 {
		fmt.Fprintf(ep.p.w, "\n%sEvidence%s — where each capability was detected (fresh-scan only):\n",
			ep.p.bold(), ep.p.reset())
		for _, ev := range r.Evidence {
			fmt.Fprintf(ep.p.w, "  %s%s%s  %s:%d\n      %s\n",
				ep.p.dim(), ev.Capability, ep.p.reset(),
				ev.File, ev.Line, ev.Snippet)
		}
	}

	if r.SourceBytes > 0 {
		fmt.Fprintf(ep.p.w, "\n%sSource size:%s %s\n",
			ep.p.bold(), ep.p.reset(), humanSizeI64(int64(r.SourceBytes)))
	}
	if r.TarballSha256 != "" {
		fmt.Fprintf(ep.p.w, "%sTarball:%s sha256:%s\n",
			ep.p.bold(), ep.p.reset(), shortHash(r.TarballSha256))
	}
}

// renderFlag prints one flag line with allowlist suppression context.
func (ep *ExplainPresenter) renderFlag(f domain.RiskFlag) {
	if f.Suppressed {
		fmt.Fprintf(ep.p.w, "  %s~ %s%s%s — %s  %s(weight +%d, suppressed by allowlist: %s)%s\n",
			ep.p.dim(),
			ep.p.dim(), f.Code, ep.p.reset(),
			f.Detail,
			ep.p.dim(), f.Weight, f.SuppressBy, ep.p.reset())
		return
	}
	fmt.Fprintf(ep.p.w, "  %s+ %s%s%s — %s  %s(weight +%d)%s\n",
		ep.p.dim(),
		ep.p.yellow(), f.Code, ep.p.reset(),
		f.Detail,
		ep.p.dim(), f.Weight, ep.p.reset())
}

// humanSizeI64 wraps humanSize for int64 inputs (humanSize takes int).
func humanSizeI64(n int64) string {
	const k int64 = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(k))
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(k*k))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(k*k*k))
	}
}

// --- JSON shape --------------------------------------------------------

type explainJSON struct {
	Source        string                  `json:"source"`
	Ecosystem     string                  `json:"ecosystem"`
	Name          string                  `json:"name"`
	Version       string                  `json:"version"`
	Direct        bool                    `json:"direct"`
	Verdict       string                  `json:"verdict"`
	RiskScore     int                     `json:"risk_score"`
	Capabilities  []explainCapabilityJSON `json:"capabilities,omitempty"`
	Hooks         []explainHookJSON       `json:"hooks,omitempty"`
	EnvReads      []string                `json:"env_reads,omitempty"`
	Flags         []explainFlagJSON       `json:"flags,omitempty"`
	Evidence      []explainEvidenceJSON   `json:"evidence,omitempty"`
	TarballSha256 string                  `json:"tarball_sha256,omitempty"`
	SourceBytes   int                     `json:"source_bytes"`
}

type explainCapabilityJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type explainHookJSON struct {
	Phase  string `json:"phase"`
	Source string `json:"source"`
	Sha256 string `json:"sha256,omitempty"`
}

type explainFlagJSON struct {
	Code         string `json:"code"`
	Detail       string `json:"detail"`
	Weight       int    `json:"weight"`
	Suppressed   bool   `json:"suppressed,omitempty"`
	SuppressedBy string `json:"suppressed_by,omitempty"`
}

type explainEvidenceJSON struct {
	Capability string `json:"capability"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Snippet    string `json:"snippet,omitempty"`
}

func toExplainJSON(r usecase.ExplainResult) explainJSON {
	caps := make([]explainCapabilityJSON, 0, len(r.Fingerprint.Capabilities))
	for _, c := range r.Fingerprint.Capabilities {
		caps = append(caps, explainCapabilityJSON{
			Name:        c.String(),
			Description: c.Description(),
		})
	}
	hooks := make([]explainHookJSON, 0, len(r.Fingerprint.Hooks))
	for _, h := range r.Fingerprint.Hooks {
		hooks = append(hooks, explainHookJSON{
			Phase: h.Phase.String(), Source: h.Source, Sha256: h.Sha256,
		})
	}
	flags := make([]explainFlagJSON, 0, len(r.Risk.Flags))
	for _, f := range r.Risk.Flags {
		flags = append(flags, explainFlagJSON{
			Code: f.Code, Detail: f.Detail, Weight: f.Weight,
			Suppressed: f.Suppressed, SuppressedBy: f.SuppressBy,
		})
	}
	ev := make([]explainEvidenceJSON, 0, len(r.Evidence))
	for _, e := range r.Evidence {
		ev = append(ev, explainEvidenceJSON{
			Capability: e.Capability.String(),
			File:       e.File, Line: e.Line, Snippet: e.Snippet,
		})
	}
	return explainJSON{
		Source:        r.Source,
		Ecosystem:     string(r.Ecosystem),
		Name:          r.Name,
		Version:       r.Version,
		Direct:        r.Direct,
		Verdict:       r.Verdict.String(),
		RiskScore:     r.Risk.Score,
		Capabilities:  caps,
		Hooks:         hooks,
		EnvReads:      r.Fingerprint.EnvReads,
		Flags:         flags,
		Evidence:      ev,
		TarballSha256: r.TarballSha256,
		SourceBytes:   r.SourceBytes,
	}
}
