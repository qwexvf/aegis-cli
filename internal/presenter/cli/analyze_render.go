package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

// AnalyzePresenter satisfies usecase.AnalyzePresenter. It writes
// progress / verdict to a base Presenter (stderr by default) and, in
// JSON mode, emits one machine-readable object to stdout. Construct
// via NewAnalyzePresenter.
type AnalyzePresenter struct {
	p        *Presenter
	jsonOut  io.Writer // typically os.Stdout — kept separate from p.w (typically stderr)
	jsonMode bool
}

// NewAnalyzePresenter wraps a base Presenter for stderr output. JSON
// mode is opt-in (analyze --json); when enabled, OnAnalyzeResult also
// writes a one-shot JSON object to stdout and the human renderer is
// skipped.
func NewAnalyzePresenter(base *Presenter) *AnalyzePresenter {
	return &AnalyzePresenter{p: base, jsonOut: os.Stdout}
}

// SetJSONMode toggles JSON output. Returns the receiver for chaining
// at the call site.
func (ap *AnalyzePresenter) SetJSONMode(on bool) *AnalyzePresenter {
	ap.jsonMode = on
	return ap
}

// SetJSONWriter overrides the JSON destination. Tests inject a buffer.
func (ap *AnalyzePresenter) SetJSONWriter(w io.Writer) *AnalyzePresenter {
	ap.jsonOut = w
	return ap
}

// OnAnalyzeStart prints the header line. JSON mode keeps stderr quiet
// so a downstream `| jq` pipe stays clean.
func (ap *AnalyzePresenter) OnAnalyzeStart(eco domain.Ecosystem, name, version string) {
	if ap.jsonMode {
		return
	}
	fmt.Fprintf(ap.p.w, "%s[aegis]%s analyzing %s/%s@%s ...\n",
		ap.p.dim(), ap.p.reset(), eco, name, version)
}

// OnAnalyzeStage prints the per-stage progress label (fetch / scan).
func (ap *AnalyzePresenter) OnAnalyzeStage(stage usecase.EnrichStage) {
	if ap.jsonMode {
		return
	}
	fmt.Fprintf(ap.p.w, "%s[aegis]%s %s ...\n",
		ap.p.dim(), ap.p.reset(), stage)
}

// OnAnalyzeError surfaces a fetch/analyze failure.
func (ap *AnalyzePresenter) OnAnalyzeError(eco domain.Ecosystem, name, version string, err error) {
	if ap.jsonMode {
		// Emit error as JSON so consumers can branch on it without
		// parsing stderr.
		_ = json.NewEncoder(ap.jsonOut).Encode(analyzeErrorJSON{
			Ecosystem: string(eco),
			Name:      name,
			Version:   version,
			Error:     err.Error(),
		})
		return
	}
	fmt.Fprintf(ap.p.w, "%s[aegis]%s %s%s! %s/%s@%s — %v%s\n",
		ap.p.dim(), ap.p.reset(),
		ap.p.red(), ap.p.bold(),
		eco, name, version, err, ap.p.reset())
}

// OnAnalyzeResult renders the verdict. In JSON mode, emits the
// AnalyzeResult to stdout as a single object; in human mode, prints a
// formatted block to stderr including capabilities, hooks, env reads,
// and (when withEvidence) per-capture file:line snippets.
func (ap *AnalyzePresenter) OnAnalyzeResult(r usecase.AnalyzeResult, withEvidence bool) {
	if ap.jsonMode {
		_ = json.NewEncoder(ap.jsonOut).Encode(toJSONResult(r, withEvidence))
		return
	}

	marker, color := analyzeVerdictMarker(ap.p, r.Verdict)
	fmt.Fprintf(ap.p.w, "\n%s%s%s %s/%s@%s — %sverdict=%s%s  risk=%d\n",
		color, marker, ap.p.reset(),
		r.Ecosystem, r.Name, r.Version,
		color, r.Verdict, ap.p.reset(),
		r.Risk.Score)

	if len(r.Fingerprint.Capabilities) > 0 || len(r.Risk.Flags) > 0 {
		fmt.Fprintf(ap.p.w, "\n%sCapabilities:%s\n", ap.p.bold(), ap.p.reset())
		for _, f := range r.Risk.Flags {
			ap.renderRiskFlag(f)
		}
	}
	if len(r.Fingerprint.Hooks) > 0 {
		fmt.Fprintf(ap.p.w, "\n%sHooks:%s\n", ap.p.bold(), ap.p.reset())
		for _, h := range r.Fingerprint.Hooks {
			line := fmt.Sprintf("  %s  %s", h.Phase, h.Source)
			if h.Sha256 != "" {
				line += "  sha256:" + shortHash(h.Sha256)
			}
			fmt.Fprintln(ap.p.w, line)
		}
	}
	if len(r.Fingerprint.EnvReads) > 0 {
		fmt.Fprintf(ap.p.w, "\n%sEnv reads:%s  %s\n",
			ap.p.bold(), ap.p.reset(),
			strings.Join(r.Fingerprint.EnvReads, ", "))
	}
	if withEvidence && len(r.Evidence) > 0 {
		fmt.Fprintf(ap.p.w, "\n%sEvidence:%s\n", ap.p.bold(), ap.p.reset())
		for _, e := range r.Evidence {
			fmt.Fprintf(ap.p.w, "  %s%s%s  %s:%d\n    %s\n",
				ap.p.dim(), e.Capability, ap.p.reset(),
				e.File, e.Line, e.Snippet)
		}
	}

	fmt.Fprintf(ap.p.w, "\n%sSource:%s  %s across %d files\n",
		ap.p.bold(), ap.p.reset(),
		humanSize(r.SourceBytes), r.FilesAnalyzed)
	if r.TarballSha256 != "" {
		fmt.Fprintf(ap.p.w, "%sTarball:%s sha256:%s\n",
			ap.p.bold(), ap.p.reset(), shortHash(r.TarballSha256))
	}
}

// renderRiskFlag prints one capability line. Suppressed flags get a ~
// marker and "(suppressed +N, allowlisted: <reason>)" trailer so the
// reader still sees the original weight while it's clear it didn't
// count toward the score.
func (ap *AnalyzePresenter) renderRiskFlag(f domain.RiskFlag) {
	if f.Suppressed {
		fmt.Fprintf(ap.p.w, "  %s~ %s%s%s — %s  %s(suppressed +%d, allowlisted: %s)%s\n",
			ap.p.dim(),
			ap.p.dim(), f.Code, ap.p.reset(),
			f.Detail,
			ap.p.dim(), f.Weight, f.SuppressBy, ap.p.reset())
		return
	}
	fmt.Fprintf(ap.p.w, "  %s⚠ %s%s%s — %s  %s(+%d)%s\n",
		ap.p.dim(),
		ap.p.yellow(), f.Code, ap.p.reset(),
		f.Detail,
		ap.p.dim(), f.Weight, ap.p.reset())
}

func analyzeVerdictMarker(p *Presenter, v domain.VerdictKind) (marker, color string) {
	switch v {
	case domain.VerdictBlock:
		return "✗", p.red()
	case domain.VerdictPrompt:
		return "⚠", p.red()
	case domain.VerdictReview:
		return "⚠", p.yellow()
	default:
		return "✓", p.green()
	}
}

// shortHash truncates a hex sha256 to its first 12 chars for the
// human view; the JSON output keeps the full hash.
func shortHash(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// humanSize formats a byte count as "1.2 KB" / "456 MB" with one
// decimal for K/M/G — readable without jq.
func humanSize(n int) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KB", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/(k*k))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/(k*k*k))
	}
}

// --- JSON shapes --------------------------------------------------------

type analyzeErrorJSON struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Error     string `json:"error"`
}

type analyzeJSON struct {
	Ecosystem     string             `json:"ecosystem"`
	Name          string             `json:"name"`
	Version       string             `json:"version"`
	Verdict       string             `json:"verdict"`
	RiskScore     int                `json:"risk_score"`
	Capabilities  []string           `json:"capabilities"`
	Hooks         []analyzeHookJSON  `json:"hooks,omitempty"`
	EnvReads      []string           `json:"env_reads,omitempty"`
	RiskFlags     []analyzeFlagJSON  `json:"risk_flags,omitempty"`
	Evidence      []analyzeEvidJSON  `json:"evidence,omitempty"`
	TarballSha256 string             `json:"tarball_sha256,omitempty"`
	FilesAnalyzed int                `json:"files_analyzed"`
	SourceBytes   int                `json:"source_bytes"`
}

type analyzeHookJSON struct {
	Phase  string `json:"phase"`
	Source string `json:"source"`
	Sha256 string `json:"sha256,omitempty"`
}

type analyzeFlagJSON struct {
	Code       string `json:"code"`
	Detail     string `json:"detail"`
	Weight     int    `json:"weight"`
	Suppressed bool   `json:"suppressed,omitempty"`
	SuppressBy string `json:"suppressed_by,omitempty"`
}

type analyzeEvidJSON struct {
	Capability string `json:"capability"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Snippet    string `json:"snippet,omitempty"`
}

func toJSONResult(r usecase.AnalyzeResult, withEvidence bool) analyzeJSON {
	caps := make([]string, 0, len(r.Fingerprint.Capabilities))
	for _, c := range r.Fingerprint.Capabilities {
		caps = append(caps, c.String())
	}
	hooks := make([]analyzeHookJSON, 0, len(r.Fingerprint.Hooks))
	for _, h := range r.Fingerprint.Hooks {
		hooks = append(hooks, analyzeHookJSON{
			Phase: h.Phase.String(), Source: h.Source, Sha256: h.Sha256,
		})
	}
	flags := make([]analyzeFlagJSON, 0, len(r.Risk.Flags))
	for _, f := range r.Risk.Flags {
		flags = append(flags, analyzeFlagJSON{
			Code: f.Code, Detail: f.Detail, Weight: f.Weight,
			Suppressed: f.Suppressed, SuppressBy: f.SuppressBy,
		})
	}
	var ev []analyzeEvidJSON
	if withEvidence {
		ev = make([]analyzeEvidJSON, 0, len(r.Evidence))
		for _, e := range r.Evidence {
			ev = append(ev, analyzeEvidJSON{
				Capability: e.Capability.String(),
				File:       e.File, Line: e.Line, Snippet: e.Snippet,
			})
		}
	}
	return analyzeJSON{
		Ecosystem:     string(r.Ecosystem),
		Name:          r.Name,
		Version:       r.Version,
		Verdict:       r.Verdict.String(),
		RiskScore:     r.Risk.Score,
		Capabilities:  caps,
		Hooks:         hooks,
		EnvReads:      r.Fingerprint.EnvReads,
		RiskFlags:     flags,
		Evidence:      ev,
		TarballSha256: r.TarballSha256,
		FilesAnalyzed: r.FilesAnalyzed,
		SourceBytes:   r.SourceBytes,
	}
}
