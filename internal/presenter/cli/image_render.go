package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// ImagePresenter satisfies usecase.ImagePresenter. Renders the
// extracted dep list to stderr in human mode or stdout as JSON.
type ImagePresenter struct {
	p        *Presenter
	jsonOut  io.Writer
	jsonMode bool
}

// NewImagePresenter wraps a base Presenter; stdout for JSON.
func NewImagePresenter(base *Presenter) *ImagePresenter {
	return &ImagePresenter{p: base, jsonOut: os.Stdout}
}

// SetJSONMode toggles JSON output.
func (ip *ImagePresenter) SetJSONMode(on bool) *ImagePresenter {
	ip.jsonMode = on
	return ip
}

// SetJSONWriter overrides the stdout destination (for tests).
func (ip *ImagePresenter) SetJSONWriter(w io.Writer) *ImagePresenter {
	ip.jsonOut = w
	return ip
}

func (ip *ImagePresenter) OnImageBegin(req usecase.ImageRequest) {
	if ip.jsonMode {
		return
	}
	fmt.Fprintf(ip.p.w, "%s[aegis]%s image scan: %s\n",
		ip.p.dim(), ip.p.reset(), req.Path)
}

func (ip *ImagePresenter) OnImageError(err error) {
	if ip.jsonMode {
		_ = json.NewEncoder(ip.jsonOut).Encode(imageErrorJSON{Error: err.Error()})
		return
	}
	fmt.Fprintf(ip.p.w, "%s[aegis]%s %s! %v%s\n",
		ip.p.dim(), ip.p.reset(),
		ip.p.red(), err, ip.p.reset())
}

func (ip *ImagePresenter) OnImageResult(r usecase.ImageResult) {
	if ip.jsonMode {
		_ = json.NewEncoder(ip.jsonOut).Encode(toImageJSONResult(r))
		return
	}
	if len(r.Deps) == 0 {
		fmt.Fprintf(ip.p.w, "%s[aegis]%s no recognised lockfiles in image\n",
			ip.p.dim(), ip.p.reset())
		return
	}
	withVuln := 0
	totalVuln := 0
	for _, d := range r.Deps {
		if len(d.Advisories) > 0 {
			withVuln++
			totalVuln += len(d.Advisories)
		}
	}
	if r.Enriched {
		fmt.Fprintf(ip.p.w, "%s[aegis]%s %d deps extracted • %d advisories across %d packages\n",
			ip.p.dim(), ip.p.reset(), len(r.Deps), totalVuln, withVuln)
	} else {
		fmt.Fprintf(ip.p.w, "%s[aegis]%s %d deps extracted (run with --enrich for vuln lookup)\n",
			ip.p.dim(), ip.p.reset(), len(r.Deps))
	}
	for _, d := range r.Deps {
		if len(d.Advisories) == 0 {
			continue
		}
		fmt.Fprintf(ip.p.w, "\n  %s/%s@%s\n", d.Ecosystem, d.Name, d.Version)
		for _, a := range d.Advisories {
			sev := a.Severity
			color := ip.p.dim()
			switch sev {
			case domain.SevCritical, domain.SevHigh:
				color = ip.p.red()
			case domain.SevMedium:
				color = ip.p.yellow()
			}
			fmt.Fprintf(ip.p.w, "    %s•%s %s%s%s [%s] — %s\n",
				ip.p.dim(), ip.p.reset(),
				color, a.ID, ip.p.reset(),
				a.Severity, a.Summary)
		}
	}
}

// --- JSON shapes -------------------------------------------------------

type imageJSONResult struct {
	ImagePath string         `json:"image_path"`
	Enriched  bool           `json:"enriched"`
	Total     int            `json:"total"`
	Deps      []imageJSONDep `json:"deps"`
}

type imageJSONDep struct {
	Ecosystem  string              `json:"ecosystem"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	Advisories []imageJSONAdvisory `json:"advisories,omitempty"`
}

type imageJSONAdvisory struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	URL      string `json:"url,omitempty"`
	FixedIn  string `json:"fixed_in,omitempty"`
}

type imageErrorJSON struct {
	Error string `json:"error"`
}

func toImageJSONResult(r usecase.ImageResult) imageJSONResult {
	out := imageJSONResult{
		ImagePath: r.ImagePath,
		Enriched:  r.Enriched,
		Total:     len(r.Deps),
		Deps:      make([]imageJSONDep, 0, len(r.Deps)),
	}
	for _, d := range r.Deps {
		j := imageJSONDep{
			Ecosystem: string(d.Ecosystem),
			Name:      d.Name,
			Version:   d.Version,
		}
		for _, a := range d.Advisories {
			j.Advisories = append(j.Advisories, imageJSONAdvisory{
				ID:       a.ID,
				Severity: string(a.Severity),
				Summary:  a.Summary,
				URL:      a.URL,
				FixedIn:  a.FixedIn,
			})
		}
		out.Deps = append(out.Deps, j)
	}
	return out
}
