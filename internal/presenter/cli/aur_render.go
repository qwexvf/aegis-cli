package cli

import (
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// AURPresenter renders AUR PKGBUILD scan results. It satisfies
// usecase.AURPresenter.
type AURPresenter struct {
	p *Presenter
}

// NewAURPresenter wraps the base presenter.
func NewAURPresenter(base *Presenter) *AURPresenter { return &AURPresenter{p: base} }

// OnAURResult prints the verdict header and one line per finding.
func (a *AURPresenter) OnAURResult(res domain.AURScanResult) {
	p := a.p
	var tag, color string
	switch res.Verdict {
	case domain.AURBlock:
		tag, color = "BLOCK", p.red()
	case domain.AURWarn:
		tag, color = "WARN", p.yellow()
	default:
		tag, color = "OK", p.green()
	}
	fmt.Fprintf(p.w, "%s[aegis]%s %s%s%s %s%s\n",
		p.dim(), p.reset(), color, p.bold(), tag, res.Package, p.reset())

	for _, f := range res.Findings {
		fmt.Fprintf(p.w, "  %s%s%s %s — %s\n",
			severityColor(p, f.Severity), f.Severity.String(), p.reset(),
			f.Where, f.Message)
		if f.Evidence != "" {
			fmt.Fprintf(p.w, "    %s%s%s\n", p.dim(), f.Evidence, p.reset())
		}
	}
	if res.Verdict == domain.AURBlock {
		fmt.Fprintf(p.w, "  %s%sinstall blocked — inspect the PKGBUILD before proceeding%s\n",
			p.red(), p.bold(), p.reset())
	}
}

// OnAURSkipped notes a package that was not scanned.
func (a *AURPresenter) OnAURSkipped(name, reason string) {
	p := a.p
	fmt.Fprintf(p.w, "%s[aegis]%s skip %s (%s)\n", p.dim(), p.reset(), name, reason)
}

// OnAURInfo prints a generic line.
func (a *AURPresenter) OnAURInfo(message string) {
	p := a.p
	fmt.Fprintf(p.w, "%s[aegis]%s %s\n", p.dim(), p.reset(), message)
}

func severityColor(p *Presenter, s domain.AURSeverity) string {
	switch s {
	case domain.AURCritical, domain.AURHigh:
		return p.red()
	case domain.AURMedium:
		return p.yellow()
	default:
		return p.dim()
	}
}
