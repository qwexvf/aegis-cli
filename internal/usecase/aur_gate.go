package usecase

import (
	"context"
	"errors"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// AURFetcher pulls an AUR package's PKGBUILD + .install hooks.
// Implementation: infra/aursource.
type AURFetcher interface {
	Fetch(ctx context.Context, name string) (domain.AURPackage, error)
}

// AURPresenter renders AUR scan results. Implementation: presenter/cli.
type AURPresenter interface {
	OnAURResult(res domain.AURScanResult)
	OnAURSkipped(name, reason string)
	OnAURInfo(message string)
}

// AURGate scans AUR install targets before the helper (paru/yay/pacman)
// builds them. It fetches each package's PKGBUILD, runs the static
// malware scanner, and decides Allow / Warn / Block. Packages not found
// in the AUR (official-repo packages) are skipped — pacman handles those
// from signed repos.
type AURGate struct {
	fetcher   AURFetcher
	confirm   Confirmer
	presenter AURPresenter
}

// NewAURGate wires the gate. confirm may be nil (no prompt → Warn is
// treated as a pass with a printed warning).
func NewAURGate(f AURFetcher, confirm Confirmer, p AURPresenter) *AURGate {
	return &AURGate{fetcher: f, confirm: confirm, presenter: p}
}

// AURRequest is the gate input.
type AURRequest struct {
	HelperName string
	Targets    []string
}

// AURResult is the gate decision.
type AURResult struct {
	AnyBlocked bool
}

// Run scans every target and reports whether any was blocked. A Block
// verdict, or a Warn the user declines, sets AnyBlocked. Fetch failures
// for a package that simply isn't in the AUR are skipped silently.
func (g *AURGate) Run(ctx context.Context, req AURRequest) (AURResult, error) {
	var out AURResult
	for _, name := range req.Targets {
		pkg, err := g.fetcher.Fetch(ctx, name)
		if err != nil {
			if isNotInAUR(err) {
				g.presenter.OnAURSkipped(name, "not an AUR package")
				continue
			}
			// Fail-open on transient fetch errors but make it loud — we
			// don't want a flaky network to block every install, but the
			// user must know the package went unscanned.
			g.presenter.OnAURSkipped(name, "fetch failed: "+err.Error())
			continue
		}

		res := domain.ScanPKGBUILD(pkg)
		g.presenter.OnAURResult(res)

		switch res.Verdict {
		case domain.AURBlock:
			out.AnyBlocked = true
		case domain.AURWarn:
			if !g.confirmProceed(name) {
				out.AnyBlocked = true
			}
		}
	}
	return out, nil
}

// confirmProceed asks the human whether to proceed past a Warn. With no
// confirmer (non-TTY), it defaults to proceed but the warning is already
// printed — the gate never silently blocks on a non-critical finding.
func (g *AURGate) confirmProceed(name string) bool {
	if g.confirm == nil {
		return true
	}
	switch g.confirm.Confirm("Proceed with installing " + name + " despite warnings?") {
	case ConfirmDeny:
		return false
	default: // ConfirmAllow or ConfirmUnavailable
		return true
	}
}

// isNotInAUR recognises the fetcher's "not found in AUR" error so the
// gate can skip official-repo packages.
func isNotInAUR(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found in AUR") || errors.Is(err, errNotInAUR)
}

// errNotInAUR is exported via isNotInAUR for adapters that prefer a
// sentinel over a string match.
var errNotInAUR = errors.New("not found in AUR")
