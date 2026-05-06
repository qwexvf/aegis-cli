package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// InstallGate is the install-time policy gate. Given a list of
// PackageSpecs to install, it consults the cache + API for each,
// applies the policy, and reports outcomes. It does NOT exec the
// underlying package manager — that's the interface layer's job.
type InstallGate struct {
	resolver  VersionResolver
	checker   DecisionChecker
	cache     DecisionCache
	audit     AuditWriter
	confirm   Confirmer
	env       EnvProbe
	presenter Presenter

	timeout time.Duration
}

// InstallGateDeps bundles every port InstallGate needs. Resolver,
// Checker, and Presenter are required; Cache/Audit/Confirm/Env have
// safe nil-handlers and may be omitted.
type InstallGateDeps struct {
	Resolver  VersionResolver
	Checker   DecisionChecker
	Cache     DecisionCache
	Audit     AuditWriter
	Confirm   Confirmer
	Env       EnvProbe
	Presenter Presenter
}

// NewInstallGate constructs the gate from its ports.
func NewInstallGate(d InstallGateDeps) *InstallGate {
	return &InstallGate{
		resolver:  d.Resolver,
		checker:   d.Checker,
		cache:     d.Cache,
		audit:     d.Audit,
		confirm:   d.Confirm,
		env:       d.Env,
		presenter: d.Presenter,
		timeout:   20 * time.Second,
	}
}

// Request is the gate's input.
type Request struct {
	PMName      string // for presenter override hints
	InstallVerb string // "install" / "add"
	Specs       []domain.PackageSpec
}

// Result is the gate's verdict over a whole request.
type Result struct {
	Outcomes   []domain.Outcome
	AnyBlocked bool
}

// Run evaluates every spec and returns the aggregate result. The
// caller decides what to do with AnyBlocked (the CLI exits with code 1).
func (g *InstallGate) Run(ctx context.Context, req Request) (Result, error) {
	var res Result

	overrideAllow, overrideReason := g.readOverride()
	overrideRefused := overrideAllow && overrideReason == ""
	if overrideRefused {
		g.presenter.OnInfo("AEGIS_OVERRIDE_REASON required to override — refusing")
	}

	pcBase := domain.PolicyContext{
		InCI:              g.envIsCI(),
		OverrideAllow:     overrideAllow && !overrideRefused,
		OverrideReason:    overrideReason,
		HasInteractiveTTY: g.confirmAvailable(),
	}

	cctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	for _, spec := range req.Specs {
		if spec.NonRegistry {
			g.presenter.OnSkipped(spec)
			continue
		}

		resolved, err := g.resolveVersion(cctx, spec)
		if err != nil {
			g.presenter.OnResolveError(spec, err)
			continue
		}

		decision, fromCache, ok := g.fetchDecision(cctx, spec, resolved)
		if !ok {
			// fail-open: API errored, render was already done by fetchDecision.
			// Audit the failure so we know the gate didn't actually verify.
			g.recordAudit(domain.Outcome{
				Decision: domain.Decision{
					Spec:     spec,
					Resolved: resolved,
					Source:   domain.SourceError,
				},
				Action: domain.ActionProceed,
			})
			continue
		}

		g.presenter.OnResolveStart(spec, resolved, fromCache)
		g.presenter.OnDecision(decision)

		outcome := domain.Evaluate(decision, pcBase)

		if outcome.Action == domain.ActionAskUser {
			outcome = g.askHuman(spec, resolved, outcome)
		}

		g.presenter.OnOutcome(outcome, req.PMName, req.InstallVerb)
		g.recordAudit(outcome)

		if outcome.Action == domain.ActionBlock {
			res.AnyBlocked = true
		}
		res.Outcomes = append(res.Outcomes, outcome)
	}

	return res, nil
}

func (g *InstallGate) resolveVersion(ctx context.Context, spec domain.PackageSpec) (string, error) {
	if spec.IsExactVersion() {
		return spec.Version, nil
	}
	return g.resolver.Resolve(ctx, spec.Ecosystem, spec.Name, spec.Version)
}

// fetchDecision tries the cache first, then the API. Returns
// (decision, fromCache, ok). When ok is false the caller should
// fail-open (API error already presented).
func (g *InstallGate) fetchDecision(ctx context.Context, spec domain.PackageSpec, resolved string) (domain.Decision, bool, bool) {
	key := CacheKey(spec.Ecosystem, spec.Name, resolved)
	if g.cache != nil {
		if d, ok := g.cache.Get(key); ok {
			d.Spec = spec
			d.Resolved = resolved
			d.Source = domain.SourceCache
			return d, true, true
		}
	}

	d, err := g.checker.Check(ctx, spec.Ecosystem, spec.Name, resolved)
	if err != nil {
		g.presenter.OnAPIError(spec, resolved, err)
		return domain.Decision{}, false, false
	}
	d.Spec = spec
	d.Resolved = resolved
	d.Source = domain.SourceAPI

	if g.cache != nil {
		_ = g.cache.Put(key, d) // best-effort
	}
	return d, false, true
}

func (g *InstallGate) askHuman(spec domain.PackageSpec, resolved string, o domain.Outcome) domain.Outcome {
	if g.confirm == nil {
		return domain.ResolvePrompt(o, false)
	}
	q := fmt.Sprintf("[aegis]   Allow %s@%s anyway?", spec.Name, resolved)
	switch g.confirm.Confirm(q) {
	case ConfirmAllow:
		return domain.ResolvePrompt(o, true)
	case ConfirmUnavailable:
		o.PromotedFromPrompt = true
		o.Action = domain.ActionBlock
		return o
	default:
		return domain.ResolvePrompt(o, false)
	}
}

func (g *InstallGate) recordAudit(o domain.Outcome) {
	if g.audit == nil {
		return
	}
	if err := g.audit.Write(o); err != nil {
		g.presenter.OnInfo(fmt.Sprintf("audit write failed: %v", err))
	}
}

func (g *InstallGate) readOverride() (bool, string) {
	if g.env == nil {
		return false, ""
	}
	return g.env.Override()
}

func (g *InstallGate) envIsCI() bool {
	if g.env == nil {
		return false
	}
	return g.env.IsCI()
}

// confirmAvailable reports whether interactive prompting is feasible.
// We can't really know without trying — so we use the env hint (CI=>no
// TTY) as a fast filter. The Confirmer itself handles the case where
// /dev/tty is absent at runtime.
func (g *InstallGate) confirmAvailable() bool {
	if g.confirm == nil {
		return false
	}
	if g.env != nil && g.env.IsCI() {
		return false
	}
	return true
}
