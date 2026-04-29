package pm

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/api"
	"github.com/qwexvf/aegis/services/cli/internal/audit"
	"github.com/qwexvf/aegis/services/cli/internal/cache"
	"github.com/qwexvf/aegis/services/cli/internal/ci"
	"github.com/qwexvf/aegis/services/cli/internal/prompt"
	"github.com/qwexvf/aegis/services/cli/internal/registry"
	"github.com/qwexvf/aegis/services/cli/internal/ui"
)

// resolver is the subset of *registry.Client we use. Defined as an
// interface so Runner is testable with a fake.
type resolver interface {
	Resolve(ctx context.Context, pkg, rangeOrTag string) (string, error)
}

// checker is the subset of *api.Client we use, for the same reason.
type checker interface {
	Check(ctx context.Context, ecosystem, pkg, version string) (*api.Decision, error)
}

// confirmer asks a y/N question and reports the human's answer.
type confirmer interface {
	Confirm(question string) prompt.Result
}

// auditWriter records one decision row.
type auditWriter interface {
	Write(audit.Entry) error
}

// realConfirmer wraps the prompt package as a confirmer.
type realConfirmer struct{}

func (realConfirmer) Confirm(q string) prompt.Result { return prompt.Confirm(q) }

// Runner orchestrates an Aegis-gated invocation of a single package
// manager.
type Runner struct {
	pm       PackageManager
	registry resolver
	api      checker
	cache    *cache.Cache
	audit    auditWriter
	confirm  confirmer
	isCI     func() bool
	out      io.Writer
	timeout  time.Duration

	installVerb string
	exitFn      func(int)
}

// NewRunner builds a Runner with the default real dependencies.
func NewRunner(p PackageManager) *Runner {
	return &Runner{
		pm:          p,
		registry:    registry.New(),
		api:         api.New(),
		cache:       cache.New(),
		audit:       audit.New(),
		confirm:     realConfirmer{},
		isCI:        ci.IsCI,
		out:         os.Stderr,
		timeout:     20 * time.Second,
		installVerb: defaultInstallVerb(p.Name()),
		exitFn:      os.Exit,
	}
}

func defaultInstallVerb(pmName string) string {
	switch pmName {
	case "npm":
		return "install"
	default: // bun, yarn, pnpm — all use "add" as their primary install verb
		return "add"
	}
}

// Run is the entrypoint. For install commands it gates the install;
// for everything else it passes straight through.
func (r *Runner) Run(args []string) error {
	if r.pm.IsInstallCommand(args) {
		blocked, err := r.runInstall(args)
		if err != nil {
			return err
		}
		if blocked {
			r.exitFn(1)
			return nil
		}
	}
	return r.pm.Exec(args)
}

func (r *Runner) runInstall(args []string) (blocked bool, err error) {
	specs := r.pm.ParseInstallArgs(args)
	if len(specs) == 0 {
		return false, nil
	}

	overrideAllow, overrideReason, overrideRefused := r.evalOverride()

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	for _, spec := range specs {
		if spec.NonRegistry {
			ui.Skipped(r.out, spec.Raw)
			continue
		}

		resolved, ok := r.resolveVersion(ctx, spec)
		if !ok {
			continue
		}

		decision, source := r.fetchDecision(ctx, spec.Name, resolved)
		if decision == nil {
			// fail-open: render the error in fetchDecision; record audit
			// row and continue without blocking.
			r.recordAudit(audit.Entry{
				PM: r.pm.Name(), Ecosystem: r.pm.Ecosystem(),
				Package: spec.Name, Version: resolved,
				Decision: "error", Source: source,
			})
			continue
		}

		ui.Render(r.out, decision, r.pm.Name(), r.installVerb)

		// Decide whether to block.
		shouldBlock := r.shouldBlock(decision, overrideAllow, overrideReason, overrideRefused, spec.Name, resolved)

		r.recordAudit(audit.Entry{
			PM: r.pm.Name(), Ecosystem: r.pm.Ecosystem(),
			Package: spec.Name, Version: resolved,
			Decision: decision.Decision, Severity: decision.Severity,
			Source:         source,
			OverrideUsed:   overrideAllow && !overrideRefused && (decision.Decision == "block" || decision.Decision == "prompt"),
			OverrideReason: overrideReason,
			AdvisoryID:     decision.AdvisoryID,
		})

		if shouldBlock {
			blocked = true
		}
	}
	return blocked, nil
}

// evalOverride centralises the AEGIS_OVERRIDE / _REASON contract.
//   - allow      : AEGIS_OVERRIDE=allow set
//   - reason     : AEGIS_OVERRIDE_REASON value (only meaningful when allow is true)
//   - refused    : allow was set but no reason given — caller must NOT honour it
func (r *Runner) evalOverride() (allow bool, reason string, refused bool) {
	allow = os.Getenv("AEGIS_OVERRIDE") == "allow"
	reason = os.Getenv("AEGIS_OVERRIDE_REASON")
	if allow && reason == "" {
		fmt.Fprintln(r.out, "[aegis] AEGIS_OVERRIDE_REASON required to override — refusing")
		refused = true
	}
	return
}

// resolveVersion resolves spec.Version through the registry unless it
// is already an exact pin. Returns (resolved, ok). When ok is false,
// fail-open behavior was already rendered to r.out.
func (r *Runner) resolveVersion(ctx context.Context, spec PackageSpec) (string, bool) {
	if spec.IsExactVersion() {
		return spec.Version, true
	}
	v, err := r.registry.Resolve(ctx, spec.Name, spec.Version)
	if err != nil {
		fmt.Fprintf(r.out, "[aegis] could not resolve %s: %v (passthrough)\n", spec.Raw, err)
		return "", false
	}
	return v, true
}

// fetchDecision tries the cache first, then the API. Renders progress
// and error UI as a side effect. source is "cache" | "api" | "error".
func (r *Runner) fetchDecision(ctx context.Context, pkg, version string) (*api.Decision, string) {
	key := cache.Key(r.pm.Ecosystem(), pkg, version)
	if d, ok := r.cache.Get(key); ok {
		ui.Resolved(r.out, pkg, version+" (cached)")
		return d, "cache"
	}

	ui.Resolved(r.out, pkg, version)
	d, err := r.api.Check(ctx, r.pm.Ecosystem(), pkg, version)
	if err != nil {
		ui.APIError(r.out, pkg, version, err)
		return nil, "error"
	}
	if err := r.cache.Put(key, d, 0); err != nil {
		// Caching is best-effort; never block an install on cache write.
		fmt.Fprintf(r.out, "[aegis] cache write failed: %v\n", err)
	}
	return d, "api"
}

// shouldBlock applies the policy: block decisions block (unless valid
// override), prompt decisions go to the human (block in CI / no-TTY /
// override-refused), allow/warn never block.
func (r *Runner) shouldBlock(d *api.Decision, overrideAllow bool, overrideReason string, overrideRefused bool, pkg, version string) bool {
	switch d.Decision {
	case "block":
		if overrideAllow && !overrideRefused {
			fmt.Fprintf(r.out, "[aegis]   AEGIS_OVERRIDE=allow set (reason: %q) — proceeding (audited)\n", overrideReason)
			return false
		}
		return true
	case "prompt":
		if overrideAllow && !overrideRefused {
			fmt.Fprintf(r.out, "[aegis]   AEGIS_OVERRIDE=allow set (reason: %q) — proceeding (audited)\n", overrideReason)
			return false
		}
		if r.isCI() {
			fmt.Fprintln(r.out, "[aegis]   CI detected — prompt promoted to block")
			return true
		}
		q := fmt.Sprintf("[aegis]   Allow %s@%s anyway?", pkg, version)
		switch r.confirm.Confirm(q) {
		case prompt.ResultAllowed:
			fmt.Fprintln(r.out, "[aegis]   user allowed — proceeding (audited)")
			return false
		case prompt.ResultUnavailable:
			fmt.Fprintln(r.out, "[aegis]   no TTY available — prompt promoted to block")
			return true
		default:
			fmt.Fprintln(r.out, "[aegis]   user denied")
			return true
		}
	}
	return false
}

func (r *Runner) recordAudit(e audit.Entry) {
	if r.audit == nil {
		return
	}
	if err := r.audit.Write(e); err != nil {
		fmt.Fprintf(r.out, "[aegis] audit write failed: %v\n", err)
	}
}
