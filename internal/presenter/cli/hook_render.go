package cli

import "fmt"

// HookPresenter satisfies usecase.HookPresenter. Tiny renderer — hook
// install/uninstall produces single-line outcomes, no per-stage
// progress, no JSON mode (it's an admin command, not a CI consumer).
type HookPresenter struct{ p *Presenter }

// NewHookPresenter wraps a base Presenter.
func NewHookPresenter(base *Presenter) *HookPresenter { return &HookPresenter{p: base} }

func (hp *HookPresenter) OnHookInstalled(framework, path string) {
	fmt.Fprintf(hp.p.w, "%s[aegis]%s installed pre-commit hook (%s%s%s) → %s\n",
		hp.p.dim(), hp.p.reset(),
		hp.p.green(), framework, hp.p.reset(),
		path)
}

func (hp *HookPresenter) OnHookUninstalled(framework, path string) {
	fmt.Fprintf(hp.p.w, "%s[aegis]%s removed pre-commit hook (%s) from %s\n",
		hp.p.dim(), hp.p.reset(), framework, path)
}

func (hp *HookPresenter) OnHookSkipped(reason string) {
	fmt.Fprintf(hp.p.w, "%s[aegis]%s skipped: %s\n",
		hp.p.dim(), hp.p.reset(), reason)
}

func (hp *HookPresenter) OnHookError(err error) {
	fmt.Fprintf(hp.p.w, "%s[aegis]%s %s%s! %v%s\n",
		hp.p.dim(), hp.p.reset(),
		hp.p.red(), hp.p.bold(), err, hp.p.reset())
}
