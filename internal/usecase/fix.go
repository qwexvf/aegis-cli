package usecase

import (
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Fix is the use case for `aegis fix` — load the saved snapshot,
// compute the minimal upgrade plan that clears every known CVE, and
// hand it to the presenter. Read-only: never writes lockfiles or
// executes the upgrade commands. The plan is informational so the
// user can choose to apply selectively.
type Fix struct {
	store     SnapshotStore
	presenter FixPresenter
}

// NewFix wires the Fix use case.
func NewFix(store SnapshotStore, presenter FixPresenter) *Fix {
	return &Fix{store: store, presenter: presenter}
}

// FixRequest is the input. ProjectDir defaults to cwd at the CLI layer.
type FixRequest struct {
	ProjectDir string
}

// FixResult bundles the plan with a convenience flag for the CLI exit-code
// logic. The presenter decides what to render; the CLI just needs to know
// whether anything was found.
type FixResult struct {
	Plan domain.FixPlan
}

// FixPresenter renders the plan. Implementation lives in
// presenter/cli/fix_render.go (human + JSON modes).
type FixPresenter interface {
	OnFixBegin(projectDir string)
	OnFixResult(result FixResult)
	OnFixError(err error)
}

// Run loads the snapshot, builds the plan, and forwards to the presenter.
// Errors flow through both the returned error and OnFixError so the CLI
// can map to a non-zero exit code.
func (f *Fix) Run(req FixRequest) (FixResult, error) {
	f.presenter.OnFixBegin(req.ProjectDir)

	snap, ok, err := f.store.Load(req.ProjectDir)
	if err != nil {
		f.presenter.OnFixError(fmt.Errorf("load snapshot: %w", err))
		return FixResult{}, err
	}
	if !ok {
		err := fmt.Errorf("no snapshot saved — run 'aegis snapshot save' first")
		f.presenter.OnFixError(err)
		return FixResult{}, err
	}

	result := FixResult{Plan: domain.BuildFixPlan(snap)}
	f.presenter.OnFixResult(result)
	return result, nil
}
