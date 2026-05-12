package usecase

import (
	"fmt"
	"sort"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/ghactions"
)

// Actions is the use case for `aegis actions scan`. It walks a
// project's `.github/workflows/` directory, parses every YAML file,
// runs heuristics, and returns aggregated findings.
//
// Layering note: this use case takes a concrete dependency on the
// ghactions infra package. The package is pure (no I/O beyond reading
// workflow files) so the cost of a port abstraction isn't justified
// for the prototype. Lift to a port once a second backend appears
// (e.g. GitHub API for remote-repo scanning).
type Actions struct{}

// NewActions constructs the use case. Stateless today; the struct
// exists so future deps (allowlist, server API) can be added without a
// breaking change.
func NewActions() *Actions { return &Actions{} }

// ActionsScanRequest is the input to Actions.Scan.
type ActionsScanRequest struct {
	// ProjectDir is the repo root. `.github/workflows/` is resolved
	// underneath it.
	ProjectDir string

	// FailOn is the minimum severity that flips Passed to false. Zero
	// value means any finding fails.
	FailOn domain.Severity

	// Ignore suppresses matching findings so they don't contribute to
	// the Passed/failed threshold. Suppressed findings are still included
	// in Findings for transparency. Load from .aegis-actions-allowlist.yaml
	// via infra/allowlist.LoadActionsIgnore.
	Ignore domain.ActionsIgnoreSet
}

// ActionsScanResult is what Scan returns.
type ActionsScanResult struct {
	Workflows int
	Findings  []domain.WorkflowFinding
	Passed    bool
}

// Scan walks workflows and returns findings. Returns an error only on
// I/O failures (workflows dir unreadable for reasons other than
// not-exist, YAML parse failures, etc); a workflow-free project is
// reported as Passed=true with zero findings.
func (a *Actions) Scan(req ActionsScanRequest) (ActionsScanResult, error) {
	paths, err := ghactions.FindWorkflows(req.ProjectDir)
	if err != nil {
		return ActionsScanResult{}, err
	}
	var all []domain.WorkflowFinding
	for _, p := range paths {
		wf, err := ghactions.Parse(p)
		if err != nil {
			return ActionsScanResult{}, fmt.Errorf("actions: parse %s: %w", p, err)
		}
		all = append(all, ghactions.Analyze(wf)...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		if all[i].Line != all[j].Line {
			return all[i].Line < all[j].Line
		}
		return all[i].Kind < all[j].Kind
	})
	all = req.Ignore.Suppress(all)
	res := ActionsScanResult{
		Workflows: len(paths),
		Findings:  all,
		Passed:    !exceedsThreshold(all, req.FailOn),
	}
	return res, nil
}

func exceedsThreshold(findings []domain.WorkflowFinding, failOn domain.Severity) bool {
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		if failOn == "" || severityAtLeast(f.Severity, failOn) {
			return true
		}
	}
	return false
}

func severityAtLeast(have, want domain.Severity) bool {
	return severityRank(have) >= severityRank(want)
}

func severityRank(s domain.Severity) int {
	switch s {
	case domain.SevCritical:
		return 4
	case domain.SevHigh:
		return 3
	case domain.SevMedium:
		return 2
	case domain.SevLow:
		return 1
	}
	return 0
}
