package usecase

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/actions"
)

// Actions is the use case for `aegis actions scan`. It walks a
// project's `.github/workflows/` directory, parses every YAML file,
// runs heuristics, and returns aggregated findings.
//
// Layering note: this use case takes a concrete dependency on the
// actions infra package. The package is pure (no I/O beyond reading
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
	// underneath it. Ignored when Repo is set.
	ProjectDir string

	// Repo is an optional "owner/repo" string for remote scanning via
	// the GitHub Contents API. When set, ProjectDir is ignored.
	Repo string

	// Token is an optional GitHub personal access token. Without a token
	// the GitHub API allows 60 requests/hour; with one it allows 5000/hour.
	Token string

	// HTTPClient is the HTTP client to use for remote requests.
	// Defaults to http.DefaultClient when nil.
	HTTPClient *http.Client

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
// Scan walks workflows and returns findings. ctx is used for remote API
// requests — pass cmd.Context() from cobra so SIGINT cancels in-flight calls.
func (a *Actions) Scan(ctx context.Context, req ActionsScanRequest) (ActionsScanResult, error) {
	var workflows []actions.ParsedWorkflow
	var numWorkflows int

	if req.Repo != "" {
		owner, repo, ok := strings.Cut(req.Repo, "/")
		if !ok {
			return ActionsScanResult{}, fmt.Errorf("actions: --repo must be owner/repo, got %q", req.Repo)
		}
		wfs, err := actions.FetchRemoteWorkflows(ctx, owner, repo, req.Token, req.HTTPClient)
		if err != nil {
			return ActionsScanResult{}, fmt.Errorf("actions: remote fetch %s: %w", req.Repo, err)
		}
		workflows = wfs
	} else {
		paths, err := actions.FindWorkflows(req.ProjectDir)
		if err != nil {
			return ActionsScanResult{}, err
		}
		for _, p := range paths {
			wf, err := actions.Parse(p)
			if err != nil {
				return ActionsScanResult{}, fmt.Errorf("actions: parse %s: %w", p, err)
			}
			workflows = append(workflows, actions.ParsedWorkflow{Workflow: wf})
		}
	}
	numWorkflows = len(workflows)

	var all []domain.WorkflowFinding
	for _, pw := range workflows {
		all = append(all, actions.Analyze(pw.Workflow)...)
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
		Workflows: numWorkflows,
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
