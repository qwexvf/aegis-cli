package ghactions

import "github.com/qwexvf/aegis-cli/internal/domain"

// WorkflowCheck is a pure function that detects one or more risks in a
// parsed workflow. Mirrors the package-heuristics Check type.
//
// Adding a new workflow heuristic:
//  1. Write a new wfCheck* function (see heuristics.go for helpers).
//  2. Append it to defaultWorkflowChecks below.
//  3. Analyze() picks it up automatically — no other change needed.
type WorkflowCheck func(wf domain.Workflow) []domain.WorkflowFinding

// defaultWorkflowChecks is the ordered list of checks run by Analyze.
// Order is stable: more critical checks first so findings sort naturally
// by severity when output is deterministic.
var defaultWorkflowChecks = []WorkflowCheck{
	wfCheckWriteAllPermissions,
	wfCheckPullRequestTargetCheckout,
	wfCheckOIDCNpmPublish,
	wfCheckCachePoisoning,
	wfCheckUnpinnedRefs,
	wfCheckSuspiciousRunScripts,
	wfCheckScriptInjections,
}

// wfCheckWriteAllPermissions flags write-all at workflow and job scope.
func wfCheckWriteAllPermissions(wf domain.Workflow) []domain.WorkflowFinding {
	var out []domain.WorkflowFinding
	out = append(out, checkWriteAllPermissions(wf.Permissions, wf.Path, 0)...)
	for _, job := range wf.Jobs {
		if job.Permissions.Mode != "" {
			out = append(out, checkWriteAllPermissions(job.Permissions, wf.Path, job.Line)...)
		}
	}
	return out
}

// wfCheckPullRequestTargetCheckout flags the pull_request_target + checkout
// privilege-escalation combo.
func wfCheckPullRequestTargetCheckout(wf domain.Workflow) []domain.WorkflowFinding {
	if !hasEvent(wf.On, "pull_request_target") {
		return nil
	}
	var out []domain.WorkflowFinding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses != nil && isCheckoutWithRef(step) {
				out = append(out, domain.WorkflowFinding{
					Kind:     domain.FindingPullRequestTargetCheckout,
					Severity: domain.SevCritical,
					File:     wf.Path,
					Line:     job.Line,
					Message:  "job " + job.ID + ": pull_request_target + actions/checkout of PR head — runs untrusted PR code with write permissions",
				})
				break // one finding per job is enough
			}
		}
	}
	return out
}

// wfCheckOIDCNpmPublish flags the id-token:write + npm publish worm vector.
func wfCheckOIDCNpmPublish(wf domain.Workflow) []domain.WorkflowFinding {
	var out []domain.WorkflowFinding
	for _, job := range wf.Jobs {
		out = append(out, checkOIDCNpmPublish(job, wf.Permissions, wf.Path)...)
	}
	return out
}

// wfCheckCachePoisoning flags actions/cache inside pull_request_target.
func wfCheckCachePoisoning(wf domain.Workflow) []domain.WorkflowFinding {
	if !hasEvent(wf.On, "pull_request_target") {
		return nil
	}
	var out []domain.WorkflowFinding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses != nil {
				out = append(out, checkCachePoisoning(step, wf.Path)...)
			}
		}
	}
	return out
}

// wfCheckUnpinnedRefs flags action refs not pinned to a 40-char SHA.
func wfCheckUnpinnedRefs(wf domain.Workflow) []domain.WorkflowFinding {
	var out []domain.WorkflowFinding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses != nil {
				out = append(out, checkUnpinnedRef(*step.Uses)...)
			}
		}
	}
	return out
}

// wfCheckSuspiciousRunScripts flags malware patterns in run: bodies.
func wfCheckSuspiciousRunScripts(wf domain.Workflow) []domain.WorkflowFinding {
	var out []domain.WorkflowFinding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run != nil {
				out = append(out, checkSuspiciousRun(*step.Run)...)
			}
		}
	}
	return out
}

// wfCheckScriptInjections flags attacker-controlled context interpolation.
func wfCheckScriptInjections(wf domain.Workflow) []domain.WorkflowFinding {
	var out []domain.WorkflowFinding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run != nil {
				out = append(out, checkScriptInjection(*step.Run)...)
			}
		}
	}
	return out
}
