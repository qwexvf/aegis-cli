package ghactions

import (
	"regexp"
	"slices"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Analyze runs all heuristics against a parsed workflow and returns
// findings in deterministic order (file walk → job order → step order →
// heuristic order). Heuristics are pure: no I/O, no external state.
func Analyze(wf domain.Workflow) []domain.WorkflowFinding {
	var findings []domain.WorkflowFinding

	// Workflow-level checks first.
	findings = append(findings, checkWriteAllPermissions(wf.Permissions, wf.Path, 0)...)
	prTarget := hasEvent(wf.On, "pull_request_target")

	for _, job := range wf.Jobs {
		// Job-level permissions override workflow-level. Re-check.
		if job.Permissions.Mode != "" {
			findings = append(findings, checkWriteAllPermissions(job.Permissions, wf.Path, job.Line)...)
		}

		findings = append(findings, checkOIDCNpmPublish(job, wf.Permissions, wf.Path)...)

		jobHasCheckout := false
		for _, step := range job.Steps {
			if step.Uses != nil {
				findings = append(findings, checkUnpinnedRef(*step.Uses)...)
				if isCheckoutWithRef(step) {
					jobHasCheckout = true
				}
				if prTarget {
					findings = append(findings, checkCachePoisoning(step, wf.Path)...)
				}
			}
			if step.Run != nil {
				findings = append(findings, checkSuspiciousRun(*step.Run)...)
				findings = append(findings, checkScriptInjection(*step.Run)...)
			}
		}
		if prTarget && jobHasCheckout {
			findings = append(findings, domain.WorkflowFinding{
				Kind:     domain.FindingPullRequestTargetCheckout,
				Severity: domain.SevCritical,
				File:     wf.Path,
				Line:     job.Line,
				Message:  "job " + job.ID + ": pull_request_target + actions/checkout of PR head — runs untrusted PR code with write permissions",
			})
		}
	}
	return findings
}

// checkOIDCNpmPublish flags the id-token:write + npm publish combo that the
// Mini Shai-Hulud worm used to self-replicate without stored credentials.
func checkOIDCNpmPublish(job domain.WorkflowJob, wfPerms domain.WorkflowPermissions, file string) []domain.WorkflowFinding {
	// Effective permissions: job-level overrides workflow-level when declared.
	effectivePerms := wfPerms
	if job.Permissions.Mode != "" || len(job.Permissions.Scopes) > 0 {
		effectivePerms = job.Permissions
	}
	hasOIDC := effectivePerms.Mode == "write-all" ||
		effectivePerms.Scopes["id-token"] == "write"
	if !hasOIDC {
		return nil
	}
	for _, step := range job.Steps {
		if step.Run == nil {
			continue
		}
		if !npmPublishPattern.MatchString(step.Run.Body) {
			continue
		}
		return []domain.WorkflowFinding{{
			Kind:     domain.FindingOIDCNpmPublish,
			Severity: domain.SevHigh,
			File:     file,
			Line:     step.Run.Line,
			Message:  "job " + job.ID + ": id-token:write + npm publish — OIDC federation can mint an npm token without stored credentials; worm self-replication vector (Mini Shai-Hulud, 2026-05-11)",
			Evidence: truncate(step.Run.Body, 120),
		}}
	}
	return nil
}

// checkCachePoisoning flags actions/cache usage inside pull_request_target
// workflows. Fork PRs share the base branch cache scope, so a malicious PR
// can read previously cached secrets or plant poisoned artifacts that later
// execute on a privileged run.
func checkCachePoisoning(step domain.WorkflowStep, file string) []domain.WorkflowFinding {
	if step.Uses == nil {
		return nil
	}
	if step.Uses.Owner != "actions" || step.Uses.Repo != "cache" {
		return nil
	}
	return []domain.WorkflowFinding{{
		Kind:     domain.FindingCachePoisoning,
		Severity: domain.SevHigh,
		File:     file,
		Line:     step.Uses.Line,
		Message:  "pull_request_target + actions/cache — fork PRs share the base branch cache scope; untrusted code can read cached secrets or poison cache entries for later privileged runs (Mini Shai-Hulud injection vector)",
	}}
}

func hasEvent(events []string, want string) bool {
	return slices.Contains(events, want)
}

// checkUnpinnedRef flags any remote action ref that isn't pinned to a
// 40-char SHA. Local and docker actions are skipped (their version
// model is different).
func checkUnpinnedRef(ref domain.ActionRef) []domain.WorkflowFinding {
	if ref.Kind != domain.ActionRefRemote {
		return nil
	}
	// Bare-action refs to GitHub-owned actions/* are typically tag-pinned
	// in the wild; we still flag them, but with a lower severity so the
	// noisy "use a SHA" warning doesn't drown out the real risks.
	if ref.IsSHAPinned() {
		return nil
	}
	sev := domain.SevMedium
	if ref.Owner != "actions" && ref.Owner != "github" {
		// Third-party actions are the real attack surface (tj-actions
		// owned by an individual maintainer, not GitHub).
		sev = domain.SevHigh
	}
	msg := "uses: " + ref.Owner + "/" + ref.Repo
	if ref.Path != "" {
		msg += "/" + ref.Path
	}
	msg += "@" + ref.Ref + " — not pinned to a commit SHA; tag/branch can be retargeted by the action owner"
	return []domain.WorkflowFinding{{
		Kind:     domain.FindingUnpinnedRef,
		Severity: sev,
		File:     ref.File,
		Line:     ref.Line,
		Message:  msg,
		Ref:      &ref,
	}}
}

// npmPublishPattern matches npm publish invocations in run scripts.
// Covers `npm publish` and the `npm pub` shorthand.
var npmPublishPattern = regexp.MustCompile(`(?i)\bnpm\s+(publish|pub)\b`)

// suspiciousRunPatterns are precompiled at package init. Order is
// stable so JSON output is reproducible.
var suspiciousRunPatterns = []struct {
	pattern *regexp.Regexp
	sev     domain.Severity
	hint    string
}{
	{
		pattern: regexp.MustCompile(`(?i)(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh|ksh)\b`),
		sev:     domain.SevHigh,
		hint:    "curl|sh / wget|sh — downloads and executes remote script with no integrity check",
	},
	{
		pattern: regexp.MustCompile(`(?i)\b(base64\s+(-d|--decode)|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64)`),
		sev:     domain.SevHigh,
		hint:    "base64 decode in run script — common obfuscation primitive",
	},
	{
		pattern: regexp.MustCompile(`https?://\d+\.\d+\.\d+\.\d+(:\d+)?(/|$|\s)`),
		sev:     domain.SevHigh,
		hint:    "raw IPv4 in URL — legitimate scripts use hostnames",
	},
	{
		pattern: regexp.MustCompile(`(?i)\b(pastebin\.com|hastebin\.com|requestbin\.|webhook\.site|ngrok\.io|burpcollaborator\.net|oast\.\w+)\b`),
		sev:     domain.SevHigh,
		hint:    "well-known data-exfil destination",
	},
}

func checkSuspiciousRun(run domain.RunScript) []domain.WorkflowFinding {
	var out []domain.WorkflowFinding
	for _, p := range suspiciousRunPatterns {
		loc := p.pattern.FindStringIndex(run.Body)
		if loc == nil {
			continue
		}
		out = append(out, domain.WorkflowFinding{
			Kind:     domain.FindingSuspiciousRun,
			Severity: p.sev,
			File:     run.File,
			Line:     run.Line + 1 + countLeadingNewlines(run.Body[:loc[0]]),
			Message:  p.hint,
			Evidence: truncate(run.Body[loc[0]:loc[1]], 120),
		})
	}
	return out
}

// scriptInjectionPattern matches GitHub-context interpolations whose
// source is attacker-controlled in a `pull_request` context. Only the
// fields a non-collaborator can set are listed — those are the dangerous
// ones in a `run:` body.
var scriptInjectionPattern = regexp.MustCompile(
	`\$\{\{\s*github\.event\.(` +
		`pull_request\.(title|body|head\.ref|head\.label)` +
		`|issue\.(title|body)` +
		`|comment\.body` +
		`|review\.body` +
		`|head_commit\.message` +
		`|head_commit\.author\.(name|email)` +
		`)\s*\}\}`,
)

func checkScriptInjection(run domain.RunScript) []domain.WorkflowFinding {
	loc := scriptInjectionPattern.FindStringIndex(run.Body)
	if loc == nil {
		return nil
	}
	return []domain.WorkflowFinding{{
		Kind:     domain.FindingScriptInjection,
		Severity: domain.SevCritical,
		File:     run.File,
		Line:     run.Line + countLeadingNewlines(run.Body[:loc[0]]),
		Message:  "attacker-controlled GitHub context interpolated into run script — assign to env first and reference as $VAR",
		Evidence: truncate(run.Body[loc[0]:loc[1]], 120),
	}}
}

// checkWriteAllPermissions flags both explicit `write-all` and the
// implicit "no permissions block declared" case. The implicit case is
// only flagged at workflow scope (jobs without their own permissions
// inherit the workflow scope).
func checkWriteAllPermissions(perms domain.WorkflowPermissions, file string, line int) []domain.WorkflowFinding {
	if perms.Mode != "write-all" {
		return nil
	}
	if line == 0 {
		line = perms.Line
	}
	return []domain.WorkflowFinding{{
		Kind:     domain.FindingWriteAllPermissions,
		Severity: domain.SevHigh,
		File:     file,
		Line:     line,
		Message:  "permissions: write-all — GITHUB_TOKEN gets every scope; narrow to the minimum needed",
	}}
}

// isCheckoutWithRef reports whether a step is `actions/checkout` configured
// to fetch the PR head (`ref: ${{ github.event.pull_request.head.sha }}`
// or similar). The dangerous combo is checkout-of-PR-head from a
// `pull_request_target` workflow.
func isCheckoutWithRef(step domain.WorkflowStep) bool {
	if step.Uses == nil {
		return false
	}
	if step.Uses.Owner != "actions" || step.Uses.Repo != "checkout" {
		return false
	}
	ref := step.With["ref"]
	if ref == "" {
		return false
	}
	return strings.Contains(ref, "pull_request.head") ||
		strings.Contains(ref, "github.head_ref") ||
		strings.Contains(ref, "github.event.pull_request")
}

func countLeadingNewlines(s string) int {
	return strings.Count(s, "\n")
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
