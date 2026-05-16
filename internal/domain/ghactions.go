package domain

// GitHub Actions scanner domain types. Parallel to (not part of) the
// per-ecosystem package scanner: workflows are config, not package
// source, and their risk surface is per-file, not per-package.

// ActionRef is one `uses: owner/repo[/path]@ref` declaration from a
// workflow step. Local actions (`uses: ./.github/actions/foo`) and
// docker actions (`uses: docker://...`) are tagged via Kind.
type ActionRef struct {
	Owner string // "tj-actions"
	Repo  string // "changed-files"
	Path  string // "" or "subdir" for monorepo actions
	Ref   string // "v45", "main", or 40-char SHA
	Kind  ActionRefKind

	// Source location for evidence.
	File string
	Line int
}

// ActionRefKind discriminates the three forms of `uses:`.
type ActionRefKind int

const (
	ActionRefRemote ActionRefKind = iota // owner/repo@ref
	ActionRefLocal                       // ./.github/actions/...
	ActionRefDocker                      // docker://...
)

// RunScript is one `run:` block from a workflow step. Multi-line is
// preserved as-is so heuristics can match across lines.
type RunScript struct {
	Body  string
	Shell string // "bash", "sh", "pwsh", or "" for default
	File  string
	Line  int
}

// Workflow is the parsed representation of one `.github/workflows/*.yml`
// file. Only the fields relevant to risk scanning are extracted; the
// full Actions schema is intentionally not modeled.
type Workflow struct {
	Path        string // ".github/workflows/release.yml"
	Name        string // workflow name attribute
	On          []string
	Permissions WorkflowPermissions
	Jobs        []WorkflowJob
}

// WorkflowPermissions captures the workflow- or job-level `permissions:`
// block. Empty Mode means "not declared" (GitHub default applies, which
// is broad for `pull_request` and narrow for `pull_request_target`).
type WorkflowPermissions struct {
	Mode   string            // "read-all", "write-all", "", "scopes"
	Scopes map[string]string // when Mode=="scopes": "contents":"read", ...
	Line   int
}

// WorkflowJob is one job from a workflow. Includes the resolved step
// list so heuristics can correlate (e.g. pull_request_target + checkout
// + run-with-PR-input).
type WorkflowJob struct {
	ID          string
	Name        string
	RunsOn      string
	Permissions WorkflowPermissions
	Steps       []WorkflowStep
	Line        int
}

// WorkflowStep is one step. Exactly one of Uses or Run is populated
// (steps without either are skipped at parse time).
type WorkflowStep struct {
	Name string
	Uses *ActionRef
	Run  *RunScript
	With map[string]string
	Env  map[string]string
	Line int
}

// WorkflowFinding is one risk-engine output row, mapped to a workflow
// location. Severity drives the CI gate exit code, mirroring the
// package scanner's verdict tiers.
type WorkflowFinding struct {
	Kind     WorkflowFindingKind
	Severity Severity
	File     string
	Line     int
	Message  string     // human-facing, one line
	Evidence string     // raw snippet from the workflow (truncated)
	Ref      *ActionRef // populated when the finding is about a `uses:`

	// Suppressed is true when an ActionsIgnoreRule matched this finding.
	// The finding is still included in output for transparency; it does
	// not contribute to the Passed/failed threshold.
	Suppressed bool
	// SuppressBy holds the Reason from the matching ignore rule.
	SuppressBy string
}

// WorkflowFindingKind enumerates the heuristic checks. Each kind maps
// to one detector in internal/infra/scan/actions/heuristics.go.
type WorkflowFindingKind int

const (
	// FindingUnpinnedRef — `uses: foo/bar@v1` or `@main`; not a 40-char
	// SHA. tj-actions/changed-files (2025-03) demonstrated why this
	// matters: the action owner pushed a malicious commit and every
	// tag-pinned consumer ran it instantly.
	FindingUnpinnedRef WorkflowFindingKind = iota + 1

	// FindingSuspiciousRun — `run:` body matches a known malware
	// distribution pattern (curl|sh, wget|bash, base64-decode-and-exec,
	// raw IP literal).
	FindingSuspiciousRun

	// FindingPullRequestTargetCheckout — `on: pull_request_target` job
	// that also runs `actions/checkout` against the PR head. Classic
	// privilege-escalation pattern: PR code runs with repo write
	// permissions + GITHUB_TOKEN.
	FindingPullRequestTargetCheckout

	// FindingWriteAllPermissions — explicit `permissions: write-all`
	// or omitted-permissions-with-pull_request_target. Token gets
	// every scope; one compromised action exfils anything.
	FindingWriteAllPermissions

	// FindingScriptInjection — `${{ github.event.* }}` interpolation
	// inside a `run:` body, where the source is attacker-controlled
	// (PR title, branch name, issue body).
	FindingScriptInjection

	// FindingOIDCNpmPublish — job has `id-token: write` permission AND
	// a `run:` step that invokes `npm publish`. This combination lets a
	// compromised CI identity mint a short-lived npm token via OIDC
	// federation and publish to the registry without any stored secret.
	// The Mini Shai-Hulud worm used exactly this mechanism to self-replicate
	// across 42 @tanstack/* packages in six minutes on 2026-05-11.
	FindingOIDCNpmPublish

	// FindingCachePoisoning — `actions/cache` (or `actions/cache/restore`)
	// is used inside a `pull_request_target` workflow. Fork PRs run with
	// read access to the base branch's cache scope; a malicious PR can
	// read secrets that were previously cached, or write a poisoned cache
	// entry that later executes on a privileged workflow run.
	FindingCachePoisoning
)

func (k WorkflowFindingKind) String() string {
	switch k {
	case FindingUnpinnedRef:
		return "unpinned_ref"
	case FindingSuspiciousRun:
		return "suspicious_run"
	case FindingPullRequestTargetCheckout:
		return "pull_request_target_checkout"
	case FindingWriteAllPermissions:
		return "write_all_permissions"
	case FindingScriptInjection:
		return "script_injection"
	case FindingOIDCNpmPublish:
		return "oidc_npm_publish"
	case FindingCachePoisoning:
		return "cache_poisoning"
	}
	return "unknown"
}

// MarshalText makes WorkflowFindingKind encode as its string name in
// JSON (and any encoding.TextMarshaler consumer) instead of the raw
// integer iota value.
func (k WorkflowFindingKind) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// IsSHAPinned reports whether Ref is a 40-character lowercase hex SHA.
// Only SHA-pinned refs are considered immutable by the unpinned-ref
// heuristic; tags, branches, and short SHAs are all mutable from the
// consumer's perspective.
func (r ActionRef) IsSHAPinned() bool {
	if len(r.Ref) != 40 {
		return false
	}
	for _, c := range r.Ref {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
