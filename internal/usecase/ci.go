package usecase

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// CI is the turnkey "is my project safe right now?" use case for
// pipelines. It composes Snapshot.Save → Snapshot.Enrich (optional)
// → score every dep → filter by threshold, returning a structured
// result the caller maps to an exit code.
//
// Single command, single exit code — designed to drop into a CI step
// without the user having to chain save / enrich / diff / parse.
type CI struct {
	snapshot  *Snapshot
	presenter CIPresenter
}

// NewCI wires the CI use case. Snapshot is required; the same
// instance the rest of the CLI uses (with risk engine + allowlist
// already attached at composition root).
func NewCI(snapshot *Snapshot, presenter CIPresenter) *CI {
	return &CI{snapshot: snapshot, presenter: presenter}
}

// CIRequest is the input. ProjectDir defaults to cwd at the CLI
// layer. FailOn names the lowest verdict that counts as a failure
// (typically VerdictBlock).
//
// BaselinePath is the optional drift mode: when non-empty, CI does
// NOT overwrite the project's aegis.lock. Instead it builds a live
// snapshot in memory (optionally enriched), diffs against the
// baseline file, and uses the per-entry diff verdicts (which fold
// in DriftScore — catches "this dep added a postinstall hook in
// this version" attacks).
type CIRequest struct {
	ProjectDir   string
	FailOn       domain.VerdictKind
	Enrich       bool // when false, score only on existing/baseline fingerprints
	BaselinePath string
}

// CIFinding is one dep that crossed the FailOn threshold. Both Risk
// and Drift are preserved so the renderer can label flag groups
// correctly — earlier we collapsed the two when drift > risk, which
// caused drift flags to be rendered as "risk flags".
//
// Drift is the empty zero value for the full-audit (non-baseline)
// path, where there's no prior fingerprint to diff against. The
// presenter checks `Drift.Score == 0` to decide whether to render
// the second flag block.
type CIFinding struct {
	Dep     domain.Dependency
	Risk    domain.RiskAssessment
	Drift   domain.RiskAssessment
	Verdict domain.VerdictKind
}

// CISummary is the per-verdict tally over the full snapshot. Useful
// for dashboards and as a sanity check that the threshold is sane
// for the project.
type CISummary struct {
	Total   int
	Safe    int
	Review  int
	Prompt  int
	Blocked int
}

// CIResult is what Run returns and what the CLI exit-code logic
// branches on. Passed=true means no findings ≥ FailOn.
type CIResult struct {
	ProjectName string
	FailOn      domain.VerdictKind
	Enriched    bool
	Summary     CISummary
	Findings    []CIFinding
	Passed      bool
}

// CIPresenter renders the audit. Implementations live in
// presenter/cli/ci_render.go (human + JSON modes).
type CIPresenter interface {
	OnCIBegin(projectDir string, failOn domain.VerdictKind, enrich bool)
	OnCIResult(result CIResult)
	OnCIError(err error)
}

// Run executes the full audit pipeline. Errors flow through both the
// returned error and OnCIError so the CLI can map to exit code 2
// ("couldn't reach a verdict") distinct from a clean failure (1) or
// pass (0).
//
// The Save and Enrich steps reuse Snapshot's existing presenter
// callbacks (lockfile-overwrite warning, live region, skip messages).
// CI doesn't suppress them — the user wants to see what's happening
// during a potentially-slow first enrich.
func (c *CI) Run(ctx context.Context, req CIRequest) (CIResult, error) {
	if c.snapshot == nil {
		err := fmt.Errorf("ci: snapshot use case not configured")
		c.presenter.OnCIError(err)
		return CIResult{}, err
	}
	if req.Enrich && !c.snapshot.RiskEngineEnabled() {
		err := fmt.Errorf("ci: --enrich requested but risk engine not configured (build with AST scanner)")
		c.presenter.OnCIError(err)
		return CIResult{}, err
	}
	if req.FailOn < domain.VerdictSafe || req.FailOn > domain.VerdictBlock {
		err := fmt.Errorf("ci: invalid fail-on level %d", req.FailOn)
		c.presenter.OnCIError(err)
		return CIResult{}, err
	}

	c.presenter.OnCIBegin(req.ProjectDir, req.FailOn, req.Enrich)

	if req.BaselinePath != "" {
		return c.runBaseline(ctx, req)
	}
	return c.runFull(ctx, req)
}

// runFull is the original audit path: save → enrich → score every
// dep absolutely. Overwrites aegis.lock with the current state.
func (c *CI) runFull(ctx context.Context, req CIRequest) (CIResult, error) {
	if err := c.snapshot.Save(req.ProjectDir); err != nil {
		c.presenter.OnCIError(fmt.Errorf("save: %w", err))
		return CIResult{}, err
	}
	if req.Enrich {
		if err := c.snapshot.Enrich(ctx, req.ProjectDir); err != nil {
			c.presenter.OnCIError(fmt.Errorf("enrich: %w", err))
			return CIResult{}, err
		}
	}
	snap, ok, err := c.snapshot.store.Load(req.ProjectDir)
	if err != nil {
		c.presenter.OnCIError(fmt.Errorf("reload: %w", err))
		return CIResult{}, err
	}
	if !ok {
		err := fmt.Errorf("ci: snapshot vanished after save (this is a bug)")
		c.presenter.OnCIError(err)
		return CIResult{}, err
	}
	result := c.scoreSnapshot(snap, req.FailOn)
	result.Enriched = req.Enrich
	result.FailOn = req.FailOn
	c.presenter.OnCIResult(result)
	return result, nil
}

// runBaseline is the drift mode. Loads the named baseline file (a
// previously-saved aegis.lock — typically the one committed to git
// at the PR's merge target), builds a fresh live snapshot in memory
// (optionally enriched in-place), and diffs the two using the
// existing Snapshot.BuildDiffReportFromSnapshots. The DiffReport's
// verdict already folds in DriftScore, so an unchanged dep that
// suddenly gained CapInstallHookExec or CapNetEgress trips it.
//
// Crucially, this path does NOT call Snapshot.Save — the baseline
// file stays untouched.
func (c *CI) runBaseline(ctx context.Context, req CIRequest) (CIResult, error) {
	baseline, err := c.snapshot.store.LoadFile(req.BaselinePath)
	if err != nil {
		c.presenter.OnCIError(fmt.Errorf("baseline: %w", err))
		return CIResult{}, err
	}

	live, err := c.buildLiveSnapshot(ctx, req)
	if err != nil {
		c.presenter.OnCIError(fmt.Errorf("live scan: %w", err))
		return CIResult{}, err
	}

	report := c.snapshot.BuildDiffReportFromSnapshots(baseline, live)
	result := c.scoreDiff(report, req.FailOn, len(live.Deps))
	result.Enriched = req.Enrich
	result.FailOn = req.FailOn
	c.presenter.OnCIResult(result)
	return result, nil
}

// buildLiveSnapshot scans the project's lockfile into an in-memory
// snapshot, optionally carries forward the saved fingerprints (so
// already-scanned deps don't need a re-fetch), and optionally
// enriches the rest. Doesn't write anywhere.
func (c *CI) buildLiveSnapshot(ctx context.Context, req CIRequest) (domain.Snapshot, error) {
	deps, err := c.snapshot.scanner.ScanProject(req.ProjectDir)
	if err != nil {
		return domain.Snapshot{}, err
	}
	live := domain.Snapshot{
		SchemaVersion: domain.SnapshotSchemaVersion,
		CreatedAt:     c.snapshot.now(),
		AegisVersion:  c.snapshot.aegisVersion,
		Project:       projectBaseName(req.ProjectDir),
		Deps:          deps,
	}
	if req.Enrich {
		// Cheap path: route through the existing fpCache. Construct
		// a temporary in-memory snapshot, persist nothing. We can't
		// use Snapshot.Enrich directly because it reloads from disk;
		// instead, directly call analyzeOneSlot for each pending dep.
		live, err = c.enrichInMemory(ctx, live)
		if err != nil {
			return domain.Snapshot{}, err
		}
	}
	return live, nil
}

// enrichInMemory runs the AST scanner over each dep in place,
// reusing Snapshot.EnrichDeps so we get the same worker pool, live
// progress UI, and fpCache reuse as the persisted Enrich path. Per-
// dep errors are still best-effort — they're surfaced via the
// snapshot presenter's "skip" info messages.
func (c *CI) enrichInMemory(ctx context.Context, snap domain.Snapshot) (domain.Snapshot, error) {
	if !c.snapshot.RiskEngineEnabled() {
		return snap, fmt.Errorf("risk engine not configured")
	}
	c.snapshot.EnrichDeps(ctx, snap.Deps)
	return snap, nil
}

// scoreDiff converts a DiffReport into the CI result shape used by
// the presenter. Findings are entries whose verdict ≥ failOn. The
// summary counts every diff entry (added + upgraded — removed deps
// are always safe so they're not bucketed).
func (c *CI) scoreDiff(report DiffReport, failOn domain.VerdictKind, liveTotal int) CIResult {
	out := CIResult{
		Summary: CISummary{Total: liveTotal},
		Passed:  true,
	}
	for _, e := range report.Entries {
		if e.Kind == DiffRemoved {
			continue
		}
		var dep domain.Dependency
		if e.New != nil {
			dep = *e.New
		} else if e.Old != nil {
			dep = *e.Old
		}
		switch e.Verdict {
		case domain.VerdictSafe:
			out.Summary.Safe++
		case domain.VerdictReview:
			out.Summary.Review++
		case domain.VerdictPrompt:
			out.Summary.Prompt++
		case domain.VerdictBlock:
			out.Summary.Blocked++
		}
		if e.Verdict >= failOn {
			out.Findings = append(out.Findings, CIFinding{
				Dep:     dep,
				Risk:    e.Risk,  // capability-level signal on the new version
				Drift:   e.Drift, // change-vs-baseline signal
				Verdict: e.Verdict,
			})
			out.Passed = false
		}
	}
	return out
}

// projectBaseName returns the last path segment, used as the live
// snapshot's Project field. Trailing slashes are tolerated. Uses
// filepath.Base which handles the cross-OS edge cases (drive
// letters, repeated separators, "/" → ".") that a hand-rolled scan
// gets wrong.
func projectBaseName(dir string) string {
	return filepath.Base(strings.TrimRight(dir, `/\`))
}

// scoreSnapshot scores every dep and partitions into summary buckets +
// findings list (entries ≥ failOn). The allowlist is applied so
// suppressed flags don't manufacture false-positive blocks.
func (c *CI) scoreSnapshot(snap domain.Snapshot, failOn domain.VerdictKind) CIResult {
	out := CIResult{
		ProjectName: snap.Project,
		Summary:     CISummary{Total: len(snap.Deps)},
		Passed:      true,
	}
	for _, d := range snap.Deps {
		risk := domain.RiskScore(d.Fingerprint).
			ApplyAllowlist(d.Ecosystem, d.Name, d.Version, c.snapshot.allowlist)
		// Single-version score (no drift, no prior fingerprint to
		// diff against — CI audits the current state, not changes).
		verdict := domain.Verdict(risk, domain.RiskAssessment{})

		switch verdict {
		case domain.VerdictSafe:
			out.Summary.Safe++
		case domain.VerdictReview:
			out.Summary.Review++
		case domain.VerdictPrompt:
			out.Summary.Prompt++
		case domain.VerdictBlock:
			out.Summary.Blocked++
		}

		if verdict >= failOn {
			out.Findings = append(out.Findings, CIFinding{
				Dep: d, Risk: risk, Verdict: verdict,
			})
			out.Passed = false
		}
	}
	return out
}

