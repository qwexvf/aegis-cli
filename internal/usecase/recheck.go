package usecase

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// recheckWorkers caps concurrent /check calls during Recheck. Higher
// than enrichWorkers because /check is a single round-trip (no
// tarball, no AST), so network is the only cost — be polite to the
// API but go reasonably wide.
const recheckWorkers = 16

// Recheck re-runs the install gate's /check against every direct dep
// in the project's live lockfile. Catches packages that were allowed
// before the incident DB knew about them — e.g. a dep installed in
// March is now compromised and the API will return BLOCK in May.
//
// Differs from Snapshot.Save+Diff: Recheck doesn't write anywhere,
// doesn't AST-scan, doesn't update the snapshot. It's a fast
// "is anything I have installed now considered bad?" probe.
type Recheck struct {
	scanner   LockfileScanner
	checker   DecisionChecker
	presenter RecheckPresenter
}

// RecheckRequest is what Run takes.
type RecheckRequest struct {
	ProjectDir   string
	IncludeAll   bool // include transitive deps; default is direct-only
	FailOnPrompt bool // treat prompt verdicts as failures (default: only block fails)
}

// RecheckFinding is one dep that came back blocked or prompt.
type RecheckFinding struct {
	Dep      domain.Dependency
	Decision domain.Decision
}

// RecheckSummary holds the per-bucket tally over the rechecked deps.
type RecheckSummary struct {
	Total   int
	Allowed int
	Warned  int
	Blocked int
	Prompts int
	Errors  int // checks that returned an error (treated as allow per fail-open policy)
}

// RecheckResult is what Run returns.
type RecheckResult struct {
	Summary  RecheckSummary
	Findings []RecheckFinding
	Passed   bool
}

// RecheckPresenter renders progress + the final result.
type RecheckPresenter interface {
	OnRecheckBegin(total int)
	OnRecheckProgress(done, total int, name string)
	OnRecheckResult(r RecheckResult)
	OnRecheckError(err error)
}

// NewRecheck wires the use case.
func NewRecheck(scanner LockfileScanner, checker DecisionChecker, presenter RecheckPresenter) *Recheck {
	return &Recheck{scanner: scanner, checker: checker, presenter: presenter}
}

// Run scans the lockfile, calls /check on every (direct or all,
// per req.IncludeAll) dep concurrently, and returns the result.
//
// Errors per-dep are non-fatal — they're counted in Summary.Errors
// and the dep is treated as "would have allowed" (fail-open is the
// install gate's policy too; reproducing it here keeps the mental
// model consistent).
func (rc *Recheck) Run(ctx context.Context, req RecheckRequest) (RecheckResult, error) {
	deps, err := rc.scanner.ScanProject(req.ProjectDir)
	if err != nil {
		rc.presenter.OnRecheckError(fmt.Errorf("scan: %w", err))
		return RecheckResult{}, err
	}

	if !req.IncludeAll {
		filtered := deps[:0]
		for _, d := range deps {
			if d.Direct {
				filtered = append(filtered, d)
			}
		}
		deps = filtered
	}
	if len(deps) == 0 {
		out := RecheckResult{Passed: true}
		rc.presenter.OnRecheckResult(out)
		return out, nil
	}

	rc.presenter.OnRecheckBegin(len(deps))
	raws := rc.runWorkers(ctx, deps)

	result := rc.summarize(deps, raws, req.FailOnPrompt)
	// Stable severity order for output. Block first, then prompt;
	// same-kind alphabetical.
	sort.Slice(result.Findings, func(i, j int) bool {
		ki, kj := result.Findings[i].Decision.Kind, result.Findings[j].Decision.Kind
		if ki != kj {
			return decisionWeight(ki) > decisionWeight(kj)
		}
		return result.Findings[i].Dep.Name < result.Findings[j].Dep.Name
	})
	rc.presenter.OnRecheckResult(result)
	return result, nil
}

// decisionWeight orders decisions by severity for sorting findings.
func decisionWeight(k domain.DecisionKind) int {
	switch k {
	case domain.DecisionBlock:
		return 4
	case domain.DecisionPrompt:
		return 3
	case domain.DecisionWarn:
		return 2
	case domain.DecisionAllow:
		return 1
	}
	return 0
}

// runWorkers fans /check calls out to recheckWorkers goroutines and
// returns the per-call results. Progress is fired inline in the
// consumer loop so a slow round-trip to the API stays visible.
func (rc *Recheck) runWorkers(ctx context.Context, deps []domain.Dependency) []rawResult {
	workerCount := min(recheckWorkers, runtime.NumCPU()*2, len(deps))
	tasks := make(chan int, len(deps))
	for i := range deps {
		tasks <- i
	}
	close(tasks)

	results := make(chan rawResult, len(deps))
	var wg sync.WaitGroup
	for range workerCount {
		wg.Go(func() {
			for i := range tasks {
				if ctx.Err() != nil {
					return
				}
				dep := deps[i]
				dec, err := rc.checker.Check(ctx, dep.Ecosystem, dep.Name, dep.Version)
				results <- rawResult{dep: dep, decision: dec, err: err}
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var collected []rawResult
	completed := 0
	total := len(deps)
	for r := range results {
		completed++
		rc.presenter.OnRecheckProgress(completed, total, r.dep.Name)
		collected = append(collected, r)
	}
	return collected
}

// rawResult is the per-call output the consumer loop summarises.
type rawResult struct {
	dep      domain.Dependency
	decision domain.Decision
	err      error
}

// summarize partitions raw results into the buckets + findings list.
// findings = anything that would have failed (block always, prompt
// when FailOnPrompt is true).
func (rc *Recheck) summarize(deps []domain.Dependency, raws []rawResult, failOnPrompt bool) RecheckResult {
	out := RecheckResult{
		Summary:  RecheckSummary{Total: len(deps)},
		Passed:   true,
		Findings: nil,
	}
	for _, raw := range raws {
		if raw.err != nil {
			out.Summary.Errors++
			continue
		}
		switch raw.decision.Kind {
		case domain.DecisionAllow:
			out.Summary.Allowed++
		case domain.DecisionWarn:
			out.Summary.Warned++
		case domain.DecisionPrompt:
			out.Summary.Prompts++
			if failOnPrompt {
				out.Findings = append(out.Findings, RecheckFinding{Dep: raw.dep, Decision: raw.decision})
				out.Passed = false
			}
		case domain.DecisionBlock:
			out.Summary.Blocked++
			out.Findings = append(out.Findings, RecheckFinding{Dep: raw.dep, Decision: raw.decision})
			out.Passed = false
		}
	}
	return out
}
