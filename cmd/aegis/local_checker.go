package main

import (
	"context"
	"fmt"
	"os"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// localChecker implements usecase.DecisionChecker using the offline AST +
// heuristic engine — the same one `aegis analyze` and `aegis ci` use. It is
// the fallback when the Cloud API is unreachable, so the install gate still
// verifies a package instead of failing open and silently installing it.
type localChecker struct {
	analyze *usecase.Analyze
}

func (l localChecker) Check(ctx context.Context, eco domain.Ecosystem, name, version string) (domain.Decision, error) {
	res, err := l.analyze.Run(ctx, usecase.AnalyzeRequest{
		Ecosystem: eco, Name: name, Version: version, Silent: true,
	})
	if err != nil {
		return domain.Decision{}, err
	}
	d := domain.Decision{
		Kind:     verdictToDecisionKind(res.Verdict),
		Severity: severityFromScore(res.Risk.Score),
		Source:   domain.SourceLocal,
	}
	for _, f := range res.Risk.Flags {
		d.Reasons = append(d.Reasons, domain.Reason{Category: f.Code, Detail: f.Detail})
	}
	return d, nil
}

func verdictToDecisionKind(v domain.VerdictKind) domain.DecisionKind {
	switch v {
	case domain.VerdictBlock:
		return domain.DecisionBlock
	case domain.VerdictPrompt:
		return domain.DecisionPrompt
	case domain.VerdictReview:
		return domain.DecisionWarn
	default:
		return domain.DecisionAllow
	}
}

func severityFromScore(score int) domain.Severity {
	switch {
	case score >= domain.VerdictThresholdBlock:
		return domain.SevCritical
	case score >= domain.VerdictThresholdPrompt:
		return domain.SevHigh
	case score >= domain.VerdictThresholdReview:
		return domain.SevMedium
	default:
		return domain.SevLow
	}
}

// fallbackChecker tries the primary checker (Cloud API) first and falls back
// to the secondary (local offline engine) when the primary errors — so a
// transient Cloud outage doesn't turn the gate into a silent no-op.
type fallbackChecker struct {
	primary  usecase.DecisionChecker
	fallback usecase.DecisionChecker
}

func (f fallbackChecker) Check(ctx context.Context, eco domain.Ecosystem, name, version string) (domain.Decision, error) {
	d, err := f.primary.Check(ctx, eco, name, version)
	if err == nil {
		return d, nil
	}
	fmt.Fprintf(os.Stderr, "[aegis] Cloud check unavailable (%v) — falling back to local offline scan\n", err)
	return f.fallback.Check(ctx, eco, name, version)
}
