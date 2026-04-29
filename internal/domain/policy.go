package domain

// Action is what the gate ultimately decides to do with one spec, after
// folding in CI / TTY / override context. It is the output of policy
// evaluation, distinct from Decision.Kind which is just the API's
// recommendation.
type Action int

const (
	// ActionProceed: install this spec.
	ActionProceed Action = iota
	// ActionBlock: refuse this spec; install must abort.
	ActionBlock
	// ActionAskUser: the gate needs to interactively confirm with the
	// human before deciding. The use case calls a Confirmer port; the
	// final Action is then re-evaluated.
	ActionAskUser
)

// PolicyContext folds runtime conditions into policy evaluation. It is
// built by the use case at request time from EnvProbe + Confirmer
// availability; domain code only reads it.
type PolicyContext struct {
	InCI              bool
	OverrideAllow     bool
	OverrideReason    string
	HasInteractiveTTY bool
}

// OverrideValid reports whether the AEGIS_OVERRIDE flag is present AND
// usable. We require a reason because untraceable overrides defeat the
// audit trail that makes this product worth running in an enterprise.
func (pc PolicyContext) OverrideValid() bool {
	return pc.OverrideAllow && pc.OverrideReason != ""
}

// Outcome is the policy verdict for one decision.
type Outcome struct {
	Decision       Decision
	Action         Action
	OverrideUsed   bool
	OverrideReason string
	// PromotedFromPrompt is true when an in-CI or no-TTY environment
	// converted a `prompt` into a hard block. Surfaced for UX.
	PromotedFromPrompt bool
}

// Evaluate applies the gate's policy to a Decision in a given context.
// Pure function — no I/O — so its decision table is exhaustively
// testable. The caller is responsible for re-running Evaluate after
// resolving ActionAskUser via a Confirmer.
//
// Policy:
//
//	allow / warn        → Proceed (warnings shown by presenter)
//	block               → OverrideValid? Proceed(audit) : Block
//	prompt              → OverrideValid?            Proceed(audit)
//	                       InCI || !TTY?            Block (promoted)
//	                       else                     AskUser
func Evaluate(d Decision, pc PolicyContext) Outcome {
	out := Outcome{Decision: d}

	switch d.Kind {
	case DecisionAllow, DecisionWarn:
		out.Action = ActionProceed

	case DecisionBlock:
		if pc.OverrideValid() {
			out.Action = ActionProceed
			out.OverrideUsed = true
			out.OverrideReason = pc.OverrideReason
			return out
		}
		out.Action = ActionBlock

	case DecisionPrompt:
		if pc.OverrideValid() {
			out.Action = ActionProceed
			out.OverrideUsed = true
			out.OverrideReason = pc.OverrideReason
			return out
		}
		if pc.InCI || !pc.HasInteractiveTTY {
			out.Action = ActionBlock
			out.PromotedFromPrompt = true
			return out
		}
		out.Action = ActionAskUser

	default:
		// Unknown decision kind — fail open. The presenter logs the
		// surprise; we don't want to block on schema drift.
		out.Action = ActionProceed
	}
	return out
}

// ResolvePrompt collapses an AskUser outcome into Proceed or Block
// based on what the human said. Pure; the use case calls this after
// consulting a Confirmer.
func ResolvePrompt(o Outcome, allowed bool) Outcome {
	if o.Action != ActionAskUser {
		return o
	}
	if allowed {
		o.Action = ActionProceed
		o.OverrideUsed = true
		o.OverrideReason = "user-allowed"
		return o
	}
	o.Action = ActionBlock
	return o
}
