package domain

// DecisionKind is what the API said about a (package, version):
// allow, warn, block, or prompt-the-human.
type DecisionKind string

const (
	DecisionAllow  DecisionKind = "allow"
	DecisionWarn   DecisionKind = "warn"
	DecisionBlock  DecisionKind = "block"
	DecisionPrompt DecisionKind = "prompt"
)

// Severity grades the urgency of a non-allow decision.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Reason is one observed-behavior fact attached to a decision.
type Reason struct {
	Category string
	Detail   string
}

// DecisionSource records where the use case learned about a decision.
// It's part of the audit trail and used for cache-vs-network metrics.
type DecisionSource string

const (
	SourceAPI   DecisionSource = "api"
	SourceCache DecisionSource = "cache"
	SourceError DecisionSource = "error"
)

// Decision is everything the gate knows about one (Spec, ResolvedVersion)
// after consulting cache + API. It's a pure domain value: no JSON tags,
// no transport concerns. Adapters translate to/from this shape.
type Decision struct {
	Spec     PackageSpec
	Resolved string

	Kind     DecisionKind
	Severity Severity
	Reasons  []Reason
	Incident *Incident
	Source   DecisionSource
}
