// Package domain — Advisory is a known vulnerability or supply-chain
// incident attached to a (Ecosystem, Name, Version) tuple. Sourced
// from public aggregators (OSV.dev, npm advisory bulk endpoint) so
// the CLI can detect known-bad packages without relying on the
// proprietary Aegis API.
//
// Advisory is intentionally small — just enough for the user to
// recognise the issue and find the upstream record. The full CVSS
// vector, references list, and patched-versions metadata stay at the
// upstream source; the CLI carries a stable URL so the user can pivot.
package domain

// Advisory is one known vulnerability against a specific package
// version. Multiple advisories per dep are common (an OSV record
// may be aliased from a CVE, a GHSA, a Snyk SNYK-JS-…, …).
type Advisory struct {
	// ID is the canonical identifier from the source — typically
	// "GHSA-jvqj-7wpc-9bqp" or "CVE-2018-16487". Stable across
	// fetches; safe to dedupe on.
	ID string

	// Aliases lists IDs that point at the same vulnerability via a
	// different naming scheme (e.g. an advisory primarily indexed
	// under GHSA may also have a CVE alias). Empty when the source
	// reports none.
	Aliases []string

	// Severity is the upstream-reported severity bucketed onto our
	// own enum. Falls back to SevInfo when the source doesn't
	// classify it (advisory-without-CVSS is common in OSV).
	Severity Severity

	// Summary is a one-line human description. Falls back to "(no
	// summary provided)" when the source is empty.
	Summary string

	// URL is the canonical advisory page (osv.dev/vulnerability/...
	// or github.com/advisories/...). Empty when the source has no
	// stable URL.
	URL string

	// Source identifies which feed produced this advisory. "osv"
	// today; "npm" / "ghsa" / "internal" planned. Used for dedup
	// when multiple feeds return the same ID.
	Source string

	// FixedIn is the earliest version that resolves this advisory, as
	// reported by the upstream feed's affected[].ranges events. Empty
	// when the feed doesn't include fix metadata. Format matches the
	// advisory's ecosystem (semver for npm/cargo/go, PEP 440 for PyPI).
	FixedIn string `json:",omitempty"`

	// EPSS is the Exploit Prediction Scoring System probability (0–1).
	// Populated by the FIRST.org API during advisory enrichment. 0 means
	// not scored (advisory has no CVE alias, or enrichment was skipped).
	EPSS float64 `json:",omitempty"`

	// EPSSPercentile is EPSS's relative rank among all CVEs (0–1). 0.99
	// means this CVE is more likely to be exploited than 99% of all CVEs.
	// 0 when EPSS is not set.
	EPSSPercentile float64 `json:",omitempty"`

	// InKEV is true when this advisory appears in CISA's Known Exploited
	// Vulnerabilities catalog — actively exploited in the wild with a
	// mandatory federal remediation deadline. Populated during enrichment.
	InKEV bool `json:",omitempty"`

	// AffectedFunctions lists specific function or method names that the
	// advisory says are vulnerable (e.g. ["lodash.template", "_.template"]).
	// Sourced from OSV's affected[].ecosystem_specific.functions when present.
	// Empty means the entire package is considered affected, or the advisory
	// doesn't carry function-level data (the common case).
	AffectedFunctions []string `json:",omitempty"`

	// VEXSuppressed is true when a VEX document with status "not_affected"
	// was applied to suppress this advisory for the dep being scored.
	// Populated only in CI run context; not persisted to the snapshot.
	VEXSuppressed bool `json:"-"`

	// FunctionUnreachable is true when symbol-level reachability cleared
	// this advisory: the advisory's AffectedFunctions don't intersect
	// the dep's UsedSymbols. The vulnerable function exists in the dep
	// but the user's source never calls it. Populated only in CI run
	// context; not persisted.
	FunctionUnreachable bool `json:"-"`
}

// AdvisoryQuery is a typed view of (eco, name, version) for batch
// vuln lookups. Lives in domain so adapters and use cases share the
// shape — the alternative (each adapter inventing its own struct)
// breaks the dependency direction.
type AdvisoryQuery struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
}

// Key returns the canonical string form used as a map key when
// matching query results back to the input list. Format:
// "<ecosystem>/<name>@<version>".
func (q AdvisoryQuery) Key() string {
	return string(q.Ecosystem) + "/" + q.Name + "@" + q.Version
}

// MaxSeverity returns the highest-severity advisory in the slice,
// or SevInfo if the slice is empty. Used by the CI scorer to map
// "this dep has advisories" onto the existing Verdict thresholds
// without per-advisory wiring.
func MaxSeverity(advs []Advisory) Severity {
	max := SevInfo
	for _, a := range advs {
		if severityRank(a.Severity) > severityRank(max) {
			max = a.Severity
		}
	}
	return max
}

// VerdictForAdvisories maps an advisory list onto the same
// VerdictKind enum the AST scorer uses, so CI can fold both signals
// into one number with `max(astVerdict, advisoryVerdict)`. Mapping
// is intentionally strict — a Critical or High CVE is never lower
// than a Block, regardless of what AST analysis says about the
// package's behavioural surface.
//
//	Critical / High → Block
//	Medium          → Prompt
//	Low             → Review
//	Info / unknown  → Safe
//
// Empty slice returns Safe.
func VerdictForAdvisories(advs []Advisory) VerdictKind {
	switch MaxSeverity(advs) {
	case SevCritical, SevHigh:
		return VerdictBlock
	case SevMedium:
		return VerdictPrompt
	case SevLow:
		return VerdictReview
	}
	return VerdictSafe
}

// severityRank orders Severity for comparison. Critical > High >
// Medium > Low > Info > Unknown. Defined here (not as a method on
// Severity) so the existing Severity type stays a pure string alias
// and remains JSON-stable.
func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	case SevInfo:
		return 0
	}
	return -1
}
