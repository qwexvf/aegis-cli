package domain

import (
	"cmp"
	"slices"
	"time"
)

// SnapshotSchemaVersion is the on-disk schema version. Bump only on
// breaking changes; new optional fields don't require a bump because
// readers ignore unknown JSON keys.
const SnapshotSchemaVersion = 1

// Snapshot is a frozen, ordered list of every dependency the gate
// observed in a project — typically derived from the project's
// lockfile. Snapshots are the unit of comparison for behavioral diff.
type Snapshot struct {
	SchemaVersion int
	CreatedAt     time.Time
	AegisVersion  string
	Project       string // optional human label (cwd basename)
	Deps          []Dependency
}

// Dependency is one (ecosystem, name, version) entry plus optional
// metadata. Direct == true when the dep appears in the project's
// manifest (package.json) directly; false for transitives.
type Dependency struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
	Integrity string // sha512-... from lockfile (if available)
	Direct    bool
	// Fingerprint is reserved for behavioral data (AST scan, depsandbox).
	// Empty in the MVP snapshot — populated by `aegis snapshot enrich`
	// in a follow-up PR.
	Fingerprint *Fingerprint
	// Advisories lists known vulnerabilities matched against this
	// (Ecosystem, Name, Version) tuple by `aegis snapshot enrich`
	// (via OSV.dev or other public feeds). Empty slice means
	// "looked up, none found"; nil means "not yet looked up". The
	// distinction matters: nil triggers a lookup on next enrich,
	// empty slice doesn't.
	Advisories []Advisory `json:",omitempty"`
	// Reachability records whether user code imports this dep. Tri-state
	// because "couldn't tell" (unsupported language, parse error) is
	// real information. Old snapshots load with the zero value
	// ReachabilityUnknown so existing scoring is unchanged.
	Reachability Reachability `json:",omitempty"`
	// UsedSymbols lists the imported binding names the user's source
	// referenced from this dep, when reachability scanning observed
	// them. Empty when Reachability != Used or when the language
	// doesn't support used-symbol extraction (Rust, Ruby, C#).
	//
	// Consumers can use this to gate per-capability suppression: a
	// CVE in `lodash.template` shouldn't fire on a project that only
	// calls `lodash.merge`. The field is informational only — the
	// reachability layer doesn't try to map symbols → CVEs itself.
	UsedSymbols []string `json:",omitempty"`
}

// Reachability classifies whether a dep is referenced by the user's
// project source.
type Reachability uint8

const (
	// ReachabilityUnknown is the default — analysis hasn't run, the
	// language isn't supported, or parsing failed. Risk scoring
	// treats this the same as Used (conservative).
	ReachabilityUnknown Reachability = iota
	// ReachabilityUsed: at least one user-source file imports this dep.
	ReachabilityUsed
	// ReachabilityUnused: project source was scanned and no import
	// matched. Risk score may be downgraded.
	ReachabilityUnused
)

// String returns the lowercase enum name; used by presenters.
func (r Reachability) String() string {
	switch r {
	case ReachabilityUsed:
		return "used"
	case ReachabilityUnused:
		return "unused"
	}
	return "unknown"
}

// Fingerprint summarizes observable behaviors of a (name, version) in
// language-neutral terms. Per-ecosystem AST scanners populate this
// (see internal/infra/astscan/<lang>) by mapping their language's
// dangerous patterns onto Capability + InstallHook values.
//
// Empty Fingerprint means "not analyzed yet" — distinguished from "no
// dangerous behaviors found" by Analyzed=true with empty slices.
type Fingerprint struct {
	// Analyzed is true once an AST scanner has visited this dependency.
	// Used to distinguish "we looked and found nothing" from "we
	// haven't looked yet".
	Analyzed bool

	// Capabilities is the set of behaviors the scanner detected. Order
	// is stable (sorted by Capability ordinal) for deterministic output.
	Capabilities CapabilitySet

	// Hooks lists declared install-time scripts (npm postinstall,
	// pip setup.py, cargo build.rs, ...). Empty when the package
	// declares no hook.
	Hooks []InstallHook

	// EnvReads enumerates the env-var names read at the source level
	// (e.g. "AWS_ACCESS_KEY_ID"). Carried separately from Capabilities
	// because the *names* matter for credential-theft heuristics.
	EnvReads []string

	// SourceSizeBytes is the total size of the .js / .py / etc. source
	// the scanner walked. Used by drift detection (sudden size jumps).
	SourceSizeBytes int

	// ASTSummaryHash is a hash over the scanner's analysis output. Two
	// versions with the same hash had identical findings; a hash
	// change signals "behavioral diff" even if Capability sets match.
	ASTSummaryHash string
}

// Key uniquely identifies a Dependency for diff purposes.
func (d Dependency) Key() string {
	return string(d.Ecosystem) + "/" + d.Name
}

// VersionedKey adds the version. Used for cache lookups.
func (d Dependency) VersionedKey() string {
	return d.Key() + "@" + d.Version
}

// SnapshotDelta is the result of comparing two snapshots.
type SnapshotDelta struct {
	Added    []Dependency // present in B, not in A
	Removed  []Dependency // present in A, not in B
	Upgraded []DepUpgrade // same Key in both, different Version
	// Note: same name + same version = no entry (no change to report).
}

// DepUpgrade is one (name) appearing in both snapshots at different
// versions. Old/New carry the full Dependency for context.
type DepUpgrade struct {
	Name string
	Old  Dependency
	New  Dependency
}

// Empty reports whether the delta has no changes.
func (d SnapshotDelta) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Upgraded) == 0
}

// DiffSnapshots computes B minus A as a SnapshotDelta. Pure: no I/O,
// no allocations beyond the result. Order of inputs is stable; the
// returned slices are sorted by Key/Name for deterministic output.
func DiffSnapshots(a, b Snapshot) SnapshotDelta {
	aByKey := make(map[string]Dependency, len(a.Deps))
	for _, d := range a.Deps {
		aByKey[d.Key()] = d
	}
	bByKey := make(map[string]Dependency, len(b.Deps))
	for _, d := range b.Deps {
		bByKey[d.Key()] = d
	}

	var delta SnapshotDelta
	for k, bd := range bByKey {
		ad, ok := aByKey[k]
		switch {
		case !ok:
			delta.Added = append(delta.Added, bd)
		case ad.Version != bd.Version:
			delta.Upgraded = append(delta.Upgraded, DepUpgrade{
				Name: bd.Name,
				Old:  ad,
				New:  bd,
			})
		}
	}
	for k, ad := range aByKey {
		if _, ok := bByKey[k]; !ok {
			delta.Removed = append(delta.Removed, ad)
		}
	}

	slices.SortFunc(delta.Added, func(a, b Dependency) int { return cmp.Compare(a.Key(), b.Key()) })
	slices.SortFunc(delta.Removed, func(a, b Dependency) int { return cmp.Compare(a.Key(), b.Key()) })
	slices.SortFunc(delta.Upgraded, func(a, b DepUpgrade) int { return cmp.Compare(a.Old.Key(), b.Old.Key()) })

	return delta
}
