package domain

import (
	"sort"
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
}

// Fingerprint summarizes observable behaviors of a (name, version).
// MVP fields are heuristics derivable from lockfile + manifest;
// AST-derived fields are nil until the AST scanner runs.
type Fingerprint struct {
	HasInstallScript    bool
	InstallScriptSHA256 string
	// AST-derived (later PR):
	ShellCalls       int
	NetCalls         int
	EnvReads         []string
	FSWrites         int
	ObfuscationScore float64
	ASTSummaryHash   string
	SourceSizeBytes  int
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

	sort.Slice(delta.Added, func(i, j int) bool { return delta.Added[i].Key() < delta.Added[j].Key() })
	sort.Slice(delta.Removed, func(i, j int) bool { return delta.Removed[i].Key() < delta.Removed[j].Key() })
	sort.Slice(delta.Upgraded, func(i, j int) bool { return delta.Upgraded[i].Old.Key() < delta.Upgraded[j].Old.Key() })

	return delta
}
