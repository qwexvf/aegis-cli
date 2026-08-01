//! Snapshot lifecycle types and pure diff logic. Vis-a-vis port of Go's
//! `internal/domain/snapshot.go`.
//!
//! A `Snapshot` is the persisted per-project record of its pinned dependencies
//! (from the lockfile) plus the enrichment results the gate has accumulated
//! for each one. It is the unit of comparison for `snapshot diff` and the
//! persisted state for `snapshot enrich` / `snapshot rescan`.
//!
//! This module is pure — no I/O, no serde. The CLI owns the on-disk wire
//! format; here we keep the domain invariants: schema version, the
//! `None`-vs-`Some(empty)` advisory contract, and the Added/Removed/Upgraded
//! diff shape.

use crate::types::{Dependency, Ecosystem};

/// On-disk schema version we read and write. Bumps are rare — the reader
/// ignores unknown keys (matching Go's tolerant decoder) so additive fields
/// don't need a bump. Mirrors `domain.SnapshotSchemaVersion`.
pub const SNAPSHOT_SCHEMA_VERSION: i64 = 1;

/// A captured snapshot of a project's lockfile plus its per-dep enrichment
/// (AST fingerprint, advisories, reachability, license, …). Mirrors
/// `domain.Snapshot`.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub schema_version: i64,
    /// RFC-3339 UTC capture timestamp. callers stamp it (CLI owns the clock,
    /// domain stays I/O-free).
    pub created_at: String,
    /// `aegis` binary version that wrote the snapshot (best-effort, omittable).
    pub aegis_version: String,
    /// Project identity = the project dir's basename (matches Go).
    pub project: String,
    /// Per-dependency rows. Order is preserved as the lockfile parser emitted
    /// it; the diff ignores order.
    pub deps: Vec<Dependency>,
}

impl Snapshot {
    /// Construct a fresh, enriched-less snapshot. `schema_version` is set to
    /// [`SNAPSHOT_SCHEMA_VERSION`]; the caller fills in `created_at` /
    /// `aegis_version` / `project` / `deps`.
    pub fn empty() -> Self {
        Snapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            created_at: String::new(),
            aegis_version: String::new(),
            project: String::new(),
            deps: Vec::new(),
        }
    }

    /// Number of dependencies in the snapshot.
    pub fn len(&self) -> usize {
        self.deps.len()
    }

    /// True when the snapshot has no dependencies (e.g. project has no
    /// recognized lockfile).
    pub fn is_empty(&self) -> bool {
        self.deps.is_empty()
    }
}

/// Diff kinds the snapshot walker produces.
///
/// Keying is on `(ecosystem, name)` — a version change between the two
/// snapshots becomes `Upgraded`; a key present only in `prev` is `Removed`;
/// only in `next` is `Added`. Mirrors `domain.SnapshotDelta`.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum DepDelta {
    /// In `next` but absent from `prev`.
    Added(Dependency),
    /// In `prev` but absent from `next`.
    Removed(Dependency),
    /// Same `(ecosystem, name)` but a different version string — carries both
    /// the prior and the new dependency so the caller can compute drift.
    Upgraded { prev: Dependency, next: Dependency },
}

impl DepDelta {
    /// Ecosystem of the changed dep — convenience for ordering/grouping.
    pub fn ecosystem(&self) -> Ecosystem {
        match self {
            DepDelta::Added(d) | DepDelta::Removed(d) => d.ecosystem,
            DepDelta::Upgraded { next, .. } => next.ecosystem,
        }
    }

    /// Name of the changed dep.
    pub fn name(&self) -> &str {
        match self {
            DepDelta::Added(d) | DepDelta::Removed(d) => &d.name,
            DepDelta::Upgraded { next, .. } => &next.name,
        }
    }
}

/// Compute the Added/Removed/Upgraded diff of two snapshots, keyed on
/// `(ecosystem, name)`. A matching key with a non-equal version becomes an
/// `Upgraded` entry; matching key with equal version is dropped (no change).
/// Mirrors `domain.DiffSnapshots`.
///
/// Output order: deterministic — ecosystem/name ascending inside each kind,
/// kinds in Added → Removed → Upgraded order so callers can render a stable
/// report without re-sorting.
pub fn diff_snapshots(prev: &Snapshot, next: &Snapshot) -> Vec<DepDelta> {
    use std::collections::HashMap;
    let mut prev_idx: HashMap<(Ecosystem, &str), &Dependency> = HashMap::new();
    for d in &prev.deps {
        prev_idx.insert((d.ecosystem, d.name.as_str()), d);
    }
    let mut next_idx: HashMap<(Ecosystem, &str), &Dependency> = HashMap::new();
    for d in &next.deps {
        next_idx.insert((d.ecosystem, d.name.as_str()), d);
    }

    let mut added: Vec<&Dependency> = Vec::new();
    let mut upgraded: Vec<(&Dependency, &Dependency)> = Vec::new();
    for d in &next.deps {
        match prev_idx.get(&(d.ecosystem, d.name.as_str())) {
            None => added.push(d),
            Some(prev_dep) if prev_dep.version != d.version => upgraded.push((prev_dep, d)),
            Some(_) => {}
        }
    }
    let mut removed: Vec<&Dependency> = Vec::new();
    for d in &prev.deps {
        if !next_idx.contains_key(&(d.ecosystem, d.name.as_str())) {
            removed.push(d);
        }
    }

    added.sort_by(|a, b| key_cmp((a.ecosystem, &a.name), (b.ecosystem, &b.name)));
    removed.sort_by(|a, b| key_cmp((a.ecosystem, &a.name), (b.ecosystem, &b.name)));
    upgraded.sort_by(|(pn, nn), (pb, nb)| {
        key_cmp((pn.ecosystem, &pn.name), (pb.ecosystem, &pb.name))
            .then(key_cmp((nn.ecosystem, &nn.name), (nb.ecosystem, &nb.name)))
    });

    let mut out: Vec<DepDelta> = Vec::new();
    out.extend(added.into_iter().cloned().map(DepDelta::Added));
    out.extend(removed.into_iter().cloned().map(DepDelta::Removed));
    out.extend(upgraded.into_iter().map(|(prev, next)| DepDelta::Upgraded {
        prev: prev.clone(),
        next: next.clone(),
    }));
    out
}

fn key_cmp(a: (Ecosystem, &str), b: (Ecosystem, &str)) -> std::cmp::Ordering {
    a.0.as_str().cmp(b.0.as_str()).then_with(|| a.1.cmp(b.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(eco: Ecosystem, name: &str, version: &str) -> Dependency {
        Dependency {
            ecosystem: eco,
            name: name.to_string(),
            version: version.to_string(),
            ..Default::default()
        }
    }

    fn snap(deps: Vec<Dependency>) -> Snapshot {
        Snapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            created_at: String::new(),
            aegis_version: String::new(),
            project: String::new(),
            deps,
        }
    }

    #[test]
    fn empty_snapshots_diff_empty() {
        assert!(diff_snapshots(&snap(vec![]), &snap(vec![])).is_empty());
    }

    #[test]
    fn new_dep_is_added() {
        let prev = snap(vec![dep(Ecosystem::Npm, "lodash", "4.17.20")]);
        let next = snap(vec![
            dep(Ecosystem::Npm, "lodash", "4.17.20"),
            dep(Ecosystem::PyPI, "requests", "2.31.0"),
        ]);
        let d = diff_snapshots(&prev, &next);
        assert_eq!(d.len(), 1);
        match &d[0] {
            DepDelta::Added(x) => assert_eq!(
                (x.ecosystem, x.name.as_str(), x.version.as_str()),
                (Ecosystem::PyPI, "requests", "2.31.0")
            ),
            other => panic!("expected Added, got {other:?}"),
        }
    }

    #[test]
    fn dropped_dep_is_removed() {
        let prev = snap(vec![
            dep(Ecosystem::Npm, "lodash", "4.17.20"),
            dep(Ecosystem::PyPI, "requests", "2.31.0"),
        ]);
        let next = snap(vec![dep(Ecosystem::Npm, "lodash", "4.17.20")]);
        let d = diff_snapshots(&prev, &next);
        assert_eq!(d.len(), 1);
        assert!(matches!(d[0], DepDelta::Removed(_)));
    }

    #[test]
    fn version_change_is_upgraded() {
        let prev = snap(vec![dep(Ecosystem::Npm, "lodash", "4.17.20")]);
        let next = snap(vec![dep(Ecosystem::Npm, "lodash", "4.17.21")]);
        let d = diff_snapshots(&prev, &next);
        assert_eq!(d.len(), 1);
        match &d[0] {
            DepDelta::Upgraded { prev, next } => {
                assert_eq!(prev.version, "4.17.20");
                assert_eq!(next.version, "4.17.21");
            }
            other => panic!("expected Upgraded, got {other:?}"),
        }
    }

    #[test]
    fn same_version_is_no_change() {
        let prev = snap(vec![dep(Ecosystem::Npm, "lodash", "4.17.21")]);
        let next = snap(vec![dep(Ecosystem::Npm, "lodash", "4.17.21")]);
        assert!(diff_snapshots(&prev, &next).is_empty());
    }

    #[test]
    fn same_name_different_ecosystem_is_added_not_upgraded() {
        // "go" is both an ecosystem name and a potential pkg name elsewhere,
        // but the canonical case: an npm "go" dep and a Go "go" dep co-exist
        // because (ecosystem, name) is the key.
        let prev = snap(vec![dep(Ecosystem::Npm, "p", "1.0.0")]);
        let next = snap(vec![
            dep(Ecosystem::Npm, "p", "1.0.0"),
            dep(Ecosystem::Go, "p", "1.0.0"),
        ]);
        let d = diff_snapshots(&prev, &next);
        assert_eq!(d.len(), 1);
        assert!(matches!(d[0], DepDelta::Added(_)));
    }

    #[test]
    fn output_is_sorted_within_kinds() {
        let prev = snap(vec![
            dep(Ecosystem::Npm, "zeta", "1.0.0"),
            dep(Ecosystem::Npm, "alpha", "1.0.0"),
            dep(Ecosystem::PyPI, "requests", "2.0.0"),
        ]);
        let next = snap(vec![
            dep(Ecosystem::Npm, "alpha", "1.0.1"),
            dep(Ecosystem::Npm, "beta", "1.0.0"),
        ]);
        let d = diff_snapshots(&prev, &next);
        // 1 added (beta npm), 2 removed (zeta npm, requests pypi), 1 upgraded (alpha npm)
        assert_eq!(d.len(), 4);
        // Added first, name-sorted within kind; the diff walker emits
        // kinds in Added → Removed → Upgraded.
        assert!(matches!(d[0], DepDelta::Added(_)));
        assert!(matches!(d[1], DepDelta::Removed(_)));
        assert!(matches!(d[2], DepDelta::Removed(_)));
        assert!(matches!(d[3], DepDelta::Upgraded { .. }));
        // Removed entries sort by ecosystem,name: npm/zeta < pypi/requests.
        match (&d[1], &d[2]) {
            (DepDelta::Removed(a), DepDelta::Removed(b)) => {
                assert_eq!(a.name, "zeta");
                assert_eq!(b.name, "requests");
            }
            _ => unreachable!(),
        }
    }
}
