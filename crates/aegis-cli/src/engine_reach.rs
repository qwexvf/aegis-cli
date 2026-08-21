//! Precise reachability backed by ripple's resolved code-graph.
//!
//! aegis-reach's own transitive walk is name-based: a callee token `foo` links
//! to *every* function named `foo` in the tree, so two unrelated `get()`s
//! collapse and the walk over-reports who reaches a symbol. That errs safe
//! (over-reporting reachable = fewer downgrades) but leaves real downgrades on
//! the table.
//!
//! Since ripple gained `NodeKind::External` and external-import binding, the
//! engine graph carries a node per referenced `dep.symbol`, so it can answer
//! reachability entirely on its own — no aegis-reach seed borrow. This backend
//! indexes the project root and derives every answer from the engine's three
//! queries:
//!
//! - `engine::uses(dep, symbol)`  — project symbols that reference `dep.symbol`
//!   directly (the direct users).
//! - `engine::reaches(dep, symbol)` — transitive call routes into `dep.symbol`;
//!   each route's origin is a (possibly transitive-only) caller.
//! - `engine::imports(dep)` — import-level floor: is the dep imported at all.
//!
//! Compiled only under the `engine-reach` feature.

use std::collections::HashSet;
use std::path::Path;

use aegis_domain::Reachability;
use aegis_reach::ReachEntry;
use engine::{InMemoryGraph, Node, NodeKind, Route};

/// Direct users of `package.symbol` plus every function that transitively
/// reaches one of them along resolved call edges. Direct entries carry
/// `direct = true`; transitive ones `false`.
///
/// The answer is fully self-seeded from the engine's external-symbol graph —
/// `uses` supplies the direct users, `reaches` the transitive callers. No
/// aegis-reach seed is consulted.
pub fn transitive(
    root: &Path,
    files: &[(String, Vec<u8>)],
    package: &str,
    symbol: &str,
) -> Vec<ReachEntry> {
    // Resolution needs the project root, not the scan sub-dir: TS path aliases
    // (`~/x`, `@/x`) live in tsconfig.json at the package root, and indexing a
    // sub-dir that can't see it silently drops every aliased import edge — which
    // reads as "unreachable" and would wrongly downgrade a live advisory. Walk up
    // to the nearest project marker and index from there.
    let index_root = project_root(root);
    let graph = match engine::index(&index_root) {
        Ok(g) => g,
        // no resolved graph (unsupported lang, parse failure): fall to the
        // name-based floor rather than assert unreachable.
        Err(_) => return aegis_reach::functions_reaching_transitive(package, symbol, files),
    };

    let mut out: Vec<ReachEntry> = Vec::new();
    let mut seen: HashSet<engine::SymbolId> = HashSet::new();

    // Direct users: project symbols with a Calls/References edge to the external
    // `dep.symbol` node. Keep function/method nodes only — module/file nodes are
    // import artifacts, not callers.
    for n in engine::uses(&graph, package, symbol) {
        if is_caller(&n) && seen.insert(n.id) {
            out.push(entry_from(&n, true));
        }
    }

    // Transitive callers: the origin of each route `reaches` returns. `reaches`
    // yields one shortest route per distinct reaching symbol; the origin is the
    // `src` of the route's first edge (routes don't carry the origin node, only
    // the nodes they land on). Direct users already seen are skipped.
    for route in engine::reaches(&graph, package, symbol) {
        let Some(origin_id) = route_origin(&route) else {
            continue;
        };
        if seen.contains(&origin_id) {
            continue;
        }
        if let Some(n) = graph.get(origin_id) {
            if is_caller(n) && seen.insert(origin_id) {
                out.push(entry_from(n, false));
            }
        }
    }

    // Soundness floor: when the resolved graph binds nothing for this
    // `dep.symbol` — the documented external-binding gaps are namespace/default
    // member calls (`import cp from 'child_process'; cp.execSync()`) and
    // side-effect-only imports — an empty engine answer is a resolution gap, not
    // proof of unreachability. Fall back to aegis-reach's name-based walk so the
    // `reach` command never under-reports a live caller. The name-based tier
    // over-approximates (errs toward "reachable"), keeping the security-safe bias.
    if out.is_empty() {
        return aegis_reach::functions_reaching_transitive(package, symbol, files);
    }

    out
}

/// Dep-level reachability verdict for the `ci`/scan downgrade path, computed
/// from the engine's four-way signal rolled up over every referenced symbol of
/// the dep:
///
/// | engine result                          | verdict  |
/// |----------------------------------------|----------|
/// | any symbol `reaches` non-empty         | Used     |
/// | else any symbol `uses` non-empty       | Used     |
/// | else `imports` true                    | Unknown  |
/// | else (`imports` false)                 | Unused   |
///
/// The import-level floor (`imports` true but nothing proven reached) yields
/// `Unknown`, never `Unused`: a resolution gap must never hard-suppress a live
/// advisory. `Unused` is only returned when the dep is not imported at all.
pub fn dep_reachability(graph: &InMemoryGraph, dep: &str) -> Reachability {
    let symbols = external_symbols(graph, dep);
    let mut any_uses = false;
    for s in &symbols {
        if !engine::reaches(graph, dep, s).is_empty() {
            return Reachability::Used;
        }
        // cheaper than reaches; remember it so a second pass isn't needed
        if !any_uses && !engine::uses(graph, dep, s).is_empty() {
            any_uses = true;
        }
    }
    verdict(false, any_uses, engine::imports(graph, dep))
}

/// Pure four-way verdict mapping, factored out so it is unit-testable without a
/// graph. `reaches`/`uses` are "non-empty?" booleans; `imports` the floor.
fn verdict(reaches_nonempty: bool, uses_nonempty: bool, imports: bool) -> Reachability {
    if reaches_nonempty || uses_nonempty {
        Reachability::Used
    } else if imports {
        Reachability::Unknown
    } else {
        Reachability::Unused
    }
}

/// Index a project directory for the engine-backed ci path. Walks up to the
/// nearest project marker (same reason as [`transitive`]) so path-alias imports
/// resolve. `None` when the tree has no resolvable graph.
pub fn index_project(project_dir: &Path) -> Option<InMemoryGraph> {
    engine::index(&project_root(project_dir)).ok()
}

/// Every external `dep.symbol` node's symbol name for `dep`. The bare module
/// node (`qualified_name == dep`, a side-effect / namespace import) has no
/// symbol part and is skipped.
fn external_symbols(graph: &InMemoryGraph, dep: &str) -> Vec<String> {
    let mut out: Vec<String> = graph
        .nodes()
        .filter(|n| n.kind == NodeKind::External && n.module_path == dep)
        .filter(|n| n.qualified_name != dep && !n.name.is_empty())
        .map(|n| n.name.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The origin symbol of a `reaches` route — `src` of its first edge. `reaches`
/// walks call edges from a caller to the external node, so the first edge leaves
/// the caller we want. `None` for an empty route (shouldn't happen).
fn route_origin(route: &Route) -> Option<engine::SymbolId> {
    route.steps.first().map(|s| s.edge.src)
}

/// Only function/method nodes are callers; module/file nodes are import
/// artifacts, not reachers.
fn is_caller(n: &Node) -> bool {
    matches!(n.kind, NodeKind::Function | NodeKind::Method)
}

fn entry_from(n: &Node, direct: bool) -> ReachEntry {
    ReachEntry {
        file: n.module_path.clone(),
        function: n.name.clone(),
        line: n.span.start_line as usize,
        direct,
    }
}

/// Nearest ancestor (including `start`) holding a project manifest — where
/// import-alias config and the full module set live. Falls back to `start` when
/// no marker is found, so a bare directory still indexes.
fn project_root(start: &Path) -> std::path::PathBuf {
    const MARKERS: &[&str] = &[
        "tsconfig.json",
        "package.json",
        "go.mod",
        "pyproject.toml",
        "setup.py",
        "Gemfile",
    ];
    let mut dir = Some(start);
    while let Some(d) = dir {
        if MARKERS.iter().any(|m| d.join(m).exists()) {
            return d.to_path_buf();
        }
        dir = d.parent();
    }
    start.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// std-only scratch dir (no tempfile dep); removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "aegis-engine-reach-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn verdict_maps_four_ways() {
        // reaches non-empty → Used, regardless of the rest.
        assert_eq!(verdict(true, false, false), Reachability::Used);
        assert_eq!(verdict(true, true, true), Reachability::Used);
        // reaches empty, uses non-empty → Used (conservative).
        assert_eq!(verdict(false, true, false), Reachability::Used);
        assert_eq!(verdict(false, true, true), Reachability::Used);
        // both empty, imports true → Unknown (floor, no downgrade).
        assert_eq!(verdict(false, false, true), Reachability::Unknown);
        // imports false → Unused (downgrade).
        assert_eq!(verdict(false, false, false), Reachability::Unused);
    }

    /// A three-file TS fixture: `entry` → `mid` → `useQuery` (external). The
    /// engine must find `mid` as a direct user and `entry` as a transitive
    /// caller purely from its own external-symbol graph — no aegis-reach seed.
    #[test]
    fn self_seeds_transitive_caller_from_engine_graph() {
        let dir = Scratch::new();
        fs::write(dir.path().join("package.json"), "{\"name\":\"fix\"}\n").unwrap();
        fs::write(
            dir.path().join("mid.ts"),
            "import { useQuery } from 'urql';\nexport function mid() { return useQuery(); }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("entry.ts"),
            "import { mid } from './mid';\nexport function entry() { return mid(); }\n",
        )
        .unwrap();

        let out = transitive(dir.path(), &[], "urql", "useQuery");

        let direct: Vec<&ReachEntry> = out.iter().filter(|e| e.direct).collect();
        let transitive: Vec<&ReachEntry> = out.iter().filter(|e| !e.direct).collect();

        assert!(
            direct.iter().any(|e| e.function == "mid"),
            "mid should be a direct user of urql.useQuery, got {out:?}"
        );
        assert!(
            transitive.iter().any(|e| e.function == "entry"),
            "entry should be a transitive caller (entry → mid → useQuery), got {out:?}"
        );
    }

    #[test]
    fn dep_reachability_used_when_reached() {
        let dir = Scratch::new();
        fs::write(dir.path().join("package.json"), "{\"name\":\"fix\"}\n").unwrap();
        fs::write(
            dir.path().join("app.ts"),
            "import { useQuery } from 'urql';\nexport function app() { return useQuery(); }\n",
        )
        .unwrap();
        let graph = engine::index(dir.path()).unwrap();
        assert_eq!(dep_reachability(&graph, "urql"), Reachability::Used);
    }

    #[test]
    fn dep_reachability_unused_when_not_imported() {
        let dir = Scratch::new();
        fs::write(dir.path().join("package.json"), "{\"name\":\"fix\"}\n").unwrap();
        fs::write(
            dir.path().join("app.ts"),
            "export function app() { return 1; }\n",
        )
        .unwrap();
        let graph = engine::index(dir.path()).unwrap();
        assert_eq!(dep_reachability(&graph, "urql"), Reachability::Unused);
    }
}
