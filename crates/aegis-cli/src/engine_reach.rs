//! Precise transitive reachability backed by ripple's resolved code-graph.
//!
//! aegis-reach's own transitive walk is name-based: a callee token `foo` links
//! to *every* function named `foo` in the tree, so two unrelated `get()`s
//! collapse and the walk over-reports who reaches a symbol. That errs safe
//! (over-reporting reachable = fewer downgrades) but leaves real downgrades on
//! the table.
//!
//! This backend keeps aegis-reach's dep-aware seeding — which project functions
//! *directly* use `package.symbol` — then does the transitive caller walk over
//! ripple's *resolved* edges (import bindings, scoping, per-root namespacing)
//! via `engine::impact` (blast radius = reverse/caller edges). Precise edges,
//! same output shape.
//!
//! Compiled only under the `engine-reach` feature.

use std::path::Path;

use aegis_reach::ReachEntry;
use engine::{Dir, EdgeKind, NodeKind};

/// Transitive caller-walk depth. Matches aegis-reach's unbounded name-based
/// walk closely enough while staying finite on dense graphs.
const REACH_DEPTH: usize = 12;

/// Direct users of `package.symbol` plus every function that transitively
/// reaches one of them along resolved call edges. Direct entries carry
/// `direct = true`; transitive ones `false`.
pub fn transitive(
    root: &Path,
    files: &[(String, Vec<u8>)],
    package: &str,
    symbol: &str,
) -> Vec<ReachEntry> {
    // Seeds: dep-aware direct users (aegis-reach knows the import binding).
    let direct: Vec<ReachEntry> = aegis_reach::functions_reaching(package, symbol, files)
        .into_iter()
        .map(|c| ReachEntry {
            file: c.file,
            function: c.function,
            line: c.line,
            direct: true,
        })
        .collect();
    if direct.is_empty() {
        return Vec::new();
    }

    // Resolution needs the project root, not the scan sub-dir: TS path aliases
    // (`~/x`, `@/x`) live in tsconfig.json at the package root, and indexing a
    // sub-dir that can't see it silently drops every aliased import edge — which
    // reads as "unreachable" and would wrongly downgrade a live advisory. Walk up
    // to the nearest project marker and index from there.
    let index_root = project_root(root);
    let graph = match engine::index(&index_root) {
        Ok(g) => g,
        // no resolved graph (unsupported lang, parse failure) — the direct
        // users are still a truthful answer, just without the precise walk
        Err(_) => return direct,
    };

    // Map each direct (file, function) onto its resolved graph node.
    let mut seeds: Vec<engine::SymbolId> = Vec::new();
    for e in &direct {
        for n in graph.nodes() {
            if n.name == e.function && module_matches(&n.module_path, &e.file) {
                seeds.push(n.id);
            }
        }
    }
    if seeds.is_empty() {
        return direct;
    }
    seeds.sort_by_key(|s| s.0);
    seeds.dedup();

    // Walk callers over CALL edges only — not Imports/References. Function-level
    // reachability asks "does this code *call* into the vulnerable function",
    // so a file that merely imports the module is not a reacher. Keep only
    // function/method nodes for the same reason (module/file nodes are import
    // artifacts, not callers).
    let call_kinds = [EdgeKind::Calls, EdgeKind::AsyncCall];
    let mut out = direct;
    for &seed in &seeds {
        for hop in graph.neighbors(seed, Dir::In, Some(&call_kinds), REACH_DEPTH) {
            if !matches!(hop.node.kind, NodeKind::Function | NodeKind::Method) {
                continue;
            }
            let dup = out
                .iter()
                .any(|e| e.function == hop.node.name && module_matches(&hop.node.module_path, &e.file));
            if dup {
                continue;
            }
            out.push(ReachEntry {
                file: hop.node.module_path.clone(),
                function: hop.node.name.clone(),
                line: hop.node.span.start_line as usize,
                direct: false,
            });
        }
    }
    out
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

/// ripple namespaces module paths by a per-root tag, so an exact string match
/// against aegis-reach's repo-relative path won't hold. Match on a path-segment
/// suffix instead (`a/b/app.ts` matches `app.ts` and `b/app.ts`, not
/// `myapp.ts`).
fn module_matches(module_path: &str, file: &str) -> bool {
    module_path == file
        || module_path
            .strip_suffix(file)
            .is_some_and(|p| p.is_empty() || p.ends_with('/'))
}
