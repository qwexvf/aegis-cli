# Reachability engine consolidation

Status: **design accepted, not implemented**
Driver: aegis-rs · Implementation home: ripple `engine` (+ `lang`, `resolve`, `ir`)
Date: 2026-08-21

## Decision

aegis will have **one** reachability system: ripple's resolved code-graph
engine. The name-based transitive walk and the single-file used-symbol pass in
`aegis-reach` are retired. Anything import-level can find that the call-graph
cannot yet is **ported into the engine**, not kept as a second system.

Rationale: two overlapping reachability implementations (aegis-reach
name-based + engine resolved) means two behaviours to reconcile, two sets of
false positives/negatives, and no single answer to "is this advisory
reachable?". Measurement on `web/src` (see below) showed the resolved graph is
a strict superset of the name-based result once integrated correctly — so the
name-based tier earns its keep only where the engine has a coverage gap. Close
those gaps in the engine and there is no reason to keep two.

## What the measurement showed (why one engine, not two)

Real repo `web/src`, function-level transitive reachability, name-based vs
engine (after fixing project-root indexing + call-edge-only walk):

| pkg.symbol | name-based | engine | delta |
|---|---|---|---|
| `urql.useQuery` | 24 (uniq) | 33 (uniq) | +9, all verified real |
| `urql.useMutation` | — | — | engine ⊇ name-based |
| `react-router.createFileRoute` | 41 | 41 | equal |

The 9 engine-only reachers were confirmed real callers name-based missed
(direct `useQuery` callers like `FindingDetailPane`/`SysadminPage`, and
hook-chain callers like `MembersSection → useOrgMembers → useQuery`). name-based
missed them because its call extraction skips some React component / aliased
import / direct-call forms. **name-based found nothing engine did not.**

Two integration bugs were found and are prerequisites, not engine faults:
1. Indexing the scan sub-dir (`web/src`) instead of the project root (`web/`,
   where `tsconfig.json` lives) drops every `~/…`/`@/…` path-alias import edge —
   silent false negatives. Fix: index from the nearest project marker.
2. `engine::impact` traverses *all* edge kinds; `Imports` edges made
   module/file nodes show up as "reachers" (54 vs the real 38). Fix: walk
   `Calls`/`AsyncCall` edges only, keep `Function`/`Method` nodes only.

Both fixes already live in the prototype (`aegis-cli/src/engine_reach.rs`,
feature `engine-reach`). They must survive into the consolidated design.

## The gap that blocks a single engine

The engine graph is **project-internal only**. It has no node for an external
symbol: `urql.useQuery` does not exist in the graph, so the engine cannot, on
its own, seed "which project functions call the vulnerable function". The
prototype borrows those seeds from `aegis-reach` (which parses imports and
resolves the dep-key). That borrow is exactly the second system we are trying
to remove.

To make the engine self-contained it must gain **external-import binding**:
given `import { useQuery } from "urql"` and a call `useQuery(...)`, record that
the call targets `urql.useQuery`.

## Target architecture — one graph, three queries

Add external-symbol representation to the engine IR and a per-language binding
pass, then derive all three reachability questions from the one graph.

### IR additions

- `NodeKind::External` — one node per referenced external `package[.symbol]`.
  `qualified_name = "urql.useQuery"`, `module_path = "urql"` (the dep-key),
  `is_exported = false`. A package imported for side effects only gets a
  bare `module_path = "urql"` node with no symbol.
- Edges into external nodes reuse the existing vocabulary:
  - `EdgeKind::Imports` file/module → external module node (import-level signal).
  - `EdgeKind::Calls` / `References` project symbol → external symbol node
    (used-symbol + call signal).
  - `confidence < 1.0` when the binding is ambiguous (re-export, namespace
    import, dynamic member access); `EdgeSource::Extracted` as today.

No new store or query primitives are needed — `neighbors`, `paths`, `impact`
already filter by `EdgeKind` and operate on any node.

### Public engine queries (self-contained, no aegis-reach seeds)

```
imports(graph, dep)            -> bool          // any Imports edge to `dep`   (import-level floor)
uses(graph, dep, symbol)       -> Vec<Node>     // project symbols with a Calls/References edge to dep.symbol
reaches(graph, dep, symbol)    -> Vec<Route>    // transitive Calls edges into the dep.symbol node
```

`reaches` seeds itself from the external `dep.symbol` node's incoming call
edges — no external seed list required.

### import-level stays, as the soundness floor

import-level is **not** deleted — it becomes a tier *inside* the engine,
computed from the engine's own `Imports` edges. When call-resolution cannot
prove reachability (dynamic dispatch, reflection, an unsupported call form),
the answer falls back to `imports(dep)` rather than asserting "unreachable".
This keeps the security-safe bias (never hard-suppress a live advisory on a
resolution gap) while remaining one system, one graph.

Verdict mapping for `downgrade_unused`:

| engine result | reachability verdict |
|---|---|
| `reaches` non-empty | Used (no downgrade) |
| `reaches` empty, `uses` non-empty | Used (symbol referenced; conservative) |
| `reaches`+`uses` empty, `imports` true | Unknown (floor — no downgrade) |
| `imports` false | Unused (downgrade) |

## Language coverage — the port list

Engine parity must reach aegis-reach's current breadth **before** aegis-reach is
deleted, or reachability for the lagging languages regresses to nothing.

| lang | engine today | aegis-reach today | port needed |
|---|---|---|---|
| JS/TS | resolved call edges | import + used-symbol + name-based | external binding pass |
| Python | resolved call edges | import + used-symbol + name-based | external binding pass |
| Go | tags only (no call edges) | import + used-symbol | call edges + external binding |
| PHP | none | import-level | full adapter (import binding) |
| Ruby | none | import-level | full adapter (import binding) |
| Rust/Gleam/Elixir | resolved call edges | — | (not an aegis ecosystem) |

The per-language `imports.scm` / used-symbol logic in `aegis-reach` is the
reference for the ported binding pass — same queries, emitting engine IR nodes
instead of `aegis-reach` structs.

## Migration phases (port → cut → delete)

Ordered to never regress. Each phase is independently shippable.

1. **External binding, TS + Python.** Add `NodeKind::External`, the binding
   pass, and `imports`/`uses`/`reaches` to the engine. Engine self-seeds for
   TS/Py. Re-run the `web/src` measurement with no aegis-reach seed borrow.
2. **Cut aegis over for TS/Py.** `engine_reach` drops the aegis-reach seed
   dependency; `ci`/`run`/`reach` use engine reachability for TS/Py. Retire the
   name-based transitive walk for those ecosystems. aegis-reach stays only for
   the languages not yet ported.
3. **Port Go call edges + Go/PHP/Ruby external binding** into the engine.
4. **Delete aegis-reach.** All reachability is engine. Keep the import-level
   floor as an in-engine tier.
5. **Wire into `downgrade_unused`.** Replace the import-level Used/Unused input
   to `downgrade_unused` with the four-way engine verdict above, so the risk
   gate itself benefits — the actual payoff, currently unmeasured because the
   prototype only touches the `reach` command.

Regression guard between phases: a golden test per language that asserts the
engine's reachable set ⊇ aegis-reach's on a fixture corpus, plus the
name-collision fixture (engine must exclude the phantom caller) and the
alias-import fixture (engine must include the aliased caller).

## Open questions

- **External symbol identity across dep versions.** `urql.useQuery` is
  version-agnostic in the graph; advisory affected-functions are version-scoped.
  Matching stays the advisory layer's job — the graph only answers "is this
  named symbol of this dep reached".
- **Where the code lives.** External binding is generic graph enrichment and
  belongs in ripple `lang`/`resolve`, not aegis. This grows ripple to serve a
  second consumer — acceptable, and the trigger to consider extracting the
  engine crates to their own repo (see the engine-facade split).
- **Proper precision/recall.** The numbers here are one repo, hand-verified.
  Before deleting aegis-reach, measure with `ripple eval --oracle lsp` (tsserver
  as ground truth) on a multi-repo corpus.
- **Soundness floor tuning.** Whether `uses`-but-not-`reaches` should be Used
  (conservative, current table) or Unknown depends on how much the call graph is
  trusted per language; revisit after the LSP-oracle numbers.
```
