---
title: Snapshot format
description: The aegis.lock file format, snapshot subcommand semantics, lockfile parsers, and CI patterns.
sidebar:
  order: 3
---


> Audience: anyone using or extending the snapshot mechanism.

A snapshot freezes a project's full dependency set at a point in
time. Diffs against the saved snapshot let Aegis reason about what
*changed* — the second axis of detection (the first is the historical
incident DB).

## When you'd use it

| Question | Command |
|---|---|
| What did my project depend on at this commit? | `aegis snapshot show` |
| What changed since I last saved? | `aegis snapshot diff` |
| What changed between two saved files? | `aegis snapshot diff a.lock b.lock` |
| Did anything dangerous show up in the new versions? | `aegis snapshot enrich && aegis snapshot diff` |

## File format

The snapshot lives at `<project>/aegis.lock`. It's **zstd-compressed
JSON** — one file, no separate index. Schema version is in the JSON
itself.

Sample (decompressed):

```jsonc
{
  "schema_version": 1,
  "created_at": "2026-04-29T15:13:30Z",
  "aegis_version": "0.1.0-demo",
  "project": "web",
  "deps": [
    {
      "ecosystem": "npm",
      "name": "lodash",
      "version": "4.17.21",
      "integrity": "sha512-v2kDEe...",
      "direct": true,
      "fp": {
        "analyzed": true,
        "capabilities": ["shell-spawn", "dynamic-eval"],
        "source_size_bytes": 1319622
      },
      "reach": "used",        // "used" | "unused" — populated by snapshot enrich
      "symbols": ["merge"]    // bound names in project source that call this dep
    },
    {
      "ecosystem": "npm",
      "name": "axios",
      "version": "1.6.0",
      "direct": true,
      "fp": { "analyzed": true, "capabilities": ["net-egress"] },
      "reach": "unused"       // in lockfile, not imported by any project source file
    }
  ]
}
```

### Why JSON + zstd (and not Protobuf)

- The web side will eventually fetch this file directly to render a
  graph view; JSON is a free pass through the browser.
- `jq` and similar tooling work without code generation.
- LLMs can ingest the file; Protobuf requires schemas they don't
  have.
- zstd brings size down: 906 deps in this repo's `web/` ⇒ 9 KB.

### Forward compatibility

- New optional fields on `Dependency` or `fp` are added with
  `omitempty`; older readers that have `KnownFields(false)` ignore
  them. Today readers don't touch unknown fields except in YAML
  allowlist files.
- Breaking changes bump `schema_version`. Loader rejects unknown
  versions with a clear error.

## Subcommands

```
aegis snapshot save             # write aegis.lock from current lockfile
aegis snapshot show [--all]     # direct deps by default; --all for transitives
aegis snapshot diff             # saved vs live (re-scan lockfile)
aegis snapshot diff a b         # explicit two-file diff
aegis snapshot enrich           # run AST scanner over deps; write fingerprints back
aegis snapshot verify           # parseable + schema_version matches
```

### `save` — fast, no network

`save` only reads the project's lockfile and writes `aegis.lock`.
No network. No tarball downloads. No AST scanning. Suitable for
running in pre-commit hooks.

Detection priority (`infra/locksnap/scanner.go`):
```
pnpm-lock.yaml > yarn.lock > bun.lock > package-lock.json
```

`package.json` is consulted to mark `direct: true` on the matching
entries; transitives are stored with `direct: false`.

### `show` — reading the file

By default lists only direct deps (the `package.json` set). Pass
`--all` for transitives. The output is tab-aligned for terminal
readability; for machine consumption, decompress the file directly:

```bash
zstd -dc aegis.lock | jq '.deps[] | select(.direct) | .name'
```

### `diff` — what changed

Two modes:

1. **Saved vs live** (no args): loads `aegis.lock`, re-scans the
   project lockfile, and reports `Added / Removed / Upgraded`. For
   unchanged versions, the saved snapshot's fingerprint is *carried
   forward* into the live re-scan — so `Risk` and `Drift` can be
   computed without re-enriching.

2. **Two explicit files** (`diff a.lock b.lock`): loads both as-is.
   Useful for CI: snapshot from `main` vs the PR branch.

Each diff entry gets a `Verdict` (`safe / review / prompt / block`)
when fingerprints are present. Without fingerprints, the diff is
delta-only.

### `enrich` — populate fingerprints

`enrich` is the expensive one: it iterates all deps in
`aegis.lock`, fetches each tarball from the registry (cached at
`~/.aegis/cache/sources/...`), runs the AST scanner, writes the
resulting fingerprint into the snapshot.

Idempotent — re-running only enriches deps without an existing
analyzed fingerprint. Errors (network down, 404 etc.) are reported
per-dep and the operation continues; no partial writes.

`aegis snapshot enrich` requires a build with the AST scanner
included (`make build-release`, not `build-core`). With the
`nojsscan` build tag set, it reports "risk engine not configured"
and exits.

See `docs/cli-risk-engine.md` for what the fingerprints contain.

### `verify` — schema sanity

Loads the file and checks:
- It exists
- It decompresses
- JSON parses
- `schema_version` is supported by this binary

Used by CI to fail-fast when an `aegis.lock` rolls over a binary
boundary.

## Lockfile parsers

| Lockfile | Parser | Notes |
|---|---|---|
| `package-lock.json` | `lockfile_npm.go` | npm v1 / v2 / v3 (flat `packages` map for v2+, recursive `dependencies` tree for v1) |
| `pnpm-lock.yaml` | `lockfile_pnpm.go` | Hand-parsed (no YAML lib). Reads only the `packages:` section. Handles modern `name@version` and legacy `name/version` forms |
| `yarn.lock` | `lockfile_yarn.go` | Classic v1 + Berry v2/3/4 share the same block format |
| `bun.lock` | `lockfile_bun.go` | Bun's text format (JSONC). Strips `//` and `/* */` comments + trailing commas |

Each parser:
- Returns `[]domain.Dependency` deduplicated by `(name, version)`
- Marks `Direct=true` when the dep appears in `package.json`
  (`dependencies` / `devDependencies` / `peerDependencies` /
  `optionalDependencies`)
- Errors only on malformed input; missing files are silent (not
  finding a lockfile is a normal "no project here" condition)

Adding pip / cargo / gem etc. is one new lockfile parser plus the
detection priority in `scanner.go`. See `docs/cli-architecture.md`
§ Adding a new ecosystem.

## Reachability

After `snapshot enrich`, each dep carries a `reach` field that records whether project source actually imports it:

| Value | Meaning |
|---|---|
| `"used"` | At least one import in your source references this dep. |
| `"unused"` | Source walk ran; no import found. Likely a transitive or an outdated direct dep. |
| omitted | Unknown — enrich hasn't run the import scan yet, or the language isn't supported for this ecosystem. Treated as `used` (conservative). |

The companion `symbols` field lists the specific bound names your code calls from the dep (e.g. `["merge"]` when only `lodash.merge` is used). This enables future per-symbol CVE suppression.

**In the UI:**

```sh
aegis snapshot show --all              # [unused] annotation in CAPS column
aegis snapshot show --all --used-only  # hide unused rows; footer shows count
```

**Risk downgrade (opt-in):**

```sh
AEGIS_UNUSED_SUPPRESS=1 aegis ci --fail-on=block
```

Install-phase capabilities are never downgraded regardless of reachability.

**Languages with symbol tracking:** JavaScript/TypeScript, Python, Go, Java, PHP.
Rust, Ruby, C# populate `reach` but leave `symbols` empty — their import forms don't bind specific local names.

## Fingerprint shape

```go
type Fingerprint struct {
    Analyzed        bool             // false until enrich runs
    Capabilities    CapabilitySet    // set of detected behaviors
    Hooks           []InstallHook    // install-time scripts (npm postinstall, pip setup.py, ...)
    EnvReads        []string         // process.env names referenced
    SourceSizeBytes int              // total bytes scanned (drift signal)
    ASTSummaryHash  string           // future: stable hash of the analysis output
}
```

Empty `Fingerprint{}` (Analyzed=false) is the "we haven't looked
yet" state. A populated fingerprint with empty `Capabilities` and
no `Hooks` means "we looked and the package is clean".

## Tarball cache

`infra/jspkgsource/cache.go` stores extracted sources at:

```
~/.aegis/cache/sources/<eco>/<name>/<version>/
    package.json
    index.js
    src/...
    .ok                    ← sentinel — write last; absence = incomplete
```

Cache hit is checked before any network call. The sentinel pattern
keeps a crash mid-extract from leaving a partially-populated dir
that looks valid.

Path-traversal protection: tarball entries with `..` segments are
silently dropped; we never write outside the per-package cache dir.
Tested in `infra/jspkgsource/fetcher_edge_test.go`.

## Performance

| Operation | Typical cost |
|---|---|
| `save` (906 deps) | ~50 ms (reads bun.lock + package.json) |
| `show` | a few ms |
| `diff` (no fingerprint deltas) | a few ms |
| `enrich` (per dep, cached) | ~0 (cache hit, no I/O) |
| `enrich` (per dep, cold) | 100-1000 ms (tarball download + AST) |
| `verify` | < 50 ms |

A first-time `enrich` over 906 deps is dominated by parallel-able
network I/O to the npm registry. The AST scanner itself runs at
~5 ms per JS file; the largest published package we've seen
(big-bundle-style) runs in 30 ms once cached.

## CI integration patterns

```bash
# Pre-commit hook: keep the snapshot fresh
aegis snapshot save

# CI: fail the PR if anything new is risky
aegis snapshot save                # at PR HEAD
git checkout main -- aegis.lock    # base file
aegis snapshot diff main.lock aegis.lock || exit 1
```

The exit code from `aegis snapshot diff` is non-zero iff any entry
hit `verdict=block` (or `prompt` in CI mode — same as the install
gate's `prompt → block` promotion when `CI=true`).

## Web graph view (future)

`aegis.lock` is shaped to be readable directly from the web side:

```js
// browser
const res = await fetch('/api/projects/${id}/snapshot');
const buf = await res.arrayBuffer();
const json = JSON.parse(new TextDecoder().decode(zstd.decompress(buf)));
// → cytoscape.js → graph view, color by Capability count
```

The Aegis backend doesn't yet have an endpoint for this — currently
`aegis.lock` is a project-local file. Tracked as future work; the
file format is intentionally browser-friendly so we don't need a
schema migration when it lands.
