# `aegis` CLI risk engine

> Audience: anyone tuning thresholds, adding capabilities, or curating
> the bundled allowlist.

The risk engine is the second axis of detection (the first is the
historical incident DB). It evaluates package source statically and
turns the findings into a Verdict the user can act on.

## Two questions, two scores

```
RiskScore(fp)               "how dangerous is this version on its own?"
DriftScore(prev_fp, next_fp) "how much did the danger profile change?"
```

Both produce a `RiskAssessment{Score, []RiskFlag}`. The combined
Verdict is `max(Risk.Score, Drift.Score)` mapped through three
thresholds.

### Why max, not sum

If a benign-but-flagged package upgrades cleanly (e.g. webpack 5.0 →
5.1, both have shell-spawn for legitimate workers, drift = 0), we
want to report Risk only and not double-count. Conversely, a clean
package that suddenly grows install-hook + shell-spawn shows up via
Drift even when `next` itself has Risk below threshold.

## Capability enum

`Capability` is a language-neutral observable behavior. The same enum
covers JS, Python, Ruby, Rust, etc. — per-language tree-sitter
scanners map their syntax onto the same Capabilities.

| Capability | JS example | Python example | Ruby example |
|---|---|---|---|
| `CapShellSpawn` | `child_process.exec` | `subprocess.run` | `Kernel#system` |
| `CapDynamicEval` | `eval`, `new Function` | `eval`, `exec`, `compile` | `eval`, `instance_eval` |
| `CapBase64Decode` | `atob`, `Buffer.from(_,'base64')` | `base64.b64decode` | `Base64.decode64` |
| `CapNetEgress` | `require('http')`, `fetch` | `import socket`, `requests` | `Net::HTTP` |
| `CapEnvRead` | `process.env.X` | `os.environ['X']` | `ENV['X']` |
| `CapFSWriteOutsideRoot` | `fs.writeFile` | `open(_, 'w')` | `File.write` |
| `CapRawIPLiteral` | `"https://1.2.3.4/..."` | (same — string match) | (same) |
| `CapInstallHookExec` | `scripts.postinstall` | `setup.py` | `extconf.rb` |

Adding a new Capability is one constant in `domain/capability.go`,
one weight in `domain/risk.go`, and one query line in each
language's `queries.scm`.

## RiskScore weights

`domain/risk.go` declares per-Capability constants:

```go
WeightInstallHook    = 30   // postinstall / setup.py / build.rs
WeightShellSpawn     = 20
WeightDynamicEval    = 25
WeightBase64Decode   = 20   // obfuscation primitive
WeightNetEgress      = 10   // many libs do this legitimately
WeightEnvCredRead    = 25   // only when names look credential-shaped
WeightFSWrite        = 15
WeightRawIPLiteral   = 15
WeightSizeAnomaly    = 5    // drift only
WeightHookContent    = 30   // drift only — hook script body changed
WeightCapabilityAdd  = 15   // drift only — per new capability
```

### Special case — env-var credential heuristic

`CapEnvRead` alone is benign (`process.env.NODE_ENV` is everywhere).
The risk engine only flags it when the names look credential-shaped.
The list is in `credentialEnvVarRoots` (case-insensitive prefix
match): `AWS_`, `GITHUB_TOKEN`, `NPM_TOKEN`, `DATABASE_URL`,
`PRIVATE_KEY`, `STRIPE_`, `TWILIO_`, etc.

A package reading `NODE_ENV` and `DEBUG` produces no flag. A package
reading `AWS_ACCESS_KEY_ID` produces an `env-cred-read` flag at
weight 25.

## DriftScore signals

```go
hookDiff(prev, next) → install-hook-added (+30) | install-hook-changed (+30)
caps_added(prev, next) → capability-added × N  (+15 each)
sizeDeltaSignal(prev, next) → size-anomaly  (+5)
```

`install-hook-changed` requires both versions to have a non-empty
SHA-256 of the hook body. Empty hash on either side (e.g.
lockfile-only metadata) is a "we don't know" — no flag.

`size-anomaly` fires only on >2× growth or <½ shrinkage. A 30%
diff is treated as a normal patch release.

## Verdict thresholds

```go
VerdictThresholdReview = 21
VerdictThresholdPrompt = 61
VerdictThresholdBlock  = 100
```

| Combined score | Verdict | UX |
|---|---|---|
| 0–20 | `safe` | ✓ green, no flag breakdown shown |
| 21–60 | `review` | ⚠ yellow, breakdown shown, install proceeds |
| 61–99 | `prompt` | ⚠ red, breakdown shown, asks user (or auto-blocks in CI) |
| 100+ | `block` | ✗ red, breakdown shown, refuses without override |

These are tunable. Bumping `VerdictThresholdBlock` to 80 makes the
gate aggressive; raising it to 150 makes it lax. We chose the
current defaults to make a typical "compromised version" pattern
(install-hook + shell-spawn + base64 + net-egress = 80) sit at
`prompt` rather than `block` — block requires either a ≥100 single-
axis score, or risk + drift together pushing above the threshold.

## Allowlist suppression

`RiskAssessment.ApplyAllowlist(eco, name, version, set)` is a pure
post-process that:

1. Walks each flag in the assessment
2. Maps the flag's `Code` to a `Capability` (string → enum table)
3. Probes `set.Suppresses(eco, name, version, capability)`
4. If matched, marks the flag `Suppressed=true`, sets `SuppressBy`
   to the rule's Reason, and **subtracts the weight from Score**

The original assessment is unchanged — `ApplyAllowlist` returns a
copy. The Verdict that follows uses the post-suppression Score.

### Code → Capability map

| `RiskFlag.Code` | Capability matched |
|---|---|
| `install-hook` | `CapInstallHookExec` |
| `install-hook-added` | `CapInstallHookExec` |
| `install-hook-changed` | `CapInstallHookExec` |
| `shell-spawn` | `CapShellSpawn` |
| `dynamic-eval` | `CapDynamicEval` |
| `base64-decode` | `CapBase64Decode` |
| `net-egress` | `CapNetEgress` |
| `env-cred-read` | `CapEnvRead` |
| `fs-write-outside-root` | `CapFSWriteOutsideRoot` |
| `raw-ip-literal` | `CapRawIPLiteral` |
| `capability-added` | parsed from `Detail` (drift-only flag) |
| `size-anomaly` | (not allowlist-able) |

`size-anomaly` is intentionally not allowlist-able: it's a structural
signal (source got dramatically bigger or smaller), not a Capability,
and silencing it would obscure the faker@6.6.6 sabotage pattern.

## Tree-sitter scanner

`infra/astscan/jsscan` uses `github.com/tree-sitter/go-tree-sitter`
v0.25 with the `tree-sitter-javascript` grammar. Detection patterns
are S-expression queries embedded from `queries.scm`.

Each query labels a capture as `@cap.<capability-name>`; the scanner
maps capture names back to `domain.Capability`. Adding detection for
a new Capability is:

1. Add the constant to `domain/capability.go` (and `String()`).
2. Add a weight to `domain/risk.go` (`Weight<Name>`).
3. Add the per-language query patterns under `infra/astscan/<lang>scan/queries.scm`.
4. Add a positive + negative test case to `<lang>scan/scanner_test.go`.

Per-file dispatch (`isAnalyzable`) skips:
- `*.min.js` (minified, false-positive prone)
- `*.d.ts` (type-only, no runtime)
- `__pycache__/`, `tests/`, `test_*.py` (when pyscan lands)

## False-positive management

The bundled allowlist (`domain.BuiltinAllowRules`) contains ~20
hand-curated entries for well-known packages whose flagged
capabilities are part of their legitimate behavior:

- Template compilers (`lodash`, `underscore`, `handlebars`, `ejs`) for
  `dynamic-eval` (they use `Function()` for runtime template
  compilation).
- Build tools (`webpack`, `@babel/core`, `esbuild`, `rollup`, `vite`,
  `parcel`, `nodemon`) for `shell-spawn` (worker processes).
- HTTP clients (`node-fetch`, `axios`, `got`, `undici`) for
  `net-egress` (the package's purpose).
- Native build (`fsevents`, `node-sass`, `sharp`, `better-sqlite3`,
  `bcrypt`) for `install-hook` (compile/download platform binary).

**Curation bar**: every entry weakens the gate. New entries should
cite the specific code path that triggers the capability. Default
to *no* version constraint (`VersionRange="*"`) but consider
anchoring to a major (`^4`) for packages with a known-sabotage
incident at a higher version.

See [README.md § Allowlist](../README.md#allowlist) for the user-facing CLI.

## Tuning workflow

When false positives or negatives surface:

1. Re-run `aegis snapshot enrich` to regenerate fingerprints with
   any updated grammar/queries.
2. `aegis snapshot diff` to see the verdict line-by-line with flag
   breakdown.
3. For a specific package, `aegis allowlist test
   npm/<name>@<version>` shows which rules already apply.
4. To suppress: `aegis allowlist add <name> --capability=<cap>
   --reason='<why>' --scope=project`.
5. To re-flag (if a builtin is too aggressive for your context):
   currently no deny rules — file an issue and we'll consider
   either narrowing the builtin or adding the deny mechanism.
6. To change a threshold: edit constants in `domain/risk.go` and
   re-run tests. The whole risk decision table is exhaustively
   tested in `domain/risk_test.go` and `domain/risk_edge_test.go`.

## Testing

The risk engine is the most-tested layer in the CLI:

- `domain/risk_test.go` — RiskScore + DriftScore × ~20 cases
- `domain/risk_edge_test.go` — boundary buckets, env heuristic,
  size deltas, drift removed, etc.
- `domain/allowlist_apply_test.go` — suppression with partial
  matches, drift `capability-added` Detail parsing, double-suppress
  no-op
- `domain/allowlist_match_test.go` — `MatchAll` enumeration
  including "any capability" collapse
- `domain/allowlist_bench_test.go` — index lookup benchmarks
- `infra/astscan/jsscan/scanner_test.go` — every Capability has
  positive + negative cases

Pure-function design means most tests are 5-line table entries.
