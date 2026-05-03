# Command reference

Every subcommand `aegis --help` lists, with flags, examples, exit codes, and output format. Authoritative as of `v0.1.0`.

> **Legend**: 🌐 marks commands that **require a reachable Aegis API
> server** (set via `AEGIS_API_URL`). The hosted Aegis Cloud is not
> yet available and the platform repo is currently private — these
> commands are documented and shipped, but won't function for most
> users in `v0.1.x`. Everything else works locally with no backend.

Global flags (apply to every subcommand):

| Flag | Description |
|---|---|
| `-v`, `--verbose` | Enable debug-level structured logging to stderr (slog DEBUG). Same effect as `AEGIS_VERBOSE=1`. |
| `-h`, `--help` | Show help for the current command. |

Common output flags (where applicable):

| Flag | Description |
|---|---|
| `--json` | Emit a machine-readable JSON object to stdout. Suppresses human-readable output entirely. Stable schema — safe to parse. |
| `--quiet` | Print only the summary line (no per-finding detail). Mutually compatible with `--json`. |

Exit codes (uniform across the binary):

| Code | Meaning |
|---|---|
| `0` | Success / no findings ≥ threshold |
| `1` | Failure / findings ≥ threshold (block, prompt, etc. depending on `--fail-on`) |
| `2` | Couldn't reach a verdict — config error, network error, malformed input |

---

## 🌐 `aegis npm` / `aegis bun` / `aegis yarn` / `aegis pnpm`

**Requires Aegis API.** Drop-in wrappers around the underlying package manager. Install commands are intercepted, parsed, checked against the Aegis API, and either allowed (passed through to the real PM), prompted (interactive y/N), or blocked (non-zero exit, no PM call). All non-install commands pass straight through.

Without `AEGIS_API_URL` pointing at a reachable backend, install commands will return a connection error. Non-install passthrough (`aegis npm test`, `aegis bun run dev`) works regardless.

```sh
aegis npm install lodash@4.17.21      # checked
aegis npm test                        # passthrough
aegis bun add lodash@^4.17.0          # range → resolved via npm registry → checked
aegis yarn global add create-react-app
aegis pnpm add lodash
```

Install verbs recognized per PM:

| PM | Recognized | Notes |
|---|---|---|
| `npm` | `install`, `i`, `add`, plus typo aliases | `npm i` is the same as `npm install` |
| `bun` | `install`, `i`, `add`, `a` | Bun's `bun add foo` is the canonical install |
| `yarn` | `add`, `install`, `global add` | Yarn classic + berry; `yarn global add` is treated as install |
| `pnpm` | `add`, `install`, `i` | Workspace-aware via the underlying `pnpm` |

Non-registry installs are detected and passed through without an API check (we have no version to check against):

- `./vendor/foo` (local path)
- `git+https://…` (git URL)
- `link:../sibling`, `workspace:*` (workspace protocols)
- `portal:./pkg`, `patch:foo`, `exec:node`, `npm:alias@1.0.0` (yarn-berry protocols)

Interactive prompts use `/dev/tty` (so they work even when stdin is piped). In CI (`CI=true`, `GITHUB_ACTIONS`, etc.), prompts auto-block — never wait for input.

**Override**: pass `AEGIS_OVERRIDE=allow` and `AEGIS_OVERRIDE_REASON='<text>'` to bypass a block; both are written to the audit log. An empty reason is refused.

**Exit codes**: `0` if the install proceeds (allow / approved prompt / passthrough), `1` if anything was blocked.

---

## `aegis snapshot save`

Scan the project's lockfile and write `aegis.lock` at the project root. No network calls — pure lockfile parse + serialise. Fast, deterministic, safe to commit.

```sh
aegis snapshot save                   # auto-detect lockfile
```

Detection priority (first match wins): `bun.lock` → `package-lock.json` → `pnpm-lock.yaml` → `yarn.lock`.

**Output**: writes `./aegis.lock` (zstd-compressed JSON). Idempotent — repeated saves with no lockfile change produce a byte-identical file.

**Exit codes**: `0` on success, `2` if no lockfile is found.

---

## `aegis snapshot show`

Print the saved snapshot. By default only direct deps are shown (transitive deps are in the file but hidden from the table by default).

```sh
aegis snapshot show                   # direct only
aegis snapshot show --all             # include transitive
```

| Flag | Default | Description |
|---|---|---|
| `--all` | off | Include transitive dependencies in the rendered table. |

Output columns: ecosystem, name, version, capability summary (if enriched), risk score (if enriched), allowlist matches.

---

## `aegis snapshot diff [a.lock] [b.lock]`

Diff two snapshots. With no arguments, diffs the saved `aegis.lock` against the live lockfile. With one argument, diffs `aegis.lock` (saved) against the given path. With two, diffs the two files.

```sh
aegis snapshot diff                              # saved vs live
aegis snapshot diff baseline.lock                # baseline vs current saved
aegis snapshot diff main.lock pr-branch.lock     # explicit
```

Reports added, removed, upgraded, downgraded — and **drift** (a version-changed dep that grew new capabilities). Drift is the high-signal entry: `lodash 4.17.20 → 4.17.21` is normal, but if `4.17.21` newly contains `child-process` it's worth a look.

---

## `aegis snapshot enrich`

Run AST analysis + vulnerability lookup over every dep in the saved snapshot.

Two phases per run:

1. **AST scan** (parallel, 8-worker pool): fetch the tarball from the registry (cached under `~/.aegis/cache/sources/`), gunzip and untar in memory, walk the tree-sitter AST, and write capability fingerprints back into `aegis.lock`. Per-dep cost: 100ms–2s for first scan, ~5ms cache hit on subsequent runs.
2. **Vulnerability lookup** (single batch POST to OSV.dev): every dep is cross-referenced against the public OSV vulnerability database. Returned advisories are stamped onto each `Dependency` and persisted in `aegis.lock`. Advisory bodies are cached under `~/.aegis/cache/advisories/`. **No Aegis API required, no auth needed.**

```sh
aegis snapshot enrich
```

Disable the vulnerability lookup with `AEGIS_NO_VULN_LOOKUP=1` (AST scanning still runs). Point at a self-hosted OSV mirror with `AEGIS_OSV_URL=…`. Respects `AEGIS_CACHE_DIR`.

**Live progress UI**: when stderr is a TTY and `AEGIS_NO_LIVE` is unset, shows an 8-slot live status panel. Disabled in CI and when piped.

---

## 🌐 `aegis snapshot submit`

**Requires Aegis API.** Post analyzed deps as community reports to the Aegis API. Requires `AEGIS_API_KEY` — keys are issued via the Aegis web UI under `/admin?tab=api-keys`.

```sh
AEGIS_API_KEY=… aegis snapshot submit
```

Submits one report per (ecosystem, name, version) tuple in the saved snapshot. The API deduplicates server-side; resubmitting doesn't create duplicate records. Submit failures are logged but don't fail the command — best-effort.

---

## `aegis snapshot verify`

Check that `aegis.lock` is loadable and matches the current schema. Used by CI to catch corrupted or out-of-date snapshot files before they trip enrich.

```sh
aegis snapshot verify
```

**Exit codes**: `0` if loadable, `2` if missing / malformed / schema-incompatible.

---

## `aegis ci`

One-stop CI command. Runs the full audit pipeline: `snapshot save` → `snapshot enrich` (AST scan + OSV vulnerability lookup; skippable with `--no-enrich`) → score → exit.

Scoring folds two signals: AST capability findings (suspicious code patterns) and known vulnerabilities from OSV.dev (CVE / GHSA). Verdict is `max(astVerdict, advisoryVerdict)`:

| Source | Critical / High | Medium | Low | Info |
|---|---|---|---|---|
| Advisory severity | `block` | `prompt` | `review` | `safe` |
| AST score | (capability-weighted; see [docs/cli-risk-engine.md](cli-risk-engine.md)) | | | |

```sh
aegis ci --fail-on=block                      # default
aegis ci --fail-on=prompt                     # tighter
aegis ci --fail-on=review                     # tightest (warn-level fails)
aegis ci --json | jq '.findings[] | .name'    # machine-readable
aegis ci --baseline=baseline.lock             # drift mode
aegis ci --no-enrich                          # score on existing fingerprints only
```

| Flag | Default | Description |
|---|---|---|
| `--fail-on` | `block` | Threshold to fail on: `safe` (any finding) ◀ `review` ◀ `prompt` ◀ `block` (only blocks) |
| `--json` | off | Emit a JSON object to stdout. Suppresses human output. |
| `--quiet` | off | Print only the summary line. |
| `--no-enrich` | off | Skip the AST scan; score on existing fingerprints. Faster, thinner. |
| `--baseline <path>` | (none) | Drift mode: diff against this saved snapshot, only fail on *newly-introduced* findings. Doesn't touch your `aegis.lock`. |

The fingerprint cache (`~/.aegis/cache/fingerprints/`) persists across runs — a warm CI is fast. Only newly-added or version-changed deps incur AST scan cost.

**Exit codes**: `0` if no findings ≥ `--fail-on`, `1` if any, `2` on config / network errors.

---

## 🌐 `aegis recheck`

**Requires Aegis API.** Re-run the install gate against the current lockfile. Useful after an incident DB update — packages allowed at install time may now be flagged.

```sh
aegis recheck                       # direct deps only
aegis recheck --all                 # include transitive
aegis recheck --json
```

| Flag | Default | Description |
|---|---|---|
| `--all` | off | Include transitive deps (default: only direct, matching what the user explicitly installed) |
| `--fail-on-prompt` | off | Exit non-zero on prompt verdicts (default: only `block` fails) |
| `--json` | off | Emit JSON to stdout |
| `--quiet` | off | Summary line only |

---

## `aegis analyze <pkg-spec>`

Fetch and AST-scan a single package — fallback when the incident DB has no record. Spec is `[ecosystem/]name@version`. Default ecosystem is `npm`.

```sh
aegis analyze lodash@4.17.21
aegis analyze @solana/web3.js@1.95.4
aegis analyze npm/event-stream@3.3.6
aegis analyze --evidence ua-parser-js@0.7.29     # show file:line snippets
aegis analyze --json lodash@4.17.21
```

| Flag | Description |
|---|---|
| `--evidence` | Include file:line snippets for each detected capability |
| `--json` | Emit JSON to stdout (suppresses human output) |

---

## `aegis explain <pkg-spec>`

Explain why a dep was flagged. Looks up the dep in the saved `aegis.lock` first (no network); falls back to a fresh fetch + AST scan if not present.

```sh
aegis explain lodash@4.17.21
aegis explain --snapshot-only ua-parser-js@0.7.29   # error if not in lock
aegis explain --json lodash@4.17.21
```

| Flag | Description |
|---|---|
| `--snapshot-only` | Only consult saved `aegis.lock`; never fetch + rescan. Errors if the dep isn't in the snapshot. |
| `--json` | Emit JSON to stdout |

Each capability is rendered with a one-line description; allowlist suppression reasons are surfaced; evidence (file:line) is shown when the scan was fresh.

---

## `aegis allowlist`

Manage capability suppressions for specific packages. Layered: builtin → user (`~/.aegis/allowlist.yaml`) → project (`./.aegis-allowlist.yaml`). Specific names beat wildcards; within each layer input order decides ties.

### `aegis allowlist list`

```sh
aegis allowlist list                              # all rules from all sources
aegis allowlist list --source=builtin             # filter by source
```

| Flag | Description |
|---|---|
| `--source` | Filter by source: `builtin` / `user` / `project` |

### `aegis allowlist add <name>`

```sh
aegis allowlist add lodash \
    --capability=dynamic-eval \
    --version='^4' \
    --reason='_.template uses Function() to compile templates'
```

| Flag | Default | Description |
|---|---|---|
| `--ecosystem` | `npm` | `npm` / `pypi` / `crates` / `go` / `maven` |
| `--capability` | (any) | Capability code to suppress; omit for "any capability" |
| `--version` | (any) | Semver range to scope the rule to; omit for "any version" |
| `--reason` | (none) | Explanation; **strongly recommended**. The allowlist is an audit trail — empty reasons are worse than no rule. |
| `--scope` | `user` | `user` (`~/.aegis/allowlist.yaml`) or `project` (`./.aegis-allowlist.yaml`) |

### `aegis allowlist remove <name>`

```sh
aegis allowlist remove lodash --capability=dynamic-eval
aegis allowlist remove lodash --scope=project
```

| Flag | Default | Description |
|---|---|---|
| `--ecosystem` | `npm` | Required to disambiguate cross-ecosystem rules |
| `--capability` | (all) | Narrow removal to a single capability; omit to remove all rules for the name |
| `--scope` | `user` | `user` or `project` |

### `aegis allowlist test <ecosystem>/<name>@<version>`

Show which allowlist rules would suppress capabilities for a given (ecosystem, name, version) tuple. Doesn't fetch or scan — pure rule evaluation.

```sh
aegis allowlist test npm/lodash@4.17.21
```

### `aegis allowlist verify`

Validate user and project allowlist YAML files. Strict decoding: unknown keys, unknown capabilities, and unsupported schema versions all error out.

```sh
aegis allowlist verify
```

### 🌐 `aegis allowlist sync`

**Requires Aegis API.** Fetch the org-level allowlist overlay from the Aegis API and cache it locally at `~/.aegis/cache/org-allowlist.yaml`. Requires `AEGIS_API_KEY`.

```sh
AEGIS_API_KEY=… aegis allowlist sync
aegis allowlist sync --force                     # ignore cache freshness
```

| Flag | Description |
|---|---|
| `--force` | Bypass the cache freshness check and re-fetch unconditionally |

---

## `aegis cache`

### `aegis cache list`

List cached decisions (the `~/.aegis/cache/decisions.json` map of `(eco, name, version) → verdict`). Useful for "why was this allowed?" debugging.

```sh
aegis cache list
```

### `aegis cache clear`

Delete the local decision cache. Pass `--fingerprints` to also delete the AST fingerprint cache (`~/.aegis/cache/fingerprints/`); pass `--all` for both plus the package source cache (`~/.aegis/cache/sources/`).

```sh
aegis cache clear                                # decisions only
aegis cache clear --fingerprints                 # + fingerprints
aegis cache clear --all                          # everything
```

| Flag | Description |
|---|---|
| `--fingerprints` | Also delete AST fingerprint cache |
| `--all` | Delete decisions + fingerprints + tarball sources |

---

## `aegis audit tail`

Show the most recent entries from the local audit log (`~/.aegis/audit.jsonl`). One line per outcome (allow / block / override / ...) with timestamp, package, decision, and reason.

```sh
aegis audit tail                  # last 20
aegis audit tail -n 100           # last 100
aegis audit tail -n 0             # all
```

| Flag | Default | Description |
|---|---|---|
| `-n`, `--n` | `20` | Show the last N entries; `0` means all |

---

## `aegis hook`

### `aegis hook install`

Install the aegis pre-commit hook in the current git project. The hook runs `aegis ci --fail-on=block` before each commit.

```sh
aegis hook install
```

Writes `.git/hooks/pre-commit`. Refuses to overwrite an existing hook unless you remove it first.

### `aegis hook uninstall`

Remove the aegis pre-commit hook. Idempotent.

```sh
aegis hook uninstall
```

---

## `aegis doctor`

Sanity-check the local environment: API reachability, cache permissions, allowlist parse, free disk. Run this first when something seems off.

```sh
aegis doctor
aegis doctor --json
```

| Flag | Description |
|---|---|
| `--json` | Emit machine-readable JSON |

Checks performed:

1. **API reachability** — `HEAD AEGIS_API_URL/check`; reports the HTTP status (any code = reachable)
2. **Cache directory** — `~/.aegis/cache/` is writeable
3. **Allowlist parse** — user + project YAML files load without errors
4. **Disk space** — at least 100MB free on the cache filesystem
5. **Build info** — Go version, OS/arch, build tags

**Exit codes**: `0` if everything green, `1` if any check failed, `2` if doctor itself crashed.

---

## `aegis admin gen-key`

Generate a fresh submit API key plus a sha256 hex digest for installing it server-side. Used when bootstrapping a new operator account against a self-hosted Aegis API.

```sh
aegis admin gen-key
```

Output: two lines — the key (give to the user) and the sha256 hex (insert into the `submit_api_keys` table). The key itself is never stored server-side.

---

## `aegis version`

Print the binary version, commit hash, and build date.

```sh
$ aegis version
aegis 0.1.0 (commit 6c5844916d8831d841edb2fec1e9dbd615519e9c, built 2026-05-03T04:46:04Z)
```

All three values are stamped at build time via `-ldflags=-X`. A binary built locally with plain `go build` (no ldflags) reports `0.1.0-demo (commit none, built unknown)`.
