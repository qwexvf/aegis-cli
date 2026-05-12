---
title: Configuration
description: Environment variables, config file paths, allowlist YAML schema, CI auto-detection, and build tags.
sidebar:
  order: 2
---


How `aegis` is configured: environment variables, config file paths, and CI auto-detection. Authoritative as of `v0.1.0`.

`aegis` is configured through **three layers** (CLI flags take precedence):

1. **`aegis.yml`** (or `.aegis.yml`) — project-level config at the repository root. Sets default flag values for `aegis ci` and `aegis actions scan`. Optional; missing file is silently ignored.
2. **Environment variables** — override built-in defaults globally.
3. **CLI flags** — highest precedence; always override config file and env vars.

This makes the binary safe to drop into shared CI runners without surprise state.

> 🌐 marks variables that are **only meaningful when an Aegis API
> server is reachable**. The hosted Aegis Cloud is not yet available
> in `v0.1.x`, so these can be left unset for local-only use.

## Environment variables

### Core

| Variable | Default | Used by | Purpose |
|---|---|---|---|
| 🌐 `AEGIS_API_URL` | `http://localhost:4000` | API-dependent commands (install gate, recheck, submit, sync) | Base URL of the Aegis decision API. Set this to your self-hosted Aegis instance once the platform is deployed. Local-only commands (snapshot, analyze, ci, allowlist, audit, hook, doctor) ignore it. |
| 🌐 `AEGIS_API_KEY` | (empty) | `snapshot submit`, `allowlist sync` | Submit/sync API key. Generate one server-side via `/admin?tab=api-keys` in the Aegis web UI. The CLI sends it as `X-API-Key`. Empty key → 401 from the API; the CLI surfaces the error verbatim. |
| `AEGIS_VERBOSE` | (unset) | Every subcommand | When set to anything non-empty, flips slog level to DEBUG. Equivalent to passing `--verbose` / `-v` on every command. |

### Override (audited bypass) 🌐

These two only fire when the install gate is producing a block, which itself requires the Aegis API. Local-only commands don't use them.

| Variable | Default | Used by | Purpose |
|---|---|---|---|
| 🌐 `AEGIS_OVERRIDE` | (unset) | Install gate | Set to `allow` to bypass a block decision. **Requires** `AEGIS_OVERRIDE_REASON` — the gate refuses to honor an override without a reason. |
| 🌐 `AEGIS_OVERRIDE_REASON` | (unset) | Install gate | Free-text reason written verbatim to the audit log. Empty / whitespace-only is refused. Examples: `'hotfix-1234'`, `'incident-response: rolling back to known-good'`, `'CVE patch verified upstream'`. |

The override is the operator's "I know what I'm doing" escape hatch. Both env vars **must be set** in the same invocation; the audit entry records the reason permanently. There is no global "always override" mode by design.

### Caching

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_CACHE_DIR` | `~/.aegis/cache` | Override the cache root. Useful in CI: `AEGIS_CACHE_DIR=$CI_PROJECT_DIR/.aegis-cache` makes the cache part of the cacheable directory set. |
| `AEGIS_CACHE_TTL` | (cake decides) | Override the decision-cache freshness window. Format: Go duration (`24h`, `7d`, `1h30m`). Cached decisions older than this are re-fetched. |
| `AEGIS_CONFIG_DIR` | `~/.aegis` | Where the user-level allowlist (`allowlist.yaml`), audit log, and reporter ID live. Override to keep multiple aegis profiles (e.g. work vs personal). |
| `AEGIS_AUDIT_DIR` | (= `AEGIS_CONFIG_DIR`) | Override only the audit log location. Useful for sending to a syslog-style central path while keeping config local. |

### Vulnerability lookup

`aegis snapshot enrich` / `aegis ci` / `aegis analyze` cross-reference every dep against a vulnerability feed. The default backend is **OSV.dev** (Google) — public, free, no auth required. When `AEGIS_API_KEY` is set, the **Aegis-managed feed** (curated OSV + GHSA + npm advisories) is preferred and OSV is used as a fallback on transient errors. Both backends share the same `usecase.VulnLookup` interface.

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_OSV_URL` | `https://api.osv.dev` | Override the OSV endpoint. Use this to point at a self-hosted OSV mirror or a corporate proxy. The wire shape (`/v1/querybatch`, `/v1/vulns/{id}`) must match upstream. |
| `AEGIS_VULN_SOURCE` | (unset) | Pin the lookup source explicitly. `osv` = OSV only (no Aegis call even when a key is set). `aegis` = Aegis only (no OSV fallback). `none` = disable the lookup entirely (same as `AEGIS_NO_VULN_LOOKUP=1`). When unset: prefer Aegis if `AEGIS_API_KEY` is set, OSV otherwise. |
| `AEGIS_NO_VULN_LOOKUP` | (unset) | When set to anything non-empty, disables the lookup entirely. The snapshot enrich step still runs the AST scanner; only the advisory column is empty. Useful for fully-offline runs or air-gapped CI. |

### Malware heuristics

`aegis snapshot enrich` and `aegis analyze` run a chain of behavior-based malware detectors over every package source after the AST scanner finishes. The heuristics are language-agnostic where possible and catch zero-day patterns OSV doesn't know about yet:

- **Suspicious install hooks** — `curl|sh`, inline `node -e`, base64-piped-to-shell, Pastebin/Discord/ngrok hosts. Covers npm `package.json` scripts and crates.io `build.rs`.
- **Obfuscated payload** — `eval(atob(...))` (JS), `eval(Net::HTTP.get(...))` (Ruby), `exec(urlopen(...).read())` / `exec(base64.b64decode(...))` (Python).
- **Suspicious URL targets** — Pastebin, Discord webhooks, Telegram bots, IP grabbers, IDN homoglyphs. Runs across `.js` / `.ts` / `.py` / `.rb` / `.rs` / `.go` source.
- **Binary droppers** — stray `.exe`/`.dll`/`.so`/`.scpt`/`.ps1` in a package tarball. Per-ecosystem carve-outs recognise legitimate native shapes (PyPI `<pkg>/.cpython-*-*.so`, `<pkg>/.libs/`, `.abi3.so`, `.pyd`).
- **Typosquat names** — Levenshtein ≤ 2 from a curated top-list per ecosystem (npm, PyPI, crates.io). One-line addition per new ecosystem via `top_<eco>_packages.txt`.
- **Maintainer hijack** — fresh release after a long quiet period from a low-download package, the canonical event-stream / ctx / rest-client shape.
- **Maintainer transfer** — current version's `_npmUser` differs from the previous version's. Catches account-handoff attacks where the package is republished by a new (potentially attacker) maintainer.
- **Tarball / source drift** *(opt-in)* — fetches the GitHub repo tree for the tag matching the published version and diffs against the tarball file list. Flags scripts or code present in the tarball but absent from the source tag (the canonical "post-publish payload injection" shape).

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_NO_HEURISTICS` | (unset) | When set to anything non-empty, disables the malware heuristic pass. Useful when A/B testing heuristic vs AST-only scoring or to silence false positives during initial rollout. |
| `AEGIS_DRIFT` | (unset) | When set to anything non-empty, enables the tarball-source-drift detector. Requires network access to GitHub; respects `GITHUB_TOKEN` for the 5000/hr authenticated rate limit (60/hr without). Direct deps only by default — see `AEGIS_DRIFT_ALL`. |
| `AEGIS_DRIFT_ALL` | (unset) | Run the drift detector on transitive deps too, not just direct ones. Cold-scan slow on large dep graphs; use when investigating a specific incident. |

### Reachability

`aegis snapshot enrich` walks your project's source files and marks each dep as `used`, `unused`, or `unknown` depending on whether any import statement references it.

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_UNUSED_SUPPRESS` | (unset) | When set to anything non-empty, non-install capability findings on `unused` deps are suppressed from the risk score. Install-phase capabilities (`postinstall`, `install-hook-suspicious`) are **never** suppressed — they execute regardless of imports. Enable after reviewing `[unused]` markers in `snapshot show`. |
| `AEGIS_TARBALL_ALLOWED_HOSTS` | (unset) | Comma-separated list of additional hostnames the npm tarball fetcher may download from, beyond the configured registry's own hostname. Required when a private registry serves tarballs from a separate CDN. Example: `cdn.mycompany.com,assets.internal`. |

### Registry

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_NPM_REGISTRY` | `https://registry.npmjs.org` | Override the npm registry endpoint. Use this for private registries (Verdaccio, Artifactory, GitHub Packages) — version resolution and tarball fetches both honor it. |

### Debugging

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_PPROF` | (unset) | Set to a `host:port` (e.g. `:6060`) to expose Go's `net/http/pprof` endpoints for the duration of the command. Useful for profiling cold scans on large dep graphs — `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30`. |

### Display / TTY

| Variable | Default | Purpose |
|---|---|---|
| `NO_COLOR` | (unset) | Standard `https://no-color.org` — disable ANSI colors entirely. Honored across every renderer. |
| `AEGIS_NO_LIVE` | (unset) | Disable the live progress UI in `snapshot enrich` even when stderr is a TTY. Useful when piping through tools that don't strip cursor escapes. |

### CI auto-detection

`aegis` decides whether it's running in CI by looking at known marker variables. CI mode does two things: prompts auto-block (no waiting for stdin), and structured JSON logging is preferred over the pretty TTY format.

The full list of markers (any one being non-empty triggers CI mode):

| Variable | CI system |
|---|---|
| `AEGIS_CI` | Explicit override — set this to force CI mode anywhere |
| `CI` | Generic |
| `GITHUB_ACTIONS` | GitHub Actions |
| `GITLAB_CI` | GitLab CI |
| `CIRCLECI` | CircleCI |
| `TRAVIS` | Travis |
| `BUILDKITE` | Buildkite |
| `DRONE` | Drone |
| `TEAMCITY_VERSION` | TeamCity |
| `BITBUCKET_BUILD_NUMBER` | Bitbucket Pipelines |
| `CODEBUILD_BUILD_ID` | AWS CodeBuild |
| `JENKINS_URL` | Jenkins |

If your CI system isn't on this list, set `CI=true` or `AEGIS_CI=1` explicitly.

## Files and directories

`aegis` writes only inside the user's config / cache directories. It never writes to the project directory unless you explicitly `aegis snapshot save` (which writes `./aegis.lock`) or `aegis hook install` (which writes `.git/hooks/pre-commit`).

| Path | Created by | Purpose |
|---|---|---|
| `~/.aegis/cache/decisions.json` | every install gate run | Cached `(eco, name, version) → verdict` map. Cleared by `aegis cache clear`. |
| `~/.aegis/cache/sources/<eco>/<name>/<version>/` | `snapshot enrich`, `analyze` | Extracted package source for AST scanning. Cleared by `aegis cache clear --all`. |
| `~/.aegis/cache/fingerprints/` | `snapshot enrich`, `ci` | Per-(name, version) AST fingerprint cache. Warm cache is the entire reason `ci` reruns are fast. Cleared by `aegis cache clear --fingerprints`. |
| `~/.aegis/cache/advisories/` | `snapshot enrich`, `ci` | Per-advisory body cache (`<id>.json`) from OSV.dev. Cleared by `aegis cache clear --all`. |
| `~/.aegis/cache/usage/<lang>/<sha[:2]>/<sha[2:]>.json` | `snapshot enrich` | Per-source-file import and symbol cache keyed by sha256(body). Re-enrich after a one-file edit re-parses only the changed file. Cleared by `aegis cache clear --all`. |
| `~/.aegis/cache/org-allowlist.yaml` | `aegis allowlist sync` | Org-wide allowlist overlay fetched from the API. Layered between user and project rules. |
| `~/.aegis/allowlist.yaml` | `aegis allowlist add --scope=user` | User-level allowlist. Personal — gitignore it. |
| `~/.aegis/audit.jsonl` | every install gate / override / sync | NDJSON audit log: one line per outcome with timestamp, decision, reason, actor. Append-only. |
| `~/.aegis/identity.json` | first run | Stable per-user reporter ID used for `snapshot submit` attribution. Random UUID; not personally identifying. |
| `./aegis.lock` | `aegis snapshot save` | Project-level dependency snapshot. **Commit this** — it's the baseline `ci` and `recheck` compare against. |
| `./aegis.yml` or `./.aegis.yml` | `aegis ci`, `aegis actions scan` | Project-level config file — default flag values. **Commit this** — team-shared. See [aegis.yml reference](#aegisyml) below. |
| `./.aegis-allowlist.yaml` | `aegis allowlist add --scope=project` | Project-level allowlist. **Commit this** — team-shared. |
| `./.aegis-actions-allowlist.yaml` | `aegis actions scan`, `aegis ci --scan-actions` | Actions-specific allowlist. **Commit this** — suppress known-safe workflow findings. |
| `.git/hooks/pre-commit` | `aegis hook install` | Pre-commit hook that runs `aegis ci --fail-on=block`. Removed by `aegis hook uninstall`. |

### Recommended `.gitignore`

```gitignore
# user-level config (personal — never commit)
.aegis/

# project-level snapshot + allowlist — DO commit these:
# aegis.lock
# .aegis-allowlist.yaml
```

## Allowlist YAML schema

Both `~/.aegis/allowlist.yaml` and `./.aegis-allowlist.yaml` use the same schema:

```yaml
version: 1
rules:
  - ecosystem: npm           # required: npm | pypi | crates | go | maven
    name: lodash             # required, "*" allowed for any
    version: "^4"            # optional (default "*")
    capability: dynamic-eval # optional (default "*")
    reason: "lodash._.template uses Function() to compile templates"
```

Strict decoding: unknown keys, unknown capabilities, and unsupported schema versions all error out. Run `aegis allowlist verify` to check both files before committing.

The org-allowlist file (`~/.aegis/cache/org-allowlist.yaml`) uses the same schema; it's fetched from the API by `aegis allowlist sync` and applied as an extra layer between user and project rules.

## Layering / precedence

When a capability fires on `(eco, name, version)`, the allowlist layers are evaluated in this order, **specific names beating wildcards within each layer**:

1. **Builtin** — `internal/domain/builtin_allowlist.go` (~20 hand-curated rules; cannot be edited)
2. **User** — `~/.aegis/allowlist.yaml`
3. **Org** — `~/.aegis/cache/org-allowlist.yaml` (only if `aegis allowlist sync` has run)
4. **Project** — `./.aegis-allowlist.yaml`

If any layer suppresses a capability, the finding is annotated with the suppression source + reason but kept visible in `--json` output (so dashboards can still count "would-have-been-blocked-but-allowlisted" for transparency).

## aegis.yml

Place `aegis.yml` (or `.aegis.yml`) at the repository root to set default flag values for `aegis ci` and `aegis actions scan`. CLI flags always override config. Missing file is silently ignored.

```yaml
# aegis.yml
version: 1

ci:
  fail_on: block          # --fail-on default (safe|review|prompt|block)
  scan_actions: true      # always run --scan-actions
  actions_fail_on: high   # --actions-fail-on default (low|medium|high|critical)
  sarif: false            # --sarif default
  no_enrich: false        # --no-enrich default

actions:
  fail_on: high           # --min-severity default for aegis actions scan
  repo: ""                # --repo default (owner/repo)
```

**Precedence**: CLI flag > `aegis.yml` > built-in default.

Invalid `fail_on` / `actions_fail_on` values error immediately at startup with a clear message — bad config never silently passes through to runtime.

See `aegis.example.yml` in the repository root for the full annotated reference.

## Build-time configuration

These are compile-time choices, not env vars. See [Getting started § Install](../getting-started/#install) for the full table.

| Build tag | Effect |
|---|---|
| `nojsscan` | Drop the JS AST scanner (no cgo, no tree-sitter). `make build-core`. |
| `nonpm` | Don't register `aegis npm`. `make build-bun` (combined with `noyarn,nopnpm`). |
| `nobun` | Don't register `aegis bun`. |
| `noyarn` | Don't register `aegis yarn`. |
| `nopnpm` | Don't register `aegis pnpm`. |

ldflags injected at release time:

| Symbol | Source |
|---|---|
| `cli.Version` | Git tag (e.g. `v0.1.0`) |
| `cli.Commit` | Full git SHA at the tag |
| `cli.Date` | RFC3339 build timestamp |

Surfaced by `aegis version`.
