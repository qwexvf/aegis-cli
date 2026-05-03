# Configuration reference

How `aegis` is configured: environment variables, config file paths, and CI auto-detection. Authoritative as of `v0.1.0`.

`aegis` has **no global config file**. Everything is either an environment variable, a per-project file in the repo, or a flag on the subcommand. This is deliberate — it makes the binary safe to drop into shared CI runners without surprise state.

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

### Vulnerability lookup (OSV.dev)

`aegis snapshot enrich` / `aegis ci` cross-reference every dep against the public OSV.dev vulnerability database — **no Aegis API required, no auth needed**. The two env vars below tune that lookup.

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_OSV_URL` | `https://api.osv.dev` | Override the OSV endpoint. Use this to point at a self-hosted OSV mirror or a corporate proxy. The wire shape (`/v1/querybatch`, `/v1/vulns/{id}`) must match upstream. |
| `AEGIS_NO_VULN_LOOKUP` | (unset) | When set to anything non-empty, disables the OSV lookup entirely. The snapshot enrich step still runs the AST scanner; only the advisory column is empty. Useful for fully-offline runs or air-gapped CI. |

### Malware heuristics

`aegis snapshot enrich` runs a chain of behavior-based malware detectors over every JS package source after the AST scanner finishes. The heuristics catch zero-day patterns OSV doesn't know about yet:

- Suspicious install hooks (`curl|sh`, `node -e`, base64-piped-to-shell, Pastebin/Discord/ngrok hosts)
- Obfuscated payload (`eval(atob(...))`, `Function(decodeURIComponent(...))`)
- Suspicious URL targets (Pastebin, Discord webhooks, Telegram bots, IP grabbers, IDN homoglyphs)
- Binary droppers (`.exe`/`.dll`/`.so`/`.scpt`/`.ps1` in an npm tarball)
- Typosquat names (Levenshtein ≤ 2 from a top-1000 npm package)

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_NO_HEURISTICS` | (unset) | When set to anything non-empty, disables the malware heuristic pass. Useful when A/B testing heuristic vs AST-only scoring or to silence false positives during initial rollout. |

### Registry

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_NPM_REGISTRY` | `https://registry.npmjs.org` | Override the npm registry endpoint. Use this for private registries (Verdaccio, Artifactory, GitHub Packages) — version resolution and tarball fetches both honor it. |

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
| `~/.aegis/cache/org-allowlist.yaml` | `aegis allowlist sync` | Org-wide allowlist overlay fetched from the API. Layered between user and project rules. |
| `~/.aegis/allowlist.yaml` | `aegis allowlist add --scope=user` | User-level allowlist. Personal — gitignore it. |
| `~/.aegis/audit.jsonl` | every install gate / override / sync | NDJSON audit log: one line per outcome with timestamp, decision, reason, actor. Append-only. |
| `~/.aegis/identity.json` | first run | Stable per-user reporter ID used for `snapshot submit` attribution. Random UUID; not personally identifying. |
| `./aegis.lock` | `aegis snapshot save` | Project-level dependency snapshot. **Commit this** — it's the baseline `ci` and `recheck` compare against. |
| `./.aegis-allowlist.yaml` | `aegis allowlist add --scope=project` | Project-level allowlist. **Commit this** — team-shared. |
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

## Build-time configuration

These are compile-time choices, not env vars. See [Install § Build flavours](../README.md#install) for the full table.

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
