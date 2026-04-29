# aegis CLI

Supply-chain install gate for the JavaScript ecosystem — wraps **npm**,
**bun**, and **yarn** and checks each install against the Aegis API
before letting it proceed.

> **Status:** v0.1.0-demo, end-to-end working.
> Done: skeleton, multi-PM support (npm/bun/yarn), argv parsing, version
> resolution, Aegis API client, allow/warn/block/prompt UX, override flow.
> Next: interactive prompt, local cache, audit log, additional ecosystems
> (pip / cargo / go). See `docs/aegis-cli-demo-plan.md`.

## Build

```bash
make build
./bin/aegis version
```

## Quickstart

```bash
make build
./demo.sh
```

`./demo.sh` spins up a local mock API and runs scenarios across all three
package managers (bun/yarn scenarios are skipped if the binaries aren't
installed):

```
==> Demo 1: Allow (lodash@4.17.21)
[aegis] checking lodash@4.17.21 ...
[aegis] lodash@4.17.21 ✓ allowed

==> Demo 2: Block (@bitwarden/cli@2026.4.0 — April 2026 incident)
[aegis] ✗ @bitwarden/cli@2026.4.0 — BLOCKED (CRITICAL)
[aegis]   depsandbox-net-egress — Postinstall connects to attacker-controlled host
[aegis]   depsandbox-credential-read — Reads /proc/self/environ during install
[aegis]   override: AEGIS_OVERRIDE=allow aegis npm install @bitwarden/cli@2026.4.0

==> Demo 6: bun block (@bitwarden/cli@2026.4.0)
[aegis] ✗ @bitwarden/cli@2026.4.0 — BLOCKED (CRITICAL)
[aegis]   override: AEGIS_OVERRIDE=allow aegis bun add @bitwarden/cli@2026.4.0

==> Demo 8: yarn block (global add ua-parser-js@0.7.29)
[aegis] ✗ ua-parser-js@0.7.29 — BLOCKED (CRITICAL)
[aegis]   override: AEGIS_OVERRIDE=allow aegis yarn add ua-parser-js@0.7.29
```

## Supported package managers

| PM     | Install commands recognized                | Registry          |
|--------|--------------------------------------------|-------------------|
| `npm`  | `install`, `i`, `add`, plus typo aliases   | registry.npmjs.org |
| `bun`  | `install`, `i`, `add`, `a`                 | registry.npmjs.org |
| `yarn` | `add`, `install`, `global add`             | registry.npmjs.org |

Non-registry forms (local paths, tarballs, git URLs, `link:`,
`workspace:`, yarn-berry `portal:` / `patch:` / `exec:` / `npm:`) are
detected and passed through without an API check.

## Manual usage

```bash
export AEGIS_API_URL=http://localhost:4000

# Transparent passthrough — same as the underlying PM for non-install commands
aegis npm --version
aegis bun run dev
aegis yarn test

# Install detection + version resolution + API check
aegis npm install lodash@4.17.21
aegis bun add lodash@^4.17.0           # range → resolved via npm registry
aegis yarn add lodash@latest            # tag → resolved via npm registry
aegis yarn global add create-react-app

# Non-registry installs pass through unchanged
aegis npm install ./vendor/foo
aegis bun add link:../sibling
aegis yarn add portal:./local-pkg

# Override a block (audited)
AEGIS_OVERRIDE=allow aegis npm install some-blocked@1.2.3
AEGIS_OVERRIDE=allow aegis bun add some-blocked@1.2.3
```

## Status

- ✅ Multi-PM support (npm + bun + yarn + pnpm share one gate)
- ✅ Argv parsing (scoped, ranges, tags, non-registry, yarn `global add`)
- ✅ Exact-version fast path (skips registry round-trip)
- ✅ Range/tag resolution via the npm registry
- ✅ Aegis API client (`POST /api/v1/supply-chain/check`)
- ✅ Allow / Warn / Block / Prompt UX with ANSI colors + NO_COLOR/TTY-aware
- ✅ Local decision cache (`~/.aegis/cache/decisions.json`)
- ✅ Interactive prompt for `prompt` decisions via `/dev/tty`
- ✅ Auto-block in CI (`CI=true`, `GITHUB_ACTIONS`, etc.) — never blocks waiting for input
- ✅ Audit log (`~/.aegis/audit.jsonl`)
- ✅ `AEGIS_OVERRIDE=allow` requires `AEGIS_OVERRIDE_REASON` (untraceable overrides refused)
- ✅ Real historical incident database (9 documented attacks, 17 version entries)
- ⬜ Audit log shipping to API (offline → batch sync)
- ⬜ pip / cargo / go (Tier A)
- ⬜ `aegis guard <command>` for universal lockfile-diff coverage (Tier B)
- ⬜ Active depsandbox runs (behavioral diff differentiator — Phase 3)

## Verified incidents

The gate ships with a curated database of real, citable npm
supply-chain incidents. None are fabricated:

| Package          | Version(s)                          | Date    | Advisory                | What happened |
|------------------|-------------------------------------|---------|-------------------------|---------------|
| `event-stream`   | `3.3.6`                             | 2018-11 | GHSA-jvqj-7wpc-9bqp     | Maintainer handover → malicious dep `flatmap-stream` targeting Bitcoin wallets |
| `flatmap-stream` | `0.1.1`                             | 2018-11 | GHSA-jvqj-7wpc-9bqp     | The actual encrypted payload of the event-stream incident |
| `eslint-scope`   | `3.7.2`                             | 2018-07 | GHSA-vhwc-9wr2-w98p     | Account takeover → npm credential exfiltration |
| `ua-parser-js`   | `0.7.29`, `0.8.0`, `1.0.0`          | 2021-10 | GHSA-pjwm-rvh2-c87w     | Cryptominer + password stealer (preinstall.sh / preinstall.bat) |
| `coa`            | `2.0.3`, `2.0.4`, `2.1.1`, `2.1.3`  | 2021-11 | GHSA-73qr-pfmq-6rp8     | Same actor / payload as ua-parser-js |
| `rc`             | `1.2.9`, `1.3.9`, `2.3.9`           | 2021-11 | GHSA-g2q5-5433-rhrf     | Same actor; rc had ~14M weekly downloads at compromise |
| `node-ipc`       | `10.1.1`, `10.1.2`                  | 2022-03 | GHSA-97m3-w2cp-4xx6     | "peacenotwar" — geo-IP-targeted file wipe on RU/BY hosts |
| `colors`         | `1.4.44-liberty-2`                  | 2022-01 | (author self-sabotage)  | Infinite loop printing "LIBERTY LIBERTY LIBERTY" |
| `faker`          | `6.6.6`                             | 2022-01 | (author self-sabotage)  | Package wiped + "What really happened with Aaron Swartz?" message |

`./scripts/demo-history.sh` walks through every entry against a live API.

## End-to-end verification

The gate is designed to run against the live Gleam API
(`POST /api/v1/supply-chain/check`). To smoke-test end-to-end:

```bash
# 1. Boot the API
docker compose up api -d
docker compose logs api    # confirm "Listening on 4000"

# 2. Build CLI + run unit tests
cd services/cli && make build && go test ./...

# 3. Smoke a known-clean install
./bin/aegis npm install lodash@4.17.21        # → ✓ allowed
./bin/aegis npm install lodash@4.17.21        # → ✓ allowed (cached) — no API call

# 4. Hit each ecosystem with a real incident
./bin/aegis npm install ua-parser-js@0.7.29    # block, GHSA-pjwm-rvh2-c87w
./bin/aegis bun add event-stream@3.3.6         # block, GHSA-jvqj-7wpc-9bqp
./bin/aegis yarn add colors@1.4.44-liberty-2   # block, author sabotage
./bin/aegis pnpm add node-ipc@10.1.2           # block, peacenotwar

# 5. Cache + audit + override
./bin/aegis cache list
./bin/aegis audit tail -n 10
AEGIS_OVERRIDE=allow ./bin/aegis npm install ua-parser-js@0.7.29
                                               # → blocked: AEGIS_OVERRIDE_REASON required
AEGIS_OVERRIDE=allow AEGIS_OVERRIDE_REASON='hotfix-123' \
    ./bin/aegis npm install ua-parser-js@0.7.29
                                               # → proceeds, audit entry with reason

# 6. CI mode (prompt → block)
CI=true ./bin/aegis npm install <prompt-package>

# 7. Or run the full canned demo
./scripts/demo-history.sh
```

## Allowlist

The risk engine flags well-known patterns (e.g. `child_process.exec`,
`Function()` constructor, `process.env` reads of credential names).
Some legitimate packages legitimately use these — lodash compiles
templates via `Function()`, webpack spawns build workers, axios is an
HTTP client. The allowlist suppresses specific
`(ecosystem, name, version-range, capability)` tuples while keeping
them visible in output for transparency.

### Sources (in match order)

1. **Builtin** — ~20 hand-curated rules shipped with the binary.
   Verified at compile time. Not user-editable.
2. **User** — `~/.aegis/allowlist.yaml` (override with `AEGIS_CONFIG_DIR`).
   Personal, **gitignored**.
3. **Project** — `<project>/.aegis-allowlist.yaml`. Team-shared,
   **commit this**.

For a single lookup, **specific-name rules win over wildcards**, then
input order decides ties within each bucket.

### CLI

```bash
aegis allowlist list                      # all rules from all sources
aegis allowlist list --source=builtin     # filter by source

aegis allowlist add <name> \
    --capability=<cap> \
    [--version=<semver-range>] \
    --reason="<required>" \
    [--scope=user|project]                # default: user

aegis allowlist remove <name> \
    [--capability=<cap>] \
    [--scope=user|project]

aegis allowlist test npm/lodash@4.17.21   # which rules apply?
aegis allowlist verify                    # parse user + project files
```

`--reason` is required on `add`. The allowlist is an audit trail; an
empty reason is worse than no rule.

### YAML schema

```yaml
version: 1
rules:
  - ecosystem: npm           # required: npm | pypi | crates | go | maven
    name: lodash             # required, "*" allowed for any
    version: "^4"            # optional (default "*")
    capability: dynamic-eval # optional (default "*")
    reason: "lodash._.template uses Function() to compile templates"
```

Strict decoding: unknown keys, unknown capabilities, and unsupported
schema versions all error out. Run `aegis allowlist verify` to check.

### Recommended .gitignore

Add to your project's `.gitignore`:
```
# user-level (personal) — never commit
.aegis/
~/.aegis/

# DO commit project-level
# .aegis-allowlist.yaml   <-- keep this in git
```

## Layout

The CLI is organised in clean-architecture layers:

```
services/cli/
├── cmd/aegis/main.go            # composition root (wires concrete adapters)
├── internal/
│   ├── domain/                  # entities + Policy.Evaluate + AllowSet (pure)
│   ├── usecase/                 # InstallGate + Snapshot + port interfaces
│   ├── interface/cli/           # Cobra command tree
│   ├── presenter/cli/           # Outcome → ANSI text
│   └── infra/
│       ├── aegisapi/            # DecisionChecker over HTTP
│       ├── allowlist/           # YAML loader (user + project)
│       ├── astscan/             # tree-sitter dispatcher + per-language
│       ├── diskcache/           # DecisionCache + FingerprintCache
│       ├── envprobe/            # CI markers + AEGIS_OVERRIDE/_REASON
│       ├── jspkgsource/         # npm tarball fetcher
│       ├── locksnap/            # lockfile parsers + zstd snapshot store
│       ├── ndjsonaudit/         # AuditWriter (NDJSON)
│       ├── npmregistry/         # VersionResolver
│       ├── pmwrapper/           # PackageManager (npm/bun/yarn/pnpm)
│       └── ttyprompt/           # Confirmer (/dev/tty)
├── Makefile
└── README.md
```

Domain has no dependencies. Usecase depends on domain + ports.
Adapters depend on domain only. The composition root is the single
place that constructs concrete implementations.

Adding a new package manager is one file under `infra/pmwrapper/`
implementing the `PackageManager` interface (`Name`, `Ecosystem`,
`InstallVerb`, `IsInstallCommand`, `ParseInstallArgs`, `Exec`).

## Roadmap

See `docs/aegis-cli-demo-plan.md` for the 12-step plan.
