# `aegis` CLI — Demo Build Plan (historical)

> **Status (2026-04-29):** All 12 demo steps shipped to `main`, plus a
> substantial second wave (clean-arch refactor, snapshot mechanism,
> tree-sitter risk engine, allowlist) — see "Beyond the demo plan"
> at the bottom for what's actually in the binary today.
>
> This document is preserved as the **historical build order** that
> got us to the first working CLI. Current architecture and feature
> docs live alongside it (`docs/cli-architecture.md`,
> `docs/cli-risk-engine.md`, `docs/cli-snapshot.md`) and in
> `services/cli/README.md`.
>
> **Goal of the original demo:** a working end-to-end demo of
> `aegis npm install <pkg>` that talks to Aegis API, gets a decision,
> and either blocks/warns/allows the install.
> **Companion docs:** `aegisd-design.md`, `depsandbox-design.md`.

This is a build-order plan. Each step has a clear "done when" check.
The demo doesn't need every feature — it needs to **convincingly show
the end-to-end flow** for one ecosystem (npm) on one platform (Linux).

---

## What the demo will do

A 60-second screen recording / live demo:

```
$ aegis npm install lodash
[aegis] checking lodash@4.17.21 ...
[aegis] ✓ allowed (cached, clean)
added 1 package in 1.2s

$ aegis npm install @aegis/evil-demo
[aegis] checking @aegis/evil-demo@1.0.1 ...
[aegis] ⚠ NEW BEHAVIOR vs @aegis/evil-demo@1.0.0:
[aegis]    - exec("/bin/sh", "-c", "curl ...")     HIGH
[aegis]    - net_connect → attacker.test:443       CRITICAL
[aegis]
[aegis] BLOCKED by org policy "default"
[aegis] Override: AEGIS_OVERRIDE=allow aegis npm install @aegis/evil-demo
npm ERR! aegis: install blocked

$ # show the audit log in the Aegis dashboard
```

That's the whole demo. Short, concrete, reproducible.

---

## Architecture for the demo

```
┌────────────────┐                  ┌──────────────────────┐
│  aegis CLI     │   POST /check    │  Aegis API (Gleam)   │
│  (Go binary)   │ ───────────────→ │  /api/v1/supply-     │
│                │ ←─────────────── │  chain/check         │
│  - intercept   │                  │                      │
│  - render UX   │                  │  - lookup baseline   │
│  - exec npm    │                  │  - apply policy      │
│                │                  │  - return decision   │
└────────────────┘                  │                      │
                                    │  (for demo: stub     │
                                    │  decisions from a    │
                                    │  hand-curated table) │
                                    └──────────────────────┘
```

**Demo shortcut:** the API doesn't run real depsandbox yet — it returns
canned decisions from a small lookup table. We're proving the
end-to-end **shape**, not the analysis quality. Real depsandbox lands
later (covered in `depsandbox-design.md`).

---

## Build order

### Step 1 — Skeleton CLI binary (~half a day) ✅ DONE 2026-04-29

**Goal:** `aegis --version` runs and prints something.

- ✅ `services/cli/` directory created
- ✅ `go mod init github.com/qwexvf/aegis/services/cli`
- ✅ `cmd/aegis/main.go` with Cobra command tree
- ✅ Subcommands wired: `version`, `npm` (pip stretch deferred)
- ✅ `Makefile` targets: `build`, `test`, `vet`, `tidy`, `clean`, `run`

**Result:** `./bin/aegis version` → `aegis 0.1.0-demo`. Binary is **3.9 MB**.

---

### Step 2 — `aegis npm install` passthrough (~half a day) ✅ DONE 2026-04-29

**Goal:** `aegis npm install lodash` works exactly like `npm install
lodash` — no analysis yet, just transparent passthrough.

- ✅ `internal/wrap/npm.go` — `exec.LookPath("npm")` + `cmd.Run()` with
  inherited stdio
- ✅ `IsInstallSubcommand` detects `install`, `i`, `add`, and the
  common `isntall` typos
- ✅ Exit codes propagated via `os.Exit(status.ExitStatus())`

**Result:** `aegis npm --version` → `11.12.1` (real npm).
Non-install commands pass through unchanged.

---

### Step 3 — Argument parsing for install commands (~half a day) ✅ DONE 2026-04-29

**Goal:** when the user runs `aegis npm install <stuff>`, we know what
packages they're trying to install.

- ✅ `internal/wrap/parse.go` — `ParseInstallArgs([]string) []PackageSpec`
- ✅ Handles unscoped (`lodash`, `lodash@4.17.21`, `lodash@^4`),
  scoped (`@scope/name@2026.4.0`), tags (`@latest`)
- ✅ Non-registry passthrough detected: tarball URLs, http(s)://, git+,
  github:, file:, local paths (`./`, `/`, `~`)
- ✅ Skips npm's own flags + flags that consume a value
  (`--workspace foo`, `-w foo`, `--registry`, `--tag`, `--access`, `--prefix`)
- ✅ `IsExactVersion()` distinguishes pinned versions from ranges/tags
  so we can skip the registry round-trip
- ✅ **14 table-driven tests, all pass** (`internal/wrap/parse_test.go`)

---

### Step 4 — Resolve `@latest` and ranges to concrete versions (~half a day) ✅ DONE 2026-04-29

**Goal:** before we can ask the API "is `lodash@^4.17.0` safe?", we
need to know which exact version npm is about to install.

- ✅ `internal/registry/npm.go` — `Client.Resolve(ctx, pkg, rangeOrTag)`
  hits `https://registry.npmjs.org/<pkg>` with the abbreviated
  metadata Accept header for smaller responses
- ✅ Tag → exact: reads `dist-tags`
- ✅ Range → exact: `Masterminds/semver/v3` constraint match, picks
  the highest satisfying version
- ✅ Empty version defaults to `latest`
- ✅ Scoped packages URL-encoded correctly (`@scope/name` →
  `@scope%2Fname`)
- ✅ In-memory packument cache shared across the run
- ✅ Exact-pin fast path in `wrap/npm.go` skips the round-trip
- ✅ **4 tests pass** (`internal/registry/npm_test.go`)

**Result (live):**
```
$ aegis npm install lodash@^4.17.0 --dry-run
[aegis] checking lodash@4.18.1 ...                 ← resolved from ^4.17.0
[aegis] lodash@4.18.1 ✓ allowed
add lodash 4.18.1
```

---

### Step 5 — API endpoint stub on the Gleam side (~half a day) ✅ DONE 2026-04-29

**Goal:** `POST /api/v1/supply-chain/check` exists and returns a
canned decision.

- ✅ `services/api/src/aegis_api/interface/http/supply_chain_handler.gleam`
  — typed `Decision`, `DecisionKind`, `Severity`, `Reason`
- ✅ Wired into `interface/router.gleam` at
  `["api", "v1", "supply-chain", "check"]` (POST)
- ✅ Hand-curated decision table covers:
  - `npm|lodash|4.17.21` → Allow
  - `npm|@bitwarden/cli|2026.4.0` → Block (Critical) — the April 2026 incident
  - `npm|ua-parser-js|0.7.29` → Block (Critical) — the 2021 compromise
  - `npm|@aegis/evil-demo|1.0.0` → Allow / `1.0.1` → Block (Critical)
  - `npm|@aegis/suspicious-demo|2.0.0` → **Prompt** (High) — exercises
    the review-required path
  - Anything else → Allow with `cached: false`
- ✅ Mirrored in `services/cli/scripts/mock-api.sh` (Python) so devs can
  iterate on the CLI without spinning up Gleam + Postgres + NATS

**Response shape (matches `aegisd-design.md §1.6`):**
```json
{
  "ecosystem": "npm",
  "package": "@bitwarden/cli",
  "version": "2026.4.0",
  "decision": "block",
  "severity": "critical",
  "cached": true,
  "reasons": [
    {"category": "depsandbox-net-egress", "detail": "..."},
    {"category": "depsandbox-credential-read", "detail": "..."}
  ]
}
```

Gleam compiles cleanly; the 12 pre-existing test failures are
`ConnectionUnavailable` (test DB not running), not regressions.

---

### Step 6 — CLI calls the API, gets a decision (~half a day) ✅ DONE 2026-04-29

**Goal:** the CLI hits the stub endpoint for each package and prints
the decision.

- ✅ `internal/api/client.go` — `Client.Check(ctx, ecosystem, pkg, version)`
- ✅ `AEGIS_API_URL` env var (default `http://localhost:4000`)
- ✅ 5 second HTTP timeout per check
- ✅ Decision struct decoded from JSON, passed to `ui.Render`
- ✅ Fail-open on HTTP error (logged loudly, install proceeds)

---

### Step 7 — Decision UX: allow / warn / block / prompt (~one day) ✅ DONE 2026-04-29

**Goal:** the CLI renders the Allow/Warn/Block/Prompt decision in the
actual UX from the design doc.

- ✅ `internal/ui/render.go` — `Render(w, decision)` dispatches on
  `decision.Decision`:
  - **Allow** — single dim line + green `✓ allowed` (extra hint when
    `cached: false`)
  - **Warn** — yellow `⚠` header + reasons, install proceeds
  - **Block** — red `✗` header + `BLOCKED (CRITICAL)` + reasons +
    override hint, install does NOT proceed (exit 1)
  - **Prompt** — yellow `⚠ REVIEW REQUIRED (HIGH)` + reasons,
    blocks for now (Step 8 wires the interactive prompt)
- ✅ ANSI color codes hand-rolled (no `fatih/color` dependency).
  Honors `NO_COLOR` (https://no-color.org) and skips colors when
  stderr isn't a TTY
- ✅ Cross-platform TTY detection via build-tagged `tty_linux.go`,
  `tty_darwin.go`, `tty_unix.go`, `tty_other.go`
- ✅ `AEGIS_OVERRIDE=allow` flow: when set, block/prompt decisions
  log `AEGIS_OVERRIDE=allow set — proceeding (audited)` and let npm run
- ✅ Helpers: `ui.Resolved`, `ui.Skipped`, `ui.APIError` for the
  pre-decision status lines

**All four UX paths verified end-to-end against the mock API.** See
the `Live demo` section below.

---

---

## Live demo (current state, 2026-04-29)

`./demo.sh` runs all four scenarios against a local mock API:

```
==> Demo 1: Allow (lodash@4.17.21)
[aegis] checking lodash@4.17.21 ...
[aegis] lodash@4.17.21 ✓ allowed                           ← green
add lodash 4.17.21
added 1 package in 190ms

==> Demo 2: Block (@bitwarden/cli@2026.4.0 — April 2026 incident)
[aegis] checking @bitwarden/cli@2026.4.0 ...
[aegis] ✗ @bitwarden/cli@2026.4.0 — BLOCKED (CRITICAL)     ← red bold
[aegis]   depsandbox-net-egress — Postinstall connects to attacker host
[aegis]   depsandbox-credential-read — Reads /proc/self/environ
[aegis]
[aegis]   override: AEGIS_OVERRIDE=allow aegis npm install ...
[exit code: 1]                                              ← npm never ran

==> Demo 3: Prompt (@aegis/suspicious-demo@2.0.0)
[aegis] ⚠ @aegis/suspicious-demo@2.0.0 — REVIEW REQUIRED (HIGH)
[aegis]   depsandbox-script-added — New postinstall since 1.x
[aegis]   depsandbox-fs-write — Writes outside ./node_modules/

==> Demo 4: Block + override (ua-parser-js@0.7.29)
[aegis] ✗ ua-parser-js@0.7.29 — BLOCKED (CRITICAL)
[aegis]   depsandbox-exec-shell — Postinstall executes shell payload
[aegis]   AEGIS_OVERRIDE=allow set — proceeding (audited)   ← bypass logged
```

**Reproduce locally:**

```bash
cd services/cli
make build
./demo.sh
```

**Build / test status:**
- `make build` → `bin/aegis` (3.9 MB)
- `make vet` → clean
- `go test ./...` → **18 passed in 5 packages**

---

### Step 8 — Interactive prompt for HIGH severity (~one day)

**Goal:** when severity is HIGH but not CRITICAL, prompt the user with
the diff and let them choose.

- `internal/ui/prompt.go` — TTY prompt with options
  `[a]llow / [b]lock (default) / [r]eview / [c]opy details`
- "Review" opens the URL from the API response in the default
  browser (use `xdg-open` / `open`)
- "Copy details" puts a JSON blob on the clipboard
- Default is block — pressing Enter is safe
- Non-TTY (CI runner): no prompt; HIGH defaults to block (configurable
  via `AEGIS_NONINTERACTIVE=warn`)

Done when: a curated `[high]` decision in the API stub triggers the
interactive prompt; choosing block stops npm; choosing allow lets it
through.

---

### Step 9 — Local decision cache (~half a day)

**Goal:** repeat installs of the same package@version don't hit the
API every time.

- `internal/cache/local.go` — disk cache at
  `~/.cache/aegis/decisions.db` (BoltDB or just a JSON file for the
  demo)
- Cache key: `(ecosystem, package, version)`
- Cache value: full decision response + TTL (default 1 hour for the
  demo)
- On cache hit: skip API call, print
  `[aegis] {pkg}@{ver} → {decision} (cached)`

Done when: running `aegis npm install lodash` twice in a row makes
exactly **one** API call.

---

### Step 10 — Audit log shipping (~half a day)

**Goal:** every install attempt (allow, warn, block, override) is
logged to the Aegis API for the dashboard demo.

- `internal/api/audit.go` — POST to `/api/v1/audit/installs` after
  each decision is rendered
- Include: package, version, decision, override flag, timestamp,
  hostname, current user
- On API error: buffer to `~/.cache/aegis/audit-pending.jsonl` and
  flush on next successful API call
- API side: append to a simple `install_audit` table (per the
  `aegisd-design.md` schema)

Done when:
- After a few demo installs, the audit log table has the right rows
- The Aegis web dashboard has a "Recent installs" page (even just a
  raw table view) showing them

---

### Step 11 — Polish for the demo recording (~half a day)

- Banner / version output looks nice
- Color choices verified on light + dark terminals
- Help text (`aegis --help`, `aegis npm --help`) is accurate
- Bin name and binary work in a Docker container (`FROM alpine && COPY
  aegis /usr/local/bin/aegis && CMD ["aegis", "npm", "install",
  "lodash"]`) — proves portability claim
- README in `services/cli/README.md` with quickstart
- Demo script: a `demo.sh` that runs the three install commands above
  with pauses, so the recording is reproducible

Done when: someone unfamiliar with the project can run the demo from
README in <5 minutes.

---

### Step 12 — Stretch: pip support (~one day, optional)

Same shape as npm:
- `aegis pip install <pkg>` passthrough
- PyPI registry version resolution
- API stub adds pip entries to the canned decision table

Adds breadth to the demo. Skip if time-constrained.

---

## What's explicitly NOT in the demo

These are in the full design doc but **not for v0.1**:

- ❌ Real depsandbox running on the orchestrator (canned decisions only)
- ❌ Registry proxy mode (we wrap, not proxy — proxy is v0.2)
- ❌ eBPF bypass detection
- ❌ macOS / Windows builds (Linux + Docker only)
- ❌ Org policy editor in the UI (one hard-coded "default" policy)
- ❌ Cross-tenant hash consensus
- ❌ OSSF feed ingestion
- ❌ Multi-ecosystem at the same time (npm only; pip is stretch)
- ❌ Auto-update
- ❌ Cosign signing (do this before any external sharing)

Each of these is a real follow-up; none are required to prove the
shape works.

---

## Progress

| Step | Status | Notes |
|---|---|---|
| 1. Skeleton CLI | ✅ | 2026-04-29 |
| 2. Passthrough | ✅ | 2026-04-29 |
| 3. Arg parsing | ✅ | 14 tests |
| 4. Version resolution | ✅ | 4 tests |
| 5. API stub | ✅ | Gleam handler + router + Python mirror |
| 6. CLI ↔ API | ✅ | fail-open, 5s timeout |
| 7. Decision UX | ✅ | allow / warn / block / prompt + AEGIS_OVERRIDE |
| 8. Interactive prompt | ⬜ | next |
| 9. Local cache | ⬜ |  |
| 10. Audit log | ⬜ |  |
| 11. Polish | ⬜ |  |
| 12. Pip (stretch) | ⬜ |  |

**~3 days of work elapsed**; ~3 days remain for steps 8–11 to reach
v0.1.0-demo as originally scoped.

---

## Repo layout (current state, 2026-04-29)

```
aegis/
├── services/
│   ├── api/                                      # existing Gleam API
│   │   └── src/aegis_api/interface/
│   │       ├── router.gleam                      # +1 route
│   │       └── http/supply_chain_handler.gleam   # NEW (Step 5)
│   ├── orchestrator/                             # existing Go orchestrator
│   └── cli/                                      # NEW
│       ├── cmd/aegis/main.go
│       ├── internal/
│       │   ├── api/client.go                     # Step 6
│       │   ├── registry/
│       │   │   ├── npm.go                        # Step 4
│       │   │   └── npm_test.go
│       │   ├── ui/
│       │   │   ├── render.go                     # Step 7
│       │   │   ├── tty_linux.go                  # build-tagged TTY detection
│       │   │   ├── tty_darwin.go
│       │   │   ├── tty_unix.go
│       │   │   └── tty_other.go
│       │   └── wrap/
│       │       ├── npm.go                        # Steps 2 + 6 + 7
│       │       ├── parse.go                      # Step 3
│       │       └── parse_test.go
│       ├── scripts/mock-api.sh                   # local Python stub
│       ├── demo.sh                               # one-command demo
│       ├── go.mod
│       ├── Makefile
│       └── README.md
└── docs/
    ├── aegisd-design.md          # full vision (host daemon)
    ├── aegis-cli-demo-plan.md    # this file
    └── depsandbox-design.md      # backend analysis engine
```

**Files NOT yet created** (steps 8–11):
- `internal/cache/local.go` (Step 9)
- `internal/api/audit.go` (Step 10)
- `internal/ui/prompt.go` (Step 8)

---

## After the demo lands

The natural follow-up sequence (each its own design doc / PR):

1. **Real depsandbox decisions** — replace the canned API table with
   the actual orchestrator analysis path (depsandbox-design.md).
2. **Registry proxy mode** — Socket-Firewall-style transparent proxy
   instead of CLI wrapping, for cases where wrapping isn't possible.
3. **Policy editor in the dashboard** — admins author policy via UI
   instead of hard-coded.
4. **Cosign signing + SLSA provenance + auto-update** — required
   before anyone outside the org runs the binary.
5. **macOS + Windows builds** — cross-compile, codesign, distribute.
6. **OSSF feed ingestion** — known-bad Bloom filter shipped with the
   CLI for offline coverage.

Each is independently shippable.

---

## Beyond the demo plan — what shipped after

The 12-step plan above brought us to a working `aegis npm install`
gate. The binary in `main` today goes substantially further. Quick
inventory, in landing order:

### Multi-package-manager support
`bun`, `yarn`, `pnpm` all wrap the same install gate. Each is one
file under `infra/pmwrapper/` implementing the `PackageManager`
interface (`Name`, `Ecosystem`, `InstallVerb`, `IsInstallCommand`,
`ParseInstallArgs`, `Exec`).

### Clean-architecture refactor
The CLI is now organised in 4 layers — `domain` (pure), `usecase`
(ports + orchestration), `interface/cli` (Cobra command tree),
`presenter/cli` (rendering), and `infra/*` (concrete adapters).
See `docs/cli-architecture.md` for the layer map and dependency
direction.

### Real historical incident database
The Gleam handler's `lookup_decision()` was replaced by
`domain/incident.gleam` populated with 9 documented historical
attacks (event-stream, ua-parser-js, coa, rc, node-ipc, eslint-scope,
flatmap-stream, colors, faker — 17 specific package@version entries).
Every entry cites a public GHSA / postmortem.

### `aegis snapshot` — project-level dep tracking
Project lockfile snapshots persisted as zstd-compressed JSON at
`<project>/aegis.lock`. Subcommands: `save`, `show`, `diff`,
`enrich`, `verify`. See `docs/cli-snapshot.md`.

### Risk engine — tree-sitter JS scanner
AST-based capability detection (`shell-spawn`, `dynamic-eval`,
`base64-decode`, `net-egress`, `env-read`, `fs-write`, `raw-ip`,
`install-hook`). Scores fed through `RiskScore` (per-version) and
`DriftScore` (version-over-version) into a `Verdict` (safe / review
/ prompt / block). See `docs/cli-risk-engine.md`.

### Allowlist
Layered builtin (~20 curated rules) + user (`~/.aegis/allowlist.yaml`)
+ project (`<project>/.aegis-allowlist.yaml`). Suppressed flags are
kept in output for transparency. CLI: `aegis allowlist
{list,add,remove,test,verify}`.

### Binary size targets
`make build-release` produces an 8.2 MB stripped binary;
`make build-core` (with `-tags=nojsscan`) drops the AST scanner for
a 7.4 MB binary suitable for size-constrained CI runners.

### Test coverage
~300+ tests across 14 packages. domain ≥ 95%, infra adapters 70-100%,
interface/cli command tree 22% (cobra wiring shape only).

---

## Forward-looking — what's still unbuilt

The original "After the demo lands" list is partially done; the rest
plus newer items:

| Area | Status |
|---|---|
| Real depsandbox decisions | Plan exists (`depsandbox-design.md`); not implemented |
| Registry proxy mode | Not started |
| Dashboard policy editor | Not started |
| Cosign / SLSA / auto-update | Not started |
| macOS + Windows builds | Native build only on dev's host |
| OSSF feed ingestion | Not started |
| **pip support** | Detailed design in plan file, not in `main` |
| **cargo / gem / maven / hex** | Drop-in via `infra/pmwrapper/*` + `infra/<eco>pkgsource/` |
| **Web graph view** | Not started — would consume `aegis.lock` directly |
| **WASM grammar plugins** | Concept only — would replace cgo tree-sitter for multi-lang scaling |
| **deny / negate rules** | Allowlist follow-up (override builtin via deny) |
| **Stable rule IDs** | Allowlist follow-up |
| **Override audit shipping** | API endpoint not built yet |
