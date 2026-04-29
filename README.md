# aegis CLI

Supply-chain install gate for npm, pip, and cargo. Wraps your package manager
and checks each install against the Aegis API before allowing it to proceed.

> **Status:** v0.1.0-demo, end-to-end working.
> Done: skeleton, npm passthrough, argv parsing, version resolution,
> Aegis API client, allow/warn/block/prompt UX, override flow.
> Next: interactive prompt, local cache, audit log. See `docs/aegis-cli-demo-plan.md`.

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

`./demo.sh` spins up a local mock API and runs four scenarios:

```
==> Demo 1: Allow (lodash@4.17.21)
[aegis] checking lodash@4.17.21 ...
[aegis] lodash@4.17.21 ✓ allowed
add lodash 4.17.21

==> Demo 2: Block (@bitwarden/cli@2026.4.0 — April 2026 incident)
[aegis] checking @bitwarden/cli@2026.4.0 ...
[aegis] ✗ @bitwarden/cli@2026.4.0 — BLOCKED (CRITICAL)
[aegis]   depsandbox-net-egress — Postinstall connects to attacker-controlled host
[aegis]   depsandbox-credential-read — Reads /proc/self/environ during install
[aegis]
[aegis]   override: AEGIS_OVERRIDE=allow aegis npm install @bitwarden/cli@2026.4.0

==> Demo 3: Prompt / Review Required (@aegis/suspicious-demo@2.0.0)
[aegis] ⚠ @aegis/suspicious-demo@2.0.0 — REVIEW REQUIRED (HIGH)
[aegis]   depsandbox-script-added — New postinstall script added since 1.x
[aegis]   depsandbox-fs-write — Writes outside ./node_modules/ during install

==> Demo 4: Block + override (ua-parser-js@0.7.29)
[aegis] ✗ ua-parser-js@0.7.29 — BLOCKED (CRITICAL)
[aegis]   depsandbox-exec-shell — Postinstall executes downloaded shell payload
[aegis]   AEGIS_OVERRIDE=allow set — proceeding (audited)
```

## Manual usage

```bash
# Point at the live Gleam API (or any compatible endpoint)
export AEGIS_API_URL=http://localhost:4000

# Transparent passthrough — same as `npm <args>` for non-install commands
aegis npm --version

# Install detection + version resolution + API check
aegis npm install lodash@4.17.21
aegis npm install lodash@^4.17.0       # range → resolved via registry
aegis npm install lodash@latest         # tag → resolved via registry

# Non-registry installs pass through unchanged
aegis npm install ./vendor/foo
aegis npm install https://github.com/owner/repo.git

# Override a block (audited)
AEGIS_OVERRIDE=allow aegis npm install some-blocked@1.2.3
```

## Status

- ✅ `npm install` / `i` / `add` detection
- ✅ Argv parsing (scoped, ranges, tags, non-registry)
- ✅ Exact-version fast path (skips registry round-trip)
- ✅ Range/tag resolution via the npm registry
- ✅ Aegis API client (POST /api/v1/supply-chain/check)
- ✅ Allow / Warn / Block / Prompt UX with ANSI colors + NO_COLOR/TTY-aware
- ✅ AEGIS_OVERRIDE=allow flow
- ⬜ Interactive prompt for HIGH severity (Step 8)
- ⬜ Local decision cache (Step 9)
- ⬜ Audit log shipping (Step 10)

## Layout

```
services/cli/
├── cmd/aegis/main.go        # entrypoint, Cobra command tree
├── internal/
│   ├── api/                 # Aegis API client (step 6)
│   ├── cache/               # local decision cache (step 9)
│   ├── registry/            # npm registry version resolution (step 4)
│   ├── ui/                  # decision rendering + prompts (steps 7-8)
│   └── wrap/                # package manager wrappers
├── Makefile
└── README.md
```

## Roadmap

See `docs/aegis-cli-demo-plan.md` for the 12-step plan.
