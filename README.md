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

- ✅ Multi-PM support (npm + bun + yarn share one gate)
- ✅ Argv parsing (scoped, ranges, tags, non-registry, yarn `global add`)
- ✅ Exact-version fast path (skips registry round-trip)
- ✅ Range/tag resolution via the npm registry
- ✅ Aegis API client (`POST /api/v1/supply-chain/check`)
- ✅ Allow / Warn / Block / Prompt UX with ANSI colors + NO_COLOR/TTY-aware
- ✅ AEGIS_OVERRIDE=allow flow
- ⬜ Interactive prompt for HIGH severity (Step 8)
- ⬜ Local decision cache (Step 9)
- ⬜ Audit log shipping (Step 10)
- ⬜ pip / cargo / go (Tier A)
- ⬜ `aegis guard <command>` for universal lockfile-diff coverage (Tier B)

## Layout

```
services/cli/
├── cmd/aegis/main.go        # entrypoint, Cobra command tree
├── internal/
│   ├── api/                 # Aegis API client
│   ├── pm/                  # PackageManager interface + Runner + npm/bun/yarn
│   ├── registry/            # npm registry version resolution
│   └── ui/                  # decision rendering
├── Makefile
└── README.md
```

Adding a new package manager is one new file under `internal/pm/`
implementing the `PackageManager` interface (`Name`, `Ecosystem`,
`IsInstallCommand`, `ParseInstallArgs`, `Exec`).

## Roadmap

See `docs/aegis-cli-demo-plan.md` for the 12-step plan.
