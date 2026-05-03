# aegis-cli

[![CI](https://github.com/qwexvf/aegis-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/qwexvf/aegis-cli/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/qwexvf/aegis-cli)](https://goreportcard.com/report/github.com/qwexvf/aegis-cli)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Supply-chain install gate for the JavaScript ecosystem. Wraps **npm**,
**bun**, **yarn**, and **pnpm**: every install request is checked against
the [Aegis](https://github.com/qwexvf/aegis) decision API before the
underlying PM is allowed to run. Tracks project dependency snapshots
and runs an AST-based risk engine over package source.

```text
$ aegis npm install ua-parser-js@0.7.29
[aegis] ✗ ua-parser-js@0.7.29 — BLOCKED (CRITICAL)
[aegis]   GHSA-pjwm-rvh2-c87w — Cryptominer + password stealer (preinstall.sh)
[aegis]   override: AEGIS_OVERRIDE=allow AEGIS_OVERRIDE_REASON=<reason> aegis npm install ua-parser-js@0.7.29
```

## Install

### Pre-built binaries

Download the latest release for your platform from
[**Releases**](https://github.com/qwexvf/aegis-cli/releases). All
artifacts are signed with [cosign](https://docs.sigstore.dev/cosign/)
keyless OIDC and ship with [SLSA build provenance](https://slsa.dev/).
Verify before running:

```sh
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/qwexvf/aegis-cli/.github/workflows/release.yml.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  checksums.txt
sha256sum -c checksums.txt
gh attestation verify aegis_<version>_linux_amd64.tar.gz --owner qwexvf
```

### From source

Requires Go 1.26 or later.

```sh
go install github.com/qwexvf/aegis-cli/cmd/aegis@latest
aegis version
```

Or build a specific flavour with `make`:

| Target               | Output                  | Build tags             | When to use                                  |
|----------------------|-------------------------|------------------------|----------------------------------------------|
| `make build-release` | `bin/aegis`             | (none)                 | full feature set, all PMs, AST scanner       |
| `make build-core`    | `bin/aegis-core`        | `nojsscan`             | size-constrained / no-cgo CI runners         |
| `make build-npm`     | `bin/aegis-npm`         | `nobun,noyarn,nopnpm`  | per-team binary registering only `aegis npm` |
| `make build-bun`     | `bin/aegis-bun`         | `nonpm,noyarn,nopnpm`  | only `aegis bun`                             |
| `make build-yarn`    | `bin/aegis-yarn`        | `nonpm,nobun,nopnpm`   | only `aegis yarn`                            |
| `make build-pnpm`    | `bin/aegis-pnpm`        | `nonpm,nobun,noyarn`   | only `aegis pnpm`                            |

The per-PM tags do not shrink the binary (Go DCE already strips unused
PM wrappers); they exist for **distribution clarity** — a binary named
`aegis-npm` whose `--help` only mentions `aegis npm` is easier to roll
out to a team that only uses one package manager.

## Quickstart

```sh
export AEGIS_API_URL=https://api.aegis.example.com   # or self-hosted Aegis

# Drop-in PM wrapper — install commands are checked, everything else passes through
aegis npm install lodash@4.17.21
aegis bun add lodash@^4.17.0
aegis yarn add lodash@latest
aegis pnpm add lodash

# Local-path / git / link installs pass through without an API call
aegis npm install ./vendor/foo
aegis bun add link:../sibling

# Snapshot the resolved dependency tree + run the AST risk engine
aegis snapshot save           # writes ./aegis.lock
aegis snapshot enrich         # fills risk + capability scores
aegis snapshot show           # human-readable view
aegis snapshot diff <ref>     # vs another snapshot or git ref

# Run as a CI gate (non-zero exit on findings ≥ threshold)
aegis ci --fail-on=block
```

See `aegis --help` for the full command tree, or
[`docs/cli-architecture.md`](docs/cli-architecture.md) for the
architectural tour.

## What `aegis` actually checks

For each install request:

1. **Argv parsing** — recognise the install subcommand, extract package
   specs, separate non-registry installs (paths, git URLs, `link:`,
   `workspace:`, yarn-berry `portal:`/`patch:`/`exec:`/`npm:`).
2. **Version resolution** — exact versions take a fast path; ranges and
   tags resolve via the npm registry.
3. **Decision check** — POST to the Aegis API
   `POST /api/v1/supply-chain/check`; cached locally in
   `~/.aegis/cache/decisions.json`.
4. **AST risk engine** (snapshot mode) — fetch the tarball, walk the
   tree-sitter AST for the source files, surface capabilities
   (`net-egress`, `child-process`, `dynamic-eval`, `credential-read`,
   `fs-write-outside-project`, `postinstall-script`, …).
5. **Allowlist** — suppress known-legitimate matches by
   `(ecosystem, name, version-range, capability)` tuple. Layered
   builtin → user → project; specific names beat wildcards.
6. **Verdict** — `allow` / `warn` / `prompt` / `block`. In CI, prompts
   auto-block (no waiting for stdin). Overrides require an explicit
   `AEGIS_OVERRIDE_REASON` and are written to the audit log.

## Verified incidents

The decision API ships with a curated database of real, citable npm
supply-chain incidents. None are fabricated:

| Package          | Version(s)                          | Date    | Advisory                | What happened |
|------------------|-------------------------------------|---------|-------------------------|---------------|
| `event-stream`   | `3.3.6`                             | 2018-11 | GHSA-jvqj-7wpc-9bqp     | Maintainer handover → malicious dep `flatmap-stream` targeting Bitcoin wallets |
| `flatmap-stream` | `0.1.1`                             | 2018-11 | GHSA-jvqj-7wpc-9bqp     | Encrypted payload of the event-stream incident |
| `eslint-scope`   | `3.7.2`                             | 2018-07 | GHSA-vhwc-9wr2-w98p     | Account takeover → npm credential exfiltration |
| `ua-parser-js`   | `0.7.29`, `0.8.0`, `1.0.0`          | 2021-10 | GHSA-pjwm-rvh2-c87w     | Cryptominer + password stealer |
| `coa`            | `2.0.3`–`2.1.3`                     | 2021-11 | GHSA-73qr-pfmq-6rp8     | Same actor / payload as ua-parser-js |
| `rc`             | `1.2.9`, `1.3.9`, `2.3.9`           | 2021-11 | GHSA-g2q5-5433-rhrf     | Same actor; rc had ~14M weekly downloads at compromise |
| `node-ipc`       | `10.1.1`, `10.1.2`                  | 2022-03 | GHSA-97m3-w2cp-4xx6     | "peacenotwar" — geo-IP-targeted file wipe |
| `colors`         | `1.4.44-liberty-2`                  | 2022-01 | (author self-sabotage)  | Infinite loop printing "LIBERTY LIBERTY LIBERTY" |
| `faker`          | `6.6.6`                             | 2022-01 | (author self-sabotage)  | Package wiped + protest message |

## Allowlist

```sh
aegis allowlist list                              # all rules from all sources
aegis allowlist add lodash \
    --capability=dynamic-eval \
    --version='^4' \
    --reason='_.template uses Function() to compile templates'
aegis allowlist test npm/lodash@4.17.21           # which rules apply?
aegis allowlist verify                            # parse user + project files
```

`--reason` is required on `add` — the allowlist is an audit trail, and
an empty reason is worse than no rule.

YAML schema:

```yaml
version: 1
rules:
  - ecosystem: npm           # required: npm | pypi | crates | go | maven
    name: lodash             # required, "*" for any
    version: "^4"            # optional (default "*")
    capability: dynamic-eval # optional (default "*")
    reason: "lodash._.template uses Function() to compile templates"
```

Sources, in match order:

1. **Builtin** — ~20 hand-curated rules shipped with the binary.
2. **User** — `~/.aegis/allowlist.yaml` (override with `AEGIS_CONFIG_DIR`).
   Personal, gitignored.
3. **Project** — `<project>/.aegis-allowlist.yaml`. Team-shared, commit this.

See [`docs/cli-risk-engine.md`](docs/cli-risk-engine.md) for capability
weights and suppression semantics.

## CI integration

Drop-in templates live under [`examples/ci/`](examples/ci/):

| File                                                     | For                                |
|----------------------------------------------------------|------------------------------------|
| [`github-actions.yml`](examples/ci/github-actions.yml)   | GitHub Actions                     |
| [`gitlab-ci.yml`](examples/ci/gitlab-ci.yml)             | GitLab CI                          |
| [`generic.sh`](examples/ci/generic.sh)                   | Buildkite / Jenkins / cron / shell |

Each template caches `~/.aegis/cache` between runs so warm runs only
re-scan changed deps. Default threshold is `block`; tighten with
`--fail-on=prompt` or `--fail-on=review`.

Exit codes from `aegis ci`:

| Code | Meaning                                              |
|------|------------------------------------------------------|
| `0`  | passed (no findings ≥ `--fail-on`)                   |
| `1`  | failed (one or more findings ≥ `--fail-on`)          |
| `2`  | couldn't reach a verdict (config / network error)    |

JSON output (`aegis ci --json`) is stable for tooling — see
[`examples/ci/README.md`](examples/ci/README.md).

## Architecture

Clean architecture with strict dependency direction:
`cmd → interface → usecase → domain ← infra`.

```
cmd/aegis/                   composition root (only place that constructs adapters)
internal/
├── domain/                  pure: PackageSpec, Decision, Capability, RiskScore, AllowSet
├── usecase/                 InstallGate, Snapshot, CI, Recheck — orchestration + ports
├── interface/cli/           Cobra command tree
├── presenter/cli/           ANSI rendering (NO_COLOR + TTY aware)
└── infra/                   adapters: pmwrapper, npmregistry, jspkgsource,
                             locksnap, astscan, allowlist, diskcache, ndjsonaudit,
                             aegisapi, ttyprompt, envprobe, hookfs, …
```

Adding a package manager is one file under `internal/infra/pmwrapper/`
implementing the `PackageManager` interface plus a registration in
`cmd/aegis/pm_<name>.go` guarded by `//go:build !no<name>`. Adding an
ecosystem (pip / cargo / gem) is five files — see
[`docs/cli-architecture.md`](docs/cli-architecture.md) for the full
walkthrough.

## Documentation

| Doc                                                       | What it covers                                                       |
|-----------------------------------------------------------|----------------------------------------------------------------------|
| This README                                               | User-facing: install, command summary, common flows                  |
| [docs/commands.md](docs/commands.md)                      | Every subcommand: flags, examples, exit codes, output schemas        |
| [docs/configuration.md](docs/configuration.md)            | Environment variables, file paths, allowlist YAML schema, CI markers |
| [docs/cookbook.md](docs/cookbook.md)                      | End-to-end recipes: local gate, CI gate, drift mode, overrides, self-host |
| [docs/cli-architecture.md](docs/cli-architecture.md)      | Layer map, dependency direction, "adding a PM / ecosystem" recipe    |
| [docs/cli-risk-engine.md](docs/cli-risk-engine.md)        | Capability enum, RiskScore / DriftScore weights, allowlist mechanics |
| [docs/cli-snapshot.md](docs/cli-snapshot.md)              | `aegis.lock` format, diff semantics, lockfile parsers, tarball cache |
| [docs/aegis-cli-demo-plan.md](docs/aegis-cli-demo-plan.md)| Historical 12-step build plan + post-demo inventory                  |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, commit style,
and the architecture rules. Before opening a non-trivial PR please open
an issue first to align on the approach.

## Security

Vulnerability reports go through [GitHub Private Vulnerability Reporting](https://github.com/qwexvf/aegis-cli/security/advisories/new) — never via public issues. See [SECURITY.md](SECURITY.md) for the full policy, scope, and response SLA.

## License

[Apache-2.0](LICENSE).
