# aegis-cli

[![CI](https://github.com/qwexvf/aegis-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/qwexvf/aegis-cli/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/qwexvf/aegis-cli)](https://goreportcard.com/report/github.com/qwexvf/aegis-cli)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Supply-chain analysis CLI for the JavaScript ecosystem. Parses
**npm / bun / yarn / pnpm** lockfiles, walks the AST of every package
source via tree-sitter, **and cross-references every dep against the
public [OSV.dev](https://osv.dev) vulnerability database** —
all without any backend or account.

What you get:

- **Known CVEs / GHSAs per dep** — every package version is checked
  against OSV (which aggregates GitHub Security Advisories,
  ecosystem-native feeds, and CVE) on each `aegis snapshot enrich`.
  No API key, no signup, no rate limit gymnastics.
- **Suspicious capability detection** — tree-sitter AST scanner
  surfaces `net-egress`, `child-process`, `dynamic-eval`,
  `credential-read`, `fs-write-outside-project`,
  `postinstall-script`, … even on packages with no published
  advisory yet (the typosquats and just-published malware nobody
  has reported).
- **Verdict folding** — Critical / High CVEs become `block`,
  Medium becomes `prompt`, Low becomes `review` — combined with
  AST findings via `max(astVerdict, advisoryVerdict)` so one risky
  signal isn't masked by the other.

```text
$ aegis snapshot save
[aegis] wrote ./aegis.lock — 312 deps from package-lock.json

$ aegis snapshot enrich
[aegis] AST-scanning 312 deps... (8 workers)
[aegis] 7 advisories across 4 packages
[aegis] enriched 312 deps

$ aegis ci --fail-on=block
✗ npm/event-stream@3.3.6 — verdict=block  risk=0
  Advisories:
    • GHSA-jvqj-7wpc-9bqp [critical] — Malicious package — Bitcoin wallet credential exfiltration
✗ npm/ua-parser-js@0.7.29 — verdict=block  risk=42
  Risk flags:
    + postinstall-script — declares postinstall hook  (+30)
    + net-egress         — fetch/XMLHttpRequest/dgram (+12)
  Advisories:
    • GHSA-pjwm-rvh2-c87w [critical] — Embedded malware in postinstall script
exit 1
```

> **About the optional Aegis Cloud:** the install-gate commands
> (`aegis npm install …`, `recheck`, `snapshot submit`, `allowlist
> sync`) require an Aegis API server. The platform repo is not yet
> public, so these are documented but not usable for most users in
> v0.1.x. **Vulnerability detection itself does NOT need Aegis
> Cloud** — it uses the public OSV.dev backend. Skip to
> [Local-only quickstart](#local-only-quickstart) for what works
> today.

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

## Local-only quickstart

These work today, with no backend, no API key, no cloud account.
Drop the binary on your `$PATH` and run them in any Node project.

```sh
# Snapshot the resolved dependency tree from the lockfile
aegis snapshot save                    # writes ./aegis.lock

# Walk every package's AST via tree-sitter; populate capability fingerprints
aegis snapshot enrich                  # fills capability scores

# Render
aegis snapshot show                    # direct deps
aegis snapshot show --all              # + transitive
aegis snapshot diff baseline.lock      # detect drift between snapshots

# Run as a CI gate — exits non-zero on findings ≥ threshold
aegis ci --fail-on=block

# Ad-hoc analyze any registry-resolvable package without committing to a project
aegis analyze lodash@4.17.21
aegis analyze --evidence ua-parser-js@0.7.29

# Manage local capability suppressions
aegis allowlist add lodash --capability=dynamic-eval --version='^4' \
    --reason='_.template uses Function() to compile templates'
aegis allowlist list
```

See `aegis --help` for the full command tree, or
[`docs/cli-architecture.md`](docs/cli-architecture.md) for the
architectural tour.

## API-dependent commands (require Aegis API)

The following commands need a reachable Aegis API server (set via
`AEGIS_API_URL`). The hosted Aegis Cloud is not yet available, and
the [qwexvf/aegis](https://github.com/qwexvf/aegis) platform repo is
private at this time, so these commands are documented but
**effectively unusable for most users in v0.1.x**:

| Command | Why it needs the API |
|---|---|
| `aegis npm install …` (and bun / yarn / pnpm) | POSTs to `/check` to look up the package against the incident database before letting the install proceed |
| `aegis recheck` | Same `/check` endpoint, applied across the whole lockfile |
| `aegis snapshot submit` | POSTs analyzed packages to `/reports` for the community signal pool |
| `aegis allowlist sync` | GETs the org-level allowlist overlay from `/allowlist` |

When the platform becomes available, these commands will work without
any binary change — they're already wired and shipped, just waiting on
a deployed server.

## What `aegis` does locally (no Aegis API needed)

For `aegis snapshot enrich` / `aegis ci` / `aegis analyze`:

1. **Lockfile parse** — read `package-lock.json` / `bun.lock` /
   `pnpm-lock.yaml` / `yarn.lock` and resolve every dep to a concrete
   `(name, version)`.
2. **Tarball fetch** — pull each package from the npm registry
   (configurable via `AEGIS_NPM_REGISTRY`); cache extracted source
   under `~/.aegis/cache/sources/`.
3. **AST risk engine** — walk the tree-sitter AST, surface
   capabilities (`net-egress`, `child-process`, `dynamic-eval`,
   `credential-read`, `fs-write-outside-project`,
   `postinstall-script`, …).
4. **Vulnerability lookup** — single batch POST to
   [OSV.dev](https://osv.dev)'s public `/v1/querybatch` endpoint
   for every dep; per-advisory GETs for severity / summary, cached
   to disk under `~/.aegis/cache/advisories/`. No auth, no signup.
   Disable with `AEGIS_NO_VULN_LOOKUP=1` for fully-offline use; point
   at a self-hosted OSV mirror via `AEGIS_OSV_URL=…`.
5. **Allowlist** — suppress known-legitimate matches by
   `(ecosystem, name, version-range, capability)` tuple. Layered
   builtin → user → project; specific names beat wildcards.
6. **Verdict** — `max(astVerdict, advisoryVerdict)` against
   thresholds, exit non-zero on findings ≥ `--fail-on`. Critical /
   High advisories become `block`; Medium becomes `prompt`; Low
   becomes `review`. Overrides require an explicit
   `AEGIS_OVERRIDE_REASON` and are written to the audit log.

## Verified incidents (Aegis API-only, requires backend)

When a deployed Aegis API is reachable, `aegis npm install …` and
`aegis recheck` consult a curated database of real, citable
supply-chain incidents:

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
