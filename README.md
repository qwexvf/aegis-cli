# aegis

Supply-chain security scanner for source packages, lockfiles, and container
images. No CGO, no tokio — pure-Rust, feature-gated crates, parallel across
cores via rayon.

It answers the questions a security engineer actually asks about a dependency:

- Does this package's code do something dangerous? (`analyze` — AST + heuristics)
- Does my lockfile pin a known-vulnerable version? (`ci` — OSV/GHSA)
- How do I fix it? (`fix` — minimal safe version bumps)
- Did this dependency's *behavior* change between versions? (`snapshot` — drift)
- Is a flagged dependency even used? (`reach` / `run` unused-deps)
- What's in this container image? (`image` — tarball or registry pull)

> **Rust rewrite.** `main` is the Rust implementation. The Go v0.29 tree that
> preceded it lives on the [`old`](https://github.com/qwexvf/aegis-cli/tree/old)
> branch and is frozen; releases up to and including `v0.29.1` are Go builds.
> See [Migrating from Go v0.29](#migrating-from-go-v029) for the command-surface
> differences.

## Install

```sh
cargo install --path crates/aegis-cli      # from this repo
# or
cargo install --git https://github.com/qwexvf/aegis-cli
```

Needs a working C compiler — the tree-sitter grammars are Rust crates that
compile their vendored `parser.c` through the `cc` build script. That's the
same `cc` cargo already needs to link, so a stock `rustup` install on Linux or
macOS is enough; there is no cgo boundary and no separate grammar toolchain.

## Commands

| command | what it does |
|---|---|
| `parse <lockfile>` | list a lockfile's dependencies (24 parsers) |
| `analyze <dir>` | AST + heuristic scan of a package's source → risk verdict |
| `ci <lockfile>` | CI gate: per-dep enrich + CVE (OSV/GHSA), fail the build on findings |
| `fix <lockfile>` | version-bump plan + safe upgrade commands |
| `run <aegis.toml>` | parallel fleet scan (ast/heuristics/cve/deprecated/license/unused-deps) |
| `sbom <lockfile>` | CycloneDX 1.5 / SPDX 2.3 SBOM |
| `image <tarball>` / `image --ref <repo:tag>` | scan an OCI image (3 tiers) |
| `snapshot <sub>` | `aegis.lock` lifecycle — see [Snapshots](#snapshots) |
| `reach <dir> <pkg>` | is a dependency imported (reachable) in JS/TS/Py/Go/PHP source? |
| `allowlist` | list built-in capability-suppression rules |
| `explain [capability\|pkg@ver]` | the risk model, or a published package's capabilities |
| `hook [--install]` | git pre-commit hook that scans staged lockfiles |
| `actions` | generate a GitHub Actions workflow (runs `ci`, uploads SARIF) |

Most reporting commands take `--json`; `ci`, `analyze`, and `run` also take
`--sarif` (SARIF 2.1.0 for GitHub Code Scanning). Exit codes: `0` clean, `1`
findings ≥ threshold, `2` usage/IO error.

## Security workflows

**Block vulnerable dependencies in CI**
```sh
aegis ci package-lock.json --fail-on block       # exit 1 → build fails
aegis ci package-lock.json --sarif > aegis.sarif # → upload to Code Scanning
aegis actions > .github/workflows/aegis.yml      # ready-made workflow
```

`--fail-on` is a *verdict* threshold — `safe`, `review`, `prompt`, or `block`
(default `block`). A dep's verdict folds together its scanned capabilities, its
advisories, and whether your source actually imports it: an unused dependency's
advisory verdict is downgraded one level.

**Catch bad dependencies before they're committed**
```sh
aegis hook --install    # writes .git/hooks/pre-commit
```

**Scan a suspicious package's source**
```sh
aegis analyze ./node_modules/some-pkg --ecosystem npm
#   verdict: block (score 180)
#   [ 70] install-hook-suspicious — install hook downloads-and-executes …
#   [ 65] git-dep-in-optional — worm-propagation injection vector
aegis analyze ./pkg --online     # + npm maintainer/provenance/tarball-drift checks
aegis explain lodash@4.17.4      # fetch + scan a published package instead
```

**Fleet-scan a monorepo of vendored packages**
```sh
aegis run aegis.toml    # per-task verdicts, overall fail if any task blocks
```
```toml
[[task]]
name = "vendored-lib"
path = "./vendor/lib"
ecosystem = "npm"
checks = ["ast", "heuristics", "cve", "deprecated", "license", "unused-deps"]
deny_licenses = ["GPL-3.0"]
```

**Scan a container image**
```sh
aegis image ./image.tar          # docker save / OCI layout
aegis image --ref alpine:latest  # pull from a registry, then scan
aegis image --ref ghcr.io/org/private:1.2 --username u --password $TOKEN
```

## Snapshots

`aegis.lock` records what each dependency *is* and what it *does*, so the next
scan can tell you what changed. This is the maintainer-takeover signal: a patch
release that suddenly gains `shell-spawn` is worth a human look even when no
CVE exists for it.

```sh
aegis snapshot save          # scan the lockfile → aegis.lock (offline, fast)
aegis snapshot enrich        # fetch + scan each dep, add advisories (network)
aegis snapshot show --all    # render it; --used-only hides unused deps
aegis snapshot diff          # saved lock vs a fresh re-scan of the lockfile
aegis snapshot rescan        # re-query advisories; exit 1 on a NEW one (cron)
aegis snapshot verify        # lint the lock for loadability + schema version
```

`enrich` is idempotent — re-running only processes deps that don't have a
fingerprint yet, so a partial run is safe to resume. `diff` also accepts two
explicit snapshot paths (`aegis snapshot diff . a.json b.json`).

Single-package drift, without a project lockfile:

```sh
aegis snapshot capture ./pkg-v1 --out baseline.json
aegis snapshot capture ./pkg-v2 --baseline baseline.json
#   + shell-spawn  (NEW capability — possible takeover)   → exit 1
```

## What it detects

Behavioral capabilities (AST + heuristics): shell-spawn, dynamic-eval, net-egress,
base64-decode, env-cred-read, obfuscated-payload (incl. `String.fromCharCode` /
split-string de-obfuscation via a taint pass), install-hook-suspicious,
binary-dropper, hardcoded-secret, typosquat, tarball-source-drift,
git-dep-in-optional, unlisted-large-file, known-malware-ioc, maintainer-hijack /
version-unpublished / maintainer-changed, provenance-missing, and more —
`aegis explain` lists them all with weights.

Known vulnerabilities: OSV.dev + GitHub GHSA (with `GITHUB_TOKEN`), enriched with
EPSS exploit-probability and CISA KEV; feeds cached on disk (24h/7d TTL).

Ecosystems: npm (package-lock/yarn/pnpm/bun), PyPI (poetry/uv/pipfile/
requirements), crates, Go, RubyGems, Composer, NuGet, Maven (pom+gradle), Hex
(mix+gleam), Pub, CocoaPods, Swift, CRAN, CPAN, Hackage — 24 lockfile parsers.
Five of them (npm/PyPI/crates/RubyGems/Go) also fetch and scan each dependency's
published source during `ci` and `snapshot enrich`.

## Design

- **Dependency-free domain core** (`aegis-domain`) — risk scoring, verdicts,
  capabilities, fix planning, snapshot diffing, reachability suppression,
  allowlist. Std only.
- **Feature-gated crates** — every lockfile ecosystem, tree-sitter grammar, and
  heuristic behind a Cargo feature; lean builds strip what they don't need:
  ```sh
  cargo build --no-default-features --features npm,pypi,rust
  ```
- **Blocking HTTP** (`ureq`) behind an `HttpClient` trait — mock-tested offline,
  no async coloring, small binary. Record/replay cassettes make network-shaped
  tests deterministic.
- **13 tree-sitter grammars** (js/ts/py/ruby/rust/go/php/csharp/java/haskell/
  lua/gleam/dart, plus cocoapods `.podspec` via the ruby grammar), each an
  ordinary Cargo dependency — no cgo, no vendored toolchain, no build step
  outside `cargo build`.

## Development

```sh
cargo test --workspace                    # 549 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo run -q -p xtask -- analyze-parity   # 36/36 vs Go goldens (offline)
cargo run -q -p xtask -- sbom-parity      # 4/4   vs Go goldens (offline)
cargo run -q -p xtask -- ci-parity        # 6/6   cassette replay (offline)
```

CI runs three blocking jobs: `build-test` (fmt/clippy/test), `lean-build`
(feature-gating guard — a leaked dependency fails here), and `parity`.

The parity harnesses check the Rust scanner against goldens captured from Go
v0.29 for `analyze`, `sbom`, and `ci`. They run offline; `ci-parity` replays a
committed HTTP cassette rather than hitting the network. Re-capture with
`--record` (needs the Go binary) or `--record-cassettes` (needs network).

`PROGRESS.txt` tracks the port in detail — phase status, parity findings, and
what is deliberately not ported.

## Migrating from Go v0.29

The Rust CLI is flat, stateless-by-default, and CI-first. Scanning behavior
(verdicts, scores, capabilities, advisories) is at parity and gated in CI, but
the command surface differs:

| Go v0.29 | Rust |
|---|---|
| `analyze <spec>` (fetch by name) | `explain <name@version>` |
| `analyze <spec> --local <dir>` | `analyze <dir>` |
| `actions scan` (scan workflows for risk) | *not ported* — `actions` **generates** a workflow |
| `allowlist add/remove/test/verify` | *not ported* — `allowlist` dumps the built-in rules read-only |
| `snapshot save/show/diff/enrich/verify/rescan` | same |
| `snapshot submit`, `cloud`, `admin`, `recheck`, `allowlist sync` | *not ported* — cloud-coupled, out of scope |
| `cache`, `audit`, `doctor`, `completion`, `hook uninstall` | *not ported* |

Rust adds commands Go has no analog for: `parse`, `run` (aegis.toml task
runner), `reach`, `snapshot capture`, and `explain`'s capability-catalog mode.

## Security

Report vulnerabilities per [SECURITY.md](SECURITY.md).

aegis is for verifying, protecting, and monitoring software **you are authorized
to assess**. It is not a replacement for authorization.

## License

[Apache-2.0](LICENSE)
