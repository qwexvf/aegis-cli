# aegis

Supply-chain security scanner for source packages, lockfiles, and container
images. Clean-room Rust port of `aegis-cli`. No CGO, no tokio — pure-Rust,
feature-gated crates, parallel across cores via rayon.

It answers the questions a security engineer actually asks about a dependency:

- Does this package's code do something dangerous? (`analyze` — AST + heuristics)
- Does my lockfile pin a known-vulnerable version? (`ci` — OSV/GHSA)
- How do I fix it? (`fix` — minimal safe version bumps)
- Did this dependency's *behavior* change between versions? (`snapshot` — drift)
- Is a flagged dependency even used? (`reach` / `run` unused-deps)
- What's in this container image? (`image` — tarball or registry pull)

## Install

```sh
cargo install --path crates/aegis-cli      # from this repo
# or
cargo install --git https://github.com/qwexvf/aegis-cli
```

## Commands

| command | what it does |
|---|---|
| `parse <lockfile>` | list a lockfile's dependencies (24 ecosystems) |
| `analyze <dir>` | AST + heuristic scan of a package's source → risk verdict |
| `ci <lockfile>` | CVE gate (OSV + GHSA), fail the build on findings |
| `fix <lockfile>` | version-bump plan + safe upgrade commands |
| `run <aegis.toml>` | parallel fleet scan (ast/heuristics/cve/deprecated/license/unused-deps) |
| `sbom <lockfile>` | CycloneDX 1.5 / SPDX 2.3 SBOM |
| `image <tarball>` / `image --ref <repo:tag>` | scan an OCI image (3 tiers) |
| `snapshot <dir>` | capability fingerprint + behavioral-drift detection |
| `reach <dir> <pkg>` | is a dependency imported (reachable) in JS/TS/Py/… source? |
| `allowlist` | list built-in capability-suppression rules |
| `explain [capability]` | the risk model — capabilities, meaning, score weight |
| `hook [--install]` | git pre-commit hook that scans staged lockfiles |
| `actions` | a GitHub Actions workflow (runs `ci`, uploads SARIF) |

Most reporting commands take `--json`; `ci` and `analyze` also take `--sarif`
(SARIF 2.1.0 for GitHub Code Scanning). Exit codes: `0` clean, `1` findings ≥
threshold, `2` usage/IO error.

## Security workflows

**Block vulnerable dependencies in CI**
```sh
aegis ci package-lock.json --fail-on high        # exit 1 → build fails
aegis ci package-lock.json --sarif > aegis.sarif # → upload to Code Scanning
aegis actions > .github/workflows/aegis.yml      # ready-made workflow
```

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
```

**Detect a maintainer takeover (behavioral drift)**
```sh
aegis snapshot ./pkg-v1 --out baseline.json
aegis snapshot ./pkg-v2 --baseline baseline.json
#   + shell-spawn  (NEW capability — possible takeover)   → exit 1
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

## Design

- **Dependency-free domain core** (`aegis-domain`) — risk scoring, verdicts,
  capabilities, fix planning, reachability suppression, allowlist. Std only.
- **Feature-gated crates** — every lockfile ecosystem, tree-sitter grammar, and
  heuristic behind a Cargo feature; lean builds strip what they don't need.
- **Blocking HTTP** (`ureq`) behind an `HttpClient` trait — mock-tested offline,
  no async coloring, small binary.
- **12 native tree-sitter grammars** (js/ts/py/ruby/rust/go/php/csharp/haskell/
  lua/gleam/dart + cocoapods) — no C toolchain.

Not a replacement for authorization: aegis is for verifying, protecting, and
monitoring software **you are authorized to assess**.
