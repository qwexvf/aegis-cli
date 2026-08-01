# Security policy

## Supported versions

`aegis-cli` ships from `main`, which is now the Rust implementation.
The Go tree it replaced is frozen on the [`old`](https://github.com/qwexvf/aegis-cli/tree/old)
branch; `v0.29.1` was its last release. Patch releases are cut from the
latest minor tag. Security fixes are backported only to the most recent
minor release line — older minors do not receive fixes. Pin to a tagged
release if you depend on this in CI; tracking `main` is fine for
day-to-day developer use but is not under SLA.

| Version    | Supported |
|------------|-----------|
| `main` (Rust) | yes (rolling) |
| Latest `vX.Y.*` minor | yes (security fixes backported) |
| Older minors | no |
| Go `v0.29.*` and earlier, branch `old` | no — frozen, unmaintained |

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability
reporting form for this repo:

  https://github.com/qwexvf/aegis-cli/security/advisories/new

If you cannot use GitHub for any reason, open a discussion in the
[Q&A category](https://github.com/qwexvf/aegis-cli/discussions/categories/q-a)
asking for a private contact channel — do not include exploit details
in the public discussion. Encrypt sensitive details with the
maintainer key listed on https://github.com/qwexvf.gpg before sharing.

Please include:

- Version (`aegis version` output) or commit SHA
- Operating system + architecture
- Reproduction steps
- Impact assessment (what an attacker could achieve)
- Suggested mitigation, if any

## Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgement of report | within 3 business days |
| Initial triage + severity assessment | within 7 business days |
| Fix or mitigation plan | within 30 days for High/Critical |
| Public disclosure | coordinated with reporter; default 90 days |

We follow [coordinated vulnerability disclosure](https://www.cisa.gov/coordinated-vulnerability-disclosure-process).
You will be credited in the release notes and the GitHub Security
Advisory unless you request otherwise.

## Scope

In scope:

- The `aegis` binary, and any lean build produced by disabling default
  Cargo features
- All 24 lockfile parsers (`aegis-lockfile`) — including malicious-input
  handling
- The AST risk engine (`aegis-ast`, 13 tree-sitter grammars) and the
  heuristic detectors (`aegis-heuristics`)
- Allowlist parsing and the layered builtin/user/project precedence
- HTTP clients (`aegis-net`, `aegis-registry`, `aegis-vuln`) — TLS
  handling, retry policy, and the record/replay cassette path
- Archive extraction: package tarballs (`.tgz`/`.tar.gz`/`.gem`/`.whl`/
  `.crate`/module zip) and OCI image layers (`aegis-image`) — path
  traversal, zip-slip, decompression bombs
- Snapshot file format (`aegis.lock`) parsing and verification
- Cache directory permissions and atomic-write logic

Out of scope:

- Vulnerabilities in tree-sitter, clap, ureq, or other third-party
  dependencies (report upstream; we'll bump the dep when a fix lands)
- Vulnerabilities in the *Aegis cloud platform* — those go to the
  separate aegis monorepo's security policy
- Issues that require an attacker to already control the user's
  machine, shell, or filesystem
- Theoretical attacks against the supply chain itself (those are what
  this tool is designed to *detect*; please open a regular issue for
  detection-rule improvements)

## Bounty

There is no monetary bounty program at this time. Public credit and
swag (when available) are the recognition we can offer for good-faith
research.
