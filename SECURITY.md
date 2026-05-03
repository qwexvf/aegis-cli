# Security policy

## Supported versions

`aegis-cli` ships from `main`. Patch releases are cut from the latest
minor tag. Security fixes are backported only to the most recent minor
release line — older minors do not receive fixes. Pin to a tagged
release if you depend on this in CI; tracking `main` is fine for
day-to-day developer use but is not under SLA.

| Version    | Supported |
|------------|-----------|
| `main`     | yes (rolling) |
| Latest `vX.Y.*` minor | yes (security fixes backported) |
| Older minors | no |

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability
reporting form for this repo:

  https://github.com/qwexvf/aegis-cli/security/advisories/new

If you cannot use GitHub for any reason, email security@aegis.dev with
"aegis-cli" in the subject line. Encrypt with the maintainer key listed
on https://github.com/qwexvf.gpg if the report contains exploit
details.

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

- The `aegis` binary and any per-PM variant (`aegis-npm`, `aegis-bun`, `aegis-yarn`, `aegis-pnpm`, `aegis-core`)
- Lockfile parsers (npm/bun/yarn/pnpm) — including malicious-input handling
- The JS AST risk engine (tree-sitter integration)
- Allowlist parsing and the layered builtin/user/project precedence
- HTTP clients (npm registry, Aegis API) — TLS handling, retry policy
- Snapshot file format (`aegis.lock`) parsing and verification
- Cache directory permissions and atomic-write logic

Out of scope:

- Vulnerabilities in tree-sitter, Cobra, zstd, or other third-party
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
