# Contributing to aegis-cli

Thanks for considering a contribution. This file is short on purpose —
the codebase enforces conventions through linting, tests, and CI, not
through documentation.

## Before you start

- For non-trivial changes, **open an issue first** to discuss the
  approach. PRs that arrive without prior discussion may be closed if
  the direction doesn't fit the project's scope. Bug fixes and small
  improvements don't need an issue.
- Read [SECURITY.md](SECURITY.md) — security issues go through private
  disclosure, not pull requests.
- `PROGRESS.txt` is the working record of the Go → Rust port: phase
  status, parity findings, and what is deliberately not ported. Check it
  before proposing something that looks missing — it may be a scoping
  decision rather than a gap.

## Local setup

Requires a recent stable Rust toolchain and a working C compiler (the
tree-sitter grammar crates compile vendored `parser.c` via `cc` — the
same `cc` cargo already uses to link).

```sh
cargo build
./target/debug/aegis --help
```

## Workflow

1. Fork or create a topic branch off `main`.
2. Make the change. Keep commits focused — a fix is one commit, a
   refactor is one commit.
3. **Every feature ships with its test in the same commit.** This is the
   project's one hard rule.
4. Run what CI runs:
   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo run -q -p xtask -- analyze-parity
   cargo run -q -p xtask -- sbom-parity
   cargo run -q -p xtask -- ci-parity
   ```
   All must pass before opening the PR. Enable the pre-push hook once per clone
   to run the fast subset (fmt + clippy + test) automatically on `git push`:
   ```sh
   git config core.hooksPath .githooks
   ```
   Bypass it for a single push with `git push --no-verify`.
5. Open the PR against `main`. Squash-merge is the default.

## Architecture

```
aegis-cli (bin)
  ├── aegis-domain      risk scoring, verdicts, capabilities, snapshot diff
  ├── aegis-lockfile    24 lockfile parsers
  ├── aegis-ast         13 tree-sitter grammars + .scm queries
  ├── aegis-heuristics  detector functions
  ├── aegis-reach       import / used-symbol / call-graph reachability
  ├── aegis-net         HttpClient trait, ureq backend, disk cache, cassettes
  ├── aegis-vuln        OSV / GHSA / EPSS / KEV
  ├── aegis-registry    per-ecosystem source + metadata fetchers
  ├── aegis-sbom        CycloneDX / SPDX / SARIF emitters
  └── aegis-image       OCI tarball + registry pull
```

Two rules the review enforces:

- **`aegis-domain` stays dependency-free.** Std only. Wire types and
  serde DTOs live in the CLI, not the domain.
- **Network goes through the `HttpClient` trait**, never `ureq` directly.
  That is what makes offline tests and cassette replay possible.

## Feature gating

Every lockfile ecosystem, tree-sitter grammar, and heavy heuristic sits
behind a Cargo feature, all on by default. A lean build must not pull in
what it didn't ask for:

```sh
cargo build --no-default-features --features npm,pypi,rust
```

The `lean-build` CI job compiles each library crate with
`--no-default-features` plus isolated optional features. A leaked
dependency or a missing `#[cfg]` fails there — add the gate, don't
loosen the job.

## Adding an ecosystem

1. `crates/aegis-lockfile/src/<eco>.rs` — the parser, behind a feature.
2. Register it in `crates/aegis-lockfile/src/lib.rs` detection order.
3. Parser tests in the same file.
4. For enrichment (fetch + scan the published source), add a fetcher to
   `crates/aegis-registry/src/pkgsource.rs` and list the ecosystem in
   `scan::is_enriched_ecosystem`.
5. For reachability downgrade, add an import parser to `aegis-reach` and
   list the ecosystem in `scan::reachability_eligible`.

## Adding a tree-sitter grammar

1. Optional dependency on the grammar crate in `crates/aegis-ast/Cargo.toml`,
   behind a feature.
2. `crates/aegis-ast/queries/<lang>.scm` — port the query verbatim if one
   exists in the Go tree on the [`old`](https://github.com/qwexvf/aegis-cli/tree/old)
   branch.
3. Two tests per grammar: the query compiles, and it detects a known
   capability.

## Parity harnesses

`xtask` compares the Rust scanner against goldens captured from Go
v0.29. If you change scanning behavior and a gate goes red, that is the
gate working — either the change is a bug, or it is a deliberate
divergence that needs a golden refresh and a note in `PROGRESS.txt`.

- `--record` re-captures goldens (needs the Go binary built from `old`).
- `--record-cassettes` re-captures the `ci-parity` HTTP cassette (needs
  network). Commit the cassette; CI has no network.

Rust-ahead behavior — where Rust deliberately does more than Go — cannot
be covered by a Go golden, so it gets a dedicated unit test instead.

## Commit messages

- Short, lowercase first word, imperative mood, no trailing period.
- One line when it fits. State what changed plainly.
- Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `ci:`,
  `refactor:`) are welcome but not enforced. Breaking changes get a `!`.

## Code style

- `cargo fmt` and `cargo clippy -D warnings` are the source of truth. If
  you disagree with a lint, propose the config change in a separate PR —
  don't add `#[allow]` without one.
- Comment *why*, not *what*. Variable names beat comments.
- Errors returned to the user are plain strings with enough context to
  act on; internal plumbing uses `Result<_, String>` consistently rather
  than a bespoke error enum per crate.

## Reviewing

Review takes a few days for small PRs, longer for architectural changes.
We don't merge anything that hasn't been read by a second human, even
from a maintainer.

## License

All contributions are accepted under [Apache-2.0](LICENSE) (the same
license as the repo). By opening a PR you assert that you have the
right to contribute the code under that license.
