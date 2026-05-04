---
title: Aegis Cloud
description: The hosted Aegis backend powers verified incidents, snapshot submission, and team allowlist sync. Coming soon.
sidebar:
  order: 99
---

Aegis Cloud is the hosted backend that powers the API-gated commands
flagged with 🌐 in the [command reference](./reference/commands/). It is
not yet available — the CLI ships every check that runs without it
(OSV lookups, AST scanning, capability fingerprints, behavior
heuristics, CI gate, local allowlist) so you can use aegis end-to-end
today against the public OSV feed.

> [!IMPORTANT]
> Aegis Cloud is not deployed yet. Commands marked 🌐 will fail with a
> clear "backend not available" message rather than silently no-op.
> Local-only workflows are unaffected.

## What's planned

- **Verified incidents feed** — curated, deduplicated supply-chain
  incidents with reproduction notes and pinned advisory text. Surfaced
  by `aegis incidents`.
- **`aegis snapshot submit`** — push your `aegis.lock` for centralized
  drift tracking across teams and repos.
- **Hosted allowlist sync** — `aegis allowlist sync` to share
  suppressions across an org without committing them per-repo.
- **`aegis npm install` recheck** — re-validate a package against the
  latest backend signal at install time.

## Status

Not deployed. CLI commands that require the backend currently exit
with a clear "Aegis Cloud not yet available" message rather than
failing silently. Local-only workflows are unaffected.

When the backend goes live, this page will be replaced with auth,
API, and dashboard documentation. Track progress in the
[GitHub repo](https://github.com/qwexvf/aegis-cli).
