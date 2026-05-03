# Cookbook

End-to-end recipes for the most common ways teams use `aegis`. Pick the one closest to what you're doing and adapt.

If you're new to the CLI, start with [README → Quickstart](../README.md#quickstart) — it covers the 30-second tour. This file picks up where that leaves off.

## Recipes

- [Drop aegis into a Node project locally](#drop-aegis-into-a-node-project-locally)
- [Run aegis only in CI (don't slow down developers)](#run-aegis-only-in-ci-dont-slow-down-developers)
- [Share an allowlist with your team via git](#share-an-allowlist-with-your-team-via-git)
- [Audit a block override (the 3am exception)](#audit-a-block-override-the-3am-exception)
- [Snapshot drift mode — catch deps that grew teeth](#snapshot-drift-mode--catch-deps-that-grew-teeth)
- [Behind a corporate proxy / private registry](#behind-a-corporate-proxy--private-registry)
- [Self-host the Aegis decision API](#self-host-the-aegis-decision-api)
- [Snapshot the dep tree on every PR](#snapshot-the-dep-tree-on-every-pr)
- [Migrate from npm to pnpm without losing the gate](#migrate-from-npm-to-pnpm-without-losing-the-gate)
- [Re-check after an incident DB update](#re-check-after-an-incident-db-update)

---

## Drop aegis into a Node project locally

Goal: `npm install` is gated by `aegis` for me but the rest of the team isn't affected yet.

```sh
# 1. Install
go install github.com/qwexvf/aegis-cli/cmd/aegis@latest
# or download from https://github.com/qwexvf/aegis-cli/releases

# 2. Point at a backend (the public one is fine for evaluation)
echo 'export AEGIS_API_URL=https://api.aegis.dev' >> ~/.zshrc

# 3. Try it (should be a no-op for safe packages)
aegis npm install lodash@4.17.21

# 4. Try a known-bad one (will block)
aegis npm install ua-parser-js@0.7.29

# 5. (optional) shell alias so muscle memory keeps you safe
echo "alias npm='aegis npm'" >> ~/.zshrc
```

Removing the alias removes the gate. No project file changes; nothing in version control. Your team is unaffected until they opt in.

---

## Run aegis only in CI (don't slow down developers)

Goal: developers run plain `npm install` locally; CI fails the build if anything risky lands in the lockfile.

`.github/workflows/ci.yml`:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v5
  with:
    node-version: '20'
- run: npm ci

- name: Install aegis
  run: |
    curl -sSL https://github.com/qwexvf/aegis-cli/releases/download/v0.1.0/aegis-cli_0.1.0_linux_amd64.tar.gz \
      | sudo tar -xz -C /usr/local/bin aegis

- uses: actions/cache@v4
  with:
    path: ~/.aegis/cache
    key: aegis-${{ runner.os }}-${{ hashFiles('package-lock.json') }}

- run: aegis ci --fail-on=block
```

`aegis ci` runs `snapshot save → enrich → score → exit`. The cache step is what makes warm runs fast — only newly-changed deps incur AST scan cost.

For a copy-paste template see [examples/ci/github-actions.yml](../examples/ci/github-actions.yml). Same pattern with platform-specific install for [GitLab](../examples/ci/gitlab-ci.yml) and [generic shell](../examples/ci/generic.sh).

---

## Share an allowlist with your team via git

Goal: every developer (and CI) sees the same `lodash._.template uses Function()` exception.

```sh
# Anyone with shell access can add a project rule
aegis allowlist add lodash \
    --capability=dynamic-eval \
    --version='^4' \
    --reason='_.template uses Function() to compile templates' \
    --scope=project

# Writes ./.aegis-allowlist.yaml — commit it
git add .aegis-allowlist.yaml
git commit -m 'allowlist: lodash._.template uses Function (legitimate)'
```

`--scope=project` is the key. The default `--scope=user` writes to `~/.aegis/allowlist.yaml` which is per-developer and gitignore-able. Project rules apply for everyone who clones the repo.

Verify what's active:

```sh
aegis allowlist list                    # all sources
aegis allowlist list --source=project   # just yours
aegis allowlist test npm/lodash@4.17.21 # which rules suppress what
```

For larger orgs there's also a server-pushed layer (`aegis allowlist sync`) that fetches an org-wide overlay from the Aegis API — see the org allowlist endpoint documentation.

---

## Audit a block override (the 3am exception)

Goal: it's an incident, the upstream package is fixed, and you need to install it now. Override but leave a trail.

```sh
AEGIS_OVERRIDE=allow \
AEGIS_OVERRIDE_REASON='incident-1234: tar 7.5.1 patches CVE-2026-XXXX, verified upstream signature' \
  aegis npm install tar@7.5.1
```

Both env vars are required — an empty `AEGIS_OVERRIDE_REASON` is refused. The decision, package, version, reason, and timestamp are all written to `~/.aegis/audit.jsonl` permanently.

Review later:

```sh
aegis audit tail -n 50               # last 50 entries
aegis audit tail -n 0 | jq '.'       # all, JSON-formatted
aegis audit tail -n 0 | jq 'select(.kind == "override")'   # just overrides
```

The audit log is append-only NDJSON. Don't edit it by hand — it's the only record of "who bypassed what, when, why" for your post-mortem.

---

## Snapshot drift mode — catch deps that grew teeth

Goal: `lodash 4.17.20 → 4.17.21` is fine. `lodash 4.17.21` newly containing `child-process` is **not** fine. Catch only the second case.

```sh
# 1. Save a baseline (e.g. the lockfile from your last release)
git checkout v1.4.0 -- package-lock.json
aegis snapshot save
mv aegis.lock baseline.lock
git checkout main -- package-lock.json

# 2. Save the current snapshot
aegis snapshot save

# 3. Diff
aegis snapshot diff baseline.lock
```

Or wire it into CI as a one-liner — only fails when a version-changed dep actually grew new capabilities:

```sh
aegis ci --baseline=baseline.lock --fail-on=block
```

`--baseline` doesn't touch your `aegis.lock` — it's a read-only comparison. The output highlights:

- **upgraded** — version went up; may or may not have new capabilities
- **drift** (subset of upgraded) — version went up AND capability set changed → high signal
- **downgraded** — version went down (uncommon; usually a rollback)
- **added / removed** — straightforward

---

## Behind a corporate proxy / private registry

Goal: company runs Verdaccio at `https://npm.corp.example.com`; developers can't reach the public registry directly.

```sh
# Point version resolution + tarball fetches at the internal registry
export AEGIS_NPM_REGISTRY=https://npm.corp.example.com

# Standard HTTP(S) proxy env vars are honored by Go's net/http
export HTTPS_PROXY=http://proxy.corp.example.com:3128
export HTTP_PROXY=http://proxy.corp.example.com:3128
export NO_PROXY=npm.corp.example.com,api.aegis.corp.example.com

# Decision API is separate from the npm registry — usually internal
export AEGIS_API_URL=https://aegis.corp.example.com
```

If your private registry requires auth, configure it the same way you would for `npm` itself (`~/.npmrc` `//npm.corp.example.com/:_authToken=…`) — `aegis` reads tarball URLs from the registry response, so any auth that works for `npm install` works for `aegis npm install`.

---

## Self-host the Aegis decision API

Goal: don't send your dep list to a SaaS. Run the Aegis platform on your own infra.

```sh
# Clone the platform monorepo (separate from this CLI repo)
git clone https://github.com/qwexvf/aegis
cd aegis

# Boot the stack (Postgres + API + orchestrator + web UI)
docker compose up -d

# Web UI on :3000, GraphQL API on :4000
open http://localhost:3000

# Point your CLI at it
export AEGIS_API_URL=http://localhost:4000
aegis doctor    # confirm reachability
```

The CLI talks to the same `POST /api/v1/supply-chain/check` endpoint regardless of whether you're hitting hosted Aegis or your self-hosted instance. The wire shape is documented in the platform repo.

For a hardened production install (TLS, secrets, persistent Postgres), see the platform repo's `docs/production-deployment.md`.

---

## Snapshot the dep tree on every PR

Goal: every PR includes a refreshed `aegis.lock`; a stale lockfile is treated as a bug.

`.github/workflows/snapshot.yml`:

```yaml
on:
  pull_request:
    paths:
      - 'package-lock.json'
      - 'bun.lock'
      - 'yarn.lock'
      - 'pnpm-lock.yaml'

jobs:
  refresh-snapshot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          curl -sSL https://github.com/qwexvf/aegis-cli/releases/download/v0.1.0/aegis-cli_0.1.0_linux_amd64.tar.gz \
            | sudo tar -xz -C /usr/local/bin aegis
      - run: aegis snapshot save
      - run: |
          if ! git diff --exit-code aegis.lock; then
            echo "::error::aegis.lock is stale. Run 'aegis snapshot save' locally and commit."
            exit 1
          fi
```

The same pattern works for `aegis snapshot enrich` if you want capability fingerprints in the committed file (slower CI, richer file).

---

## Migrate from npm to pnpm without losing the gate

Goal: switch package managers and keep aegis working with one command change.

```sh
# Before:                       After:
aegis npm install               aegis pnpm install
aegis npm install foo           aegis pnpm add foo
```

Aegis is package-manager-agnostic — every PM hits the same decision API and the same snapshot store. Your existing `aegis.lock` is per-PM (the lockfile parser detects which PM wrote the source lockfile), so after the migration:

```sh
rm aegis.lock package-lock.json
pnpm install                   # generates pnpm-lock.yaml
aegis snapshot save            # detects pnpm-lock.yaml automatically
git add aegis.lock pnpm-lock.yaml
git rm package-lock.json
```

Allowlist rules carry over unchanged — they're keyed by `(ecosystem, name, version, capability)`, not by PM.

---

## Re-check after an incident DB update

Goal: a new advisory dropped (e.g. a maintainer-handover incident). What in your tree is now blocked?

```sh
aegis recheck                       # re-check direct deps against the updated DB
aegis recheck --all                 # include transitive
aegis recheck --json | jq '.findings[] | select(.verdict == "block")'
```

`recheck` queries `/check` for every dep in the live lockfile and reports any that the API now says are blocked. Useful both ad-hoc ("is the new node-ipc thing in our tree?") and on a daily cron ("alert if anything we ship has flipped to BLOCK").

Pair with `aegis cache clear` first if you suspect cached `allow` decisions are masking a fresh block:

```sh
aegis cache clear && aegis recheck --all
```

---

## See also

- [README](../README.md) — install, quickstart, full feature overview
- [docs/commands.md](commands.md) — every subcommand and flag
- [docs/configuration.md](configuration.md) — env vars, file paths, allowlist schema
- [docs/cli-architecture.md](cli-architecture.md) — code layout and how to add a package manager / ecosystem
- [docs/cli-risk-engine.md](cli-risk-engine.md) — capability scoring, allowlist mechanics
- [docs/cli-snapshot.md](cli-snapshot.md) — `aegis.lock` format
