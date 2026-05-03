# Cookbook

End-to-end recipes for the most common ways teams use `aegis`. Pick the one closest to what you're doing and adapt.

If you're new to the CLI, start with [README → Local-only quickstart](../README.md#local-only-quickstart) — it covers the 30-second tour. This file picks up where that leaves off.

> **Status note (v0.1.x):** the Aegis API platform is not yet
> publicly deployed. Recipes below that mark themselves with 🌐
> require a self-hosted Aegis backend; until that platform repo is
> public, those recipes are aspirational. Recipes without 🌐 work
> today with just the CLI binary on your `$PATH`.

## Recipes

**Local-only — work today, no backend:**

- [Snapshot + analyze a Node project](#snapshot--analyze-a-node-project)
- [Run aegis ci in CI (don't slow down developers)](#run-aegis-ci-in-ci-dont-slow-down-developers)
- [Share an allowlist with your team via git](#share-an-allowlist-with-your-team-via-git)
- [Snapshot drift mode — catch deps that grew teeth](#snapshot-drift-mode--catch-deps-that-grew-teeth)
- [Snapshot the dep tree on every PR](#snapshot-the-dep-tree-on-every-pr)
- [Behind a corporate proxy / private registry](#behind-a-corporate-proxy--private-registry)
- [Migrate from npm to pnpm without losing analysis](#migrate-from-npm-to-pnpm-without-losing-analysis)

**🌐 API-dependent — need an Aegis backend (planned, not yet deployed):**

- [🌐 Drop the install gate into a Node project](#-drop-the-install-gate-into-a-node-project)
- [🌐 Audit a block override (the 3am exception)](#-audit-a-block-override-the-3am-exception)
- [🌐 Re-check after an incident DB update](#-re-check-after-an-incident-db-update)

---

## Snapshot + analyze a Node project

Goal: get capability fingerprints + known CVEs for every dep in the project; spot risky packages locally without sending anything to our servers.

```sh
# 1. Install
go install github.com/qwexvf/aegis-cli/cmd/aegis@latest
# or download from https://github.com/qwexvf/aegis-cli/releases

# 2. Snapshot the lockfile (no network)
cd my-node-project
aegis snapshot save                  # writes ./aegis.lock

# 3. AST-scan + vulnerability lookup
aegis snapshot enrich                # AST capabilities + OSV.dev CVE/GHSA matching
aegis snapshot show --all            # render the full table with advisories

# 4. Investigate any single package
aegis analyze ua-parser-js@0.7.29 --evidence
aegis explain lodash@4.17.21
```

`enrich` does two things in one shot: it walks each package's tree-sitter AST for suspicious capabilities AND batch-queries OSV.dev for known vulnerabilities. **OSV.dev is a free public service from Google — no auth, no signup, no backend on our side**. Disable the vuln lookup with `AEGIS_NO_VULN_LOOKUP=1` for fully-offline runs.

The snapshot file (`aegis.lock`, zstd-compressed JSON) is safe to commit. Subsequent `enrich` runs reuse the persistent fingerprint cache (`~/.aegis/cache/fingerprints/`) and the per-advisory cache (`~/.aegis/cache/advisories/`).

---

## Run aegis ci in CI (don't slow down developers)

Goal: developers run plain `npm install` locally; CI fails the build if the AST analysis surfaces a capability that's not allowlisted.

`.github/workflows/ci.yml`:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v5
  with:
    node-version: '20'
- run: npm ci

- name: Install aegis
  run: |
    curl -sSL https://github.com/qwexvf/aegis-cli/releases/download/v0.7.1/aegis-cli_0.7.1_linux_amd64.tar.gz \
      | sudo tar -xz -C /usr/local/bin aegis

- uses: actions/cache@v4
  with:
    path: ~/.aegis/cache
    key: aegis-${{ runner.os }}-${{ hashFiles('package-lock.json') }}

- run: aegis ci --fail-on=block
```

`aegis ci` runs `snapshot save → enrich → score → exit`. The cache step is what makes warm runs fast — only newly-changed deps incur AST scan cost. **No backend required**: the score step uses the local AST findings + local allowlist only.

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

For larger orgs there's also a server-pushed layer (`aegis allowlist sync`) that fetches an org-wide overlay from the Aegis API — see the API-dependent section below for status.

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
          curl -sSL https://github.com/qwexvf/aegis-cli/releases/download/v0.7.1/aegis-cli_0.7.1_linux_amd64.tar.gz \
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

## Behind a corporate proxy / private registry

Goal: company runs Verdaccio at `https://npm.corp.example.com`; developers can't reach the public registry directly.

```sh
# Point version resolution + tarball fetches at the internal registry
export AEGIS_NPM_REGISTRY=https://npm.corp.example.com

# Standard HTTP(S) proxy env vars are honored by Go's net/http
export HTTPS_PROXY=http://proxy.corp.example.com:3128
export HTTP_PROXY=http://proxy.corp.example.com:3128
export NO_PROXY=npm.corp.example.com
```

If your private registry requires auth, configure it the same way you would for `npm` itself (`~/.npmrc` `//npm.corp.example.com/:_authToken=…`) — `aegis` reads tarball URLs from the registry response, so any auth that works for `npm install` works for `aegis snapshot enrich`.

---

## Migrate from npm to pnpm without losing analysis

Goal: switch package managers and keep aegis snapshot/CI working with one command change.

Aegis is package-manager-agnostic — every PM produces a lockfile that aegis can read. After the migration:

```sh
rm aegis.lock package-lock.json
pnpm install                   # generates pnpm-lock.yaml
aegis snapshot save            # detects pnpm-lock.yaml automatically
git add aegis.lock pnpm-lock.yaml
git rm package-lock.json
```

Allowlist rules carry over unchanged — they're keyed by `(ecosystem, name, version, capability)`, not by PM.

---

## 🌐 Drop the install gate into a Node project

> **Requires Aegis API.** The hosted Aegis Cloud is not yet available
> and the platform repo ([qwexvf/aegis](https://github.com/qwexvf/aegis))
> is currently private. Until those land, the install-gate recipe
> below is documented for completeness but won't function for most
> users.

Goal: `npm install` is checked against the incident database before the install proceeds.

```sh
export AEGIS_API_URL=https://your-self-hosted-aegis.example.com

aegis npm install lodash@4.17.21          # /check → allow
aegis npm install ua-parser-js@0.7.29     # /check → block
```

Local-path / git / link installs pass through without an API call:

```sh
aegis npm install ./vendor/foo
aegis bun add link:../sibling
aegis yarn add portal:./local-pkg
```

When the public Aegis API endpoint exists, this section will be updated with the actual URL.

---

## 🌐 Audit a block override (the 3am exception)

> **Requires Aegis API.** Override is only meaningful when there's an API-served block to override against. The audit log itself works locally — see `aegis audit tail`.

Goal: it's an incident, the upstream package is fixed, and you need to install it now. Override but leave a trail.

```sh
AEGIS_OVERRIDE=allow \
AEGIS_OVERRIDE_REASON='incident-1234: tar 7.5.1 patches CVE-2026-XXXX, verified upstream signature' \
  aegis npm install tar@7.5.1
```

Both env vars are required — an empty `AEGIS_OVERRIDE_REASON` is refused. The decision, package, version, reason, and timestamp are all written to `~/.aegis/audit.jsonl` permanently.

Review later (works without API):

```sh
aegis audit tail -n 50               # last 50 entries
aegis audit tail -n 0 | jq '.'       # all, JSON-formatted
aegis audit tail -n 0 | jq 'select(.kind == "override")'   # just overrides
```

The audit log is append-only NDJSON. Don't edit it by hand — it's the only record of "who bypassed what, when, why" for your post-mortem.

---

## 🌐 Re-check after an incident DB update

> **Requires Aegis API.** Hits `/check` per dep against a deployed Aegis backend.

Goal: a new advisory dropped (e.g. a maintainer-handover incident). What in your tree is now blocked?

```sh
aegis recheck                       # re-check direct deps against the updated DB
aegis recheck --all                 # include transitive
aegis recheck --json | jq '.findings[] | select(.verdict == "block")'
```

`recheck` queries `/check` for every dep in the live lockfile and reports any that the API now says are blocked.

Pair with `aegis cache clear` first if you suspect cached `allow` decisions are masking a fresh block:

```sh
aegis cache clear && aegis recheck --all
```

---

## See also

- [README](../README.md) — install, quickstart, full feature overview
- [docs/commands.md](commands.md) — every subcommand and flag (with 🌐 markers)
- [docs/configuration.md](configuration.md) — env vars, file paths, allowlist schema
- [docs/cli-architecture.md](cli-architecture.md) — code layout and how to add a package manager / ecosystem
- [docs/cli-risk-engine.md](cli-risk-engine.md) — capability scoring, allowlist mechanics
- [docs/cli-snapshot.md](cli-snapshot.md) — `aegis.lock` format
