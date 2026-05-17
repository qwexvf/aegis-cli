# Neovim plugin manager — safety spec

What a Neovim plugin manager (packline.nvim, lazy.nvim fork, custom) must
do to ship safe plugins. Designed to compose with `aegis analyze
--ecosystem neovim` and `aegis snapshot` on `lazy-lock.json`.

Sections marked **MUST** are the minimum safe baseline. **SHOULD** are
strong recommendations. **MAY** are opt-in for advanced users.

---

## 1. Source pinning

### 1.1 SHA-pinned by default — MUST

Every plugin entry in the lockfile MUST resolve to a 40-char git commit
SHA. No `branch: "main"` without a paired `commit: "<sha>"`. Floating
branches without SHAs let upstream rewrite history between user's
machine and yours.

```jsonc
// good
{ "telescope.nvim": { "branch": "master", "commit": "abc123…" } }
// bad
{ "telescope.nvim": { "branch": "master" } }
```

### 1.2 Verify on every fetch — MUST

After `git fetch`, before checkout: `git rev-parse HEAD` MUST equal the
SHA in the lockfile. Reject the update if it doesn't. Forces the user
through `:PluginUpdate` (or equivalent) to advance — no silent rev jumps.

### 1.3 Source URL pinning — SHOULD

Lockfile SHOULD record the resolved git URL alongside the SHA. A plugin
that switches from `github.com/foo/bar` to `gitlab.example/foo/bar` w/o
the lockfile changing should fail verification.

### 1.4 Mirror / cache layer — MAY

A self-hosted git mirror (gitea, forgejo, or a local bare repo) cuts
the "upstream force-pushed a malicious commit while users still have
the SHA pinned" attack window from "until everyone updates" to "until
the next mirror sync." Mirror sync runs on a cron with diff alerts.

---

## 2. Capability gate (aegis integration)

### 2.1 Scan before activation — MUST

Before `package.path` / `package.cpath` registers the plugin, the
manager MUST shell out to:

```sh
aegis analyze --ecosystem neovim <plugin-dir> --json --evidence
```

Block plugin load when:

- `verdict` is `block`
- `verdict` is `prompt` AND the plugin is not in the user's allowlist

`verdict` of `review` proceeds with a warning (printed to the user's
status line on first load only — don't spam).

### 2.2 Cache scan results — MUST

Re-running the AST scan on every Neovim launch is wasteful and adds
hundreds of milliseconds. Cache by `(plugin_name, commit_sha)` →
verdict. Invalidate the cache entry only when the commit SHA changes.

Cache location: `vim.fn.stdpath('cache') .. '/aegis/<name>-<sha>.json'`.

### 2.3 First-load vs subsequent loads — SHOULD

First load after install or update SHOULD prompt the user with the
capability summary. Subsequent loads consult the cached verdict
silently. Example UX:

```
[aegis] new plugin telescope.nvim@a4ed6831 detected:
  - shell-spawn        (3 sites)
  - net-egress         (1 site)
  - fs-write-outside-root  (5 sites)
verdict: review  risk=40
allow on this machine? [y/N/details]
```

### 2.4 Detail view — SHOULD

`details` should print file:line evidence (already in the aegis JSON
output under `evidence`). Don't paginate; let the user scroll the
buffer.

---

## 3. Allowlist mechanics

### 3.1 Project-scoped allowlist — MUST

Each Neovim config (per `vim.fn.stdpath('config')`) keeps an allowlist
file. Format mirrors aegis's existing allowlist YAML so the same rules
travel between project (`aegis ci`) and plugin manager use:

```yaml
# ~/.config/nvim/aegis-allowlist.yaml
version: 1
rules:
  - ecosystem: neovim
    name: telescope.nvim
    capability: shell-spawn
    reason: "uses vim.fn.system for fd / rg; expected"
  - ecosystem: neovim
    name: "*"
    capability: env-read
    reason: "vim.env.* is normal for env detection"
```

### 3.2 Allowlist signing — SHOULD

The allowlist file SHOULD be signed (`aegis allowlist sign`) when shared
across machines via dotfiles. Otherwise an attacker who lands in
`~/.config/nvim/` can silently allowlist their own malware.

### 3.3 Per-version pinning — MAY

`version:` field on the rule scopes the allowlist to a single commit SHA.
Catches plugin takeovers where the v1.0 commit was reviewed but a v2.0
backdoor wasn't. Default scope (no version field) covers all versions.

---

## 4. Install / post-install hooks

### 4.1 Treat `build = "..."` strings as install hooks — MUST

Lua plugin specs frequently embed shell:

```lua
{ "nvim-treesitter/nvim-treesitter", build = ":TSUpdate" }
{ "MunifTanjim/prettier.nvim", build = "npm install --frozen-lockfile" }
```

These MUST be surfaced to the user on first install — same prompt UX
as a capability finding. Match aegis's existing `CapInstallHookExec` /
`CapInstallHookSuspicious` heuristics: any of `curl|sh`, `wget|bash`,
`| sudo`, `eval` in a `build` string is a strong signal.

### 4.2 `build` runs in restricted shell — SHOULD

Run `build` commands via `vim.system({...}, { env = limited_env, ... })`
with `$HOME`, `$PATH`, and other secret-bearing env vars stripped or
narrowed. Most plugin `build` steps don't need `$GITHUB_TOKEN` or
`$AWS_SECRET_ACCESS_KEY`.

### 4.3 `build` runs with timeout — SHOULD

A `build` that takes >60s without producing output is hung or
exfiltrating. Kill on timeout. Make the timeout configurable per
plugin (`build_timeout = 300` for treesitter parser builds).

### 4.4 Sandboxed build — MAY

`bwrap` / `firejail` wrapper around `build`. Strips network access by
default. Plugin authors that genuinely need network during build
(downloading parsers, prebuilts) opt in per plugin via a config flag
the user reviews on install.

---

## 5. Update flow

### 5.1 Lockfile diff is mandatory review — MUST

`:PluginUpdate` MUST present the lockfile diff before applying. Same
shape as `git diff lazy-lock.json`. User confirms; no auto-apply.

### 5.2 Re-scan on rev change — MUST

Every plugin whose commit SHA changed in the diff MUST be re-scanned.
Cached verdict is invalidated (per §2.2). If the new scan introduces
new capabilities, prompt the user again with the delta (not the full
list — just what's new).

```
[aegis] telescope.nvim updated: a4ed6831 → 1a2b3c4d
  + new capabilities: net-egress
  details? [y/N]
```

### 5.3 Auto-revert on regression — SHOULD

When the new SHA's verdict is worse than the pinned SHA's verdict
(e.g. `safe` → `block`), the update SHOULD be rejected automatically
with a message linking to the new evidence. User explicitly forces
the update with `--force`.

### 5.4 Drift detection — SHOULD

Out-of-band: a periodic (weekly) job re-fetches every plugin's branch
HEAD and compares to the lockfile SHA. When an installed plugin's
upstream `HEAD` advances past the pinned SHA, surface a "1 plugin
behind upstream" indicator. Doesn't auto-update; just informs.

---

## 6. Manifest / spec parsing safety

### 6.1 Reject `dofile` in plugin specs — MUST

Some plugin managers (lazy.nvim) let users specify plugins via a Lua
table that is executed at startup. That table file MUST be parsed with
`load()` in a restricted env (no `os`, no `io`, no `package`, no
`require`). A malicious dotfiles PR that injects `os.execute("curl ...
| sh")` into the plugin spec must not run.

### 6.2 Spec schema validation — SHOULD

Validate each plugin entry against a schema before processing:

```
plugin: {
  name: string,
  url: string (must start with https://github.com/ or https://gitlab.com/ or ...),
  branch: string (optional),
  commit: string (40 hex chars, required),
  build: string (optional, max length 200),
  ...
}
```

URL allowlist of source hosts MAY be empty for "any URL" but the
schema check itself MUST run.

---

## 7. Visibility / observability

### 7.1 Audit log — MUST

Every plugin install, update, and load decision (allow / block /
prompt-result) is appended to `vim.fn.stdpath('state') .. '/aegis-log.json'`
as one JSON line. Forensic record for "when did this plugin gain
shell-spawn?"

Schema:

```json
{
  "ts": "2026-05-17T08:00:00Z",
  "action": "load|install|update|block",
  "plugin": "telescope.nvim",
  "commit": "abc123...",
  "verdict": "review",
  "capabilities": ["shell-spawn", "fs-write-outside-root"],
  "user_action": "allow|deny|allowlisted"
}
```

### 7.2 `:PluginStatus` command — SHOULD

A buffer-rendered summary: every installed plugin, its pinned SHA, its
latest verdict, allowlist hits, build script presence. Trivial to
implement; high transparency win.

### 7.3 SBOM export — MAY

`:PluginSBOMExport` writes a CycloneDX SBOM of every installed plugin
keyed by `pkg:github/<owner>/<repo>@<sha>`. Composes with the user's
project-level SBOM tooling for compliance.

---

## 8. Threat model — what this guards against

| Threat | Defense |
|---|---|
| Upstream force-push of malicious commit | §1.1 SHA pin, §1.2 verify |
| Plugin author takeover (new maintainer pushes malware) | §5.2 re-scan, §5.3 auto-revert on worsened verdict |
| Drive-by `curl|sh` in `build` field | §4.1 surface, §4.3 timeout, §4.4 sandbox |
| Malicious dotfiles PR injecting plugin spec eval | §6.1 restricted load env |
| Allowlist tampering via local file write | §3.2 sign |
| Capability drift between versions | §5.2 delta prompt |
| User loses track of what's installed | §7 audit log + `:PluginStatus` |

## 9. Threat model — what this does NOT guard against

- A plugin author who is themselves the attacker from day 1 with a
  novel capability not in `aegis-cli`'s taxonomy. Static analysis is
  best-effort; review code you don't recognize.
- Runtime exfil after legitimate-looking AST. `fs-write-outside-root`
  flags `io.open("/tmp/x", "w")` but can't tell `/tmp/x` from
  `/home/user/.ssh/id_rsa.pub`. Pair with OS-level sandboxing.
- Vulnerabilities in the underlying tools (`git`, `lua`, Neovim
  itself). Out of scope for any plugin manager.
- Time-bombed payloads. Static analysis sees the eval; if the malware
  only fires after `Date.now() > 2027-01-01`, the eval looks benign.
  Aegis Cloud sandbox dynamic analysis (planned, see issue #91)
  addresses this.

---

## 10. Minimum viable plugin manager

If you can only ship five things from this spec, ship these:

1. **§1.1 + §1.2** — SHA pinning, verify on fetch
2. **§2.1 + §2.2** — `aegis analyze` on first install + cache results
3. **§3.1** — project-scoped allowlist
4. **§5.1 + §5.2** — lockfile diff prompt, re-scan on rev change
5. **§7.1** — audit log

That's the safe baseline. Everything else is hardening.
