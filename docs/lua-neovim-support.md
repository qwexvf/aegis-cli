# Lua / Neovim plugin support — implementation plan

Concrete plan for adding Lua AST scanning + Neovim plugin support to
aegis-cli. Every file/line reference verified against the codebase at
v0.26.0.

---

## Today's gaps

- AST scanners cover 9 languages (`internal/infra/scan/ast/{csharp,gleam,golang,java,js,php,py,ruby,rust}`). **No Lua.** Pure-Lua plugins produce zero capability findings.
- `domain.Ecosystem` (`internal/domain/spec.go:25-39`) enumerates registry namespaces (npm, pypi, crates, …). **No identifier** for git-distributed plugins.
- `aegis analyze` and `aegis snapshot` both expect a recognised manifest at root. Neovim plugins have none.

---

## v1 — minimum useful slice

Three landable pieces. Total realistic effort: **3-4 days**.

### P0 — Lua tree-sitter capability scanner

Mirror `internal/infra/scan/ast/gleam/` — the smallest reference scanner today (109 LOC `scanner.go` + 103 LOC `scanner_test.go` + 65 LOC `queries.scm`).

**Files to add:**

- `internal/infra/scan/ast/lua/scanner.go`
- `internal/infra/scan/ast/lua/queries.scm`
- `internal/infra/scan/ast/lua/scanner_test.go`

**Files to edit:**

- `go.mod` — add `github.com/tree-sitter-grammars/tree-sitter-lua` (MIT, community-maintained). Pin to a tag, not a branch.
- `internal/infra/scan/ast/scanner.go:216` (`isAnalyzable`) — add the Lua case:
  ```go
  case domain.EcoNeovim:
      if strings.HasSuffix(path, "_spec.lua") || strings.HasSuffix(path, "_test.lua") {
          return false
      }
      return strings.HasSuffix(path, ".lua")
  ```
- `cmd/aegis/risk_engine.go:55-57` — append next to the existing `tryRegister` calls:
  ```go
  tryRegister("Lua", domain.EcoNeovim, func() (ast.LanguageScanner, error) { return lua.New() })
  ```

**queries.scm — capture targets (all reuse existing `domain.Capability` values):**

| Lua pattern                                                  | Capability                  |
|--------------------------------------------------------------|-----------------------------|
| `os.execute`, `io.popen`                                     | `CapShellSpawn`             |
| `vim.fn.system`, `vim.system`, `vim.fn.jobstart`             | `CapShellSpawn`             |
| `loadstring`, `load`, `loadfile`, `dofile`                   | `CapDynamicEval`            |
| `vim.cmd` with non-literal arg, `vim.api.nvim_exec`/`nvim_exec2` | `CapDynamicEval`        |
| `require("socket.http")`, `require("ssl.https")`             | `CapNetEgress`              |
| `vim.loop.new_tcp`, `vim.uv.new_tcp`                         | `CapNetEgress`              |
| `os.getenv`                                                  | `CapEnvRead`                |
| `io.open(_, "w"\|"a"\|"wb"\|"ab")`, `vim.fn.writefile`       | `CapFSWriteOutsideRoot`     |
| `ffi.load`, `package.cpath` write                            | `CapInstallHookExec`        |
| Raw IPv4 in string literal                                   | `CapRawIPLiteral`           |
| Pastebin / Discord webhook URL literal                       | `CapSuspiciousURL`          |

**No new capabilities for v1.** Adding a `domain.Capability` ripples through risk scoring (`internal/domain/risk.go`), allowlist matching (`internal/domain/allowlist*.go`), CycloneDX builder (`internal/infra/sbomcdx/cyclonedx.go`), JSON output, and the allowlist YAML schema (Cloud contract — per `CLAUDE.md` would need `../aegis` schema bump first). Fold `ffi.load` / `package.cpath` into `CapInstallHookExec` for now; revisit `CapNativeBinding` in v1.1 if the FP rate warrants it.

**Taint-flavored captures deferred.** `string.char(...) → load(...)` and `vim.api.nvim_exec(http_response)` need intra-procedural dataflow; tree-sitter queries don't do that, and no existing scanner has a taint pass. Punt to v1.1 with a stub query that matches `load(_)` calls and tags non-literal-arg cases at high FP rate, behind a `--lua-taint` flag.

Realistic effort: **1-2 days** including queries, tests, and grammar quirk handling (`obj:method()` vs `obj.method(self)`, multi-return semantics, string-call sugar `f"x"`).

---

### P0b — Ecosystem identifier

Pick **one** addition to `internal/domain/spec.go:25-39`:

```go
EcoNeovim    Ecosystem = "neovim"
```

**Why not `EcoGit` (generic git-distributed)?** Helm charts, Terraform modules, and Neovim plugins all share the raw-git distribution model — but they need different AST scanners, different lockfile parsers, and different OSV behavior. Generic `EcoGit` collapses the dispatch axis. Better to add one ecosystem per scanner-class and treat the distribution model as orthogonal metadata.

**Why not extend `EcoGo`?** Go modules carry registry-style semantics (proxy, sumdb). Repurposing it for Neovim loses that.

**Why not Option B (`EcoLuaRocks` + `EcoNeovim`)?** OSV.dev does have a LuaRocks ecosystem key, but Neovim plugins almost never come from LuaRocks. Ship `EcoNeovim` only in v1. Add `EcoLuaRocks` if/when a real user pulls rockspec-distributed deps through aegis.

Touch sites for the new constant: `internal/domain/spec.go` only. No other domain code switches on the full ecosystem list — `EcoNeovim` is allowed to be "the static-only path" until vuln data exists.

---

### P0c — Local-path scan without a manifest

`AnalyzeRequest.LocalPath` (`internal/usecase/analyze.go:80`) already supports analyzing a directory tree without going through the registry fetcher — the `--local` flag uses it today.

What's needed is **not** a new `--bare` mode. What's needed is:

1. **Skip manifest requirement for `EcoNeovim`.** In the local-path code path that builds `PackageSource`, when the ecosystem is `EcoNeovim` accept `Manifest: nil` (the field is already optional in the struct — see `groupPackageSources` in image scanner which sets it from `package.json`/`composer.json`/`pyproject.toml` when present).

2. **Skip registry fetch.** Already implicit — `LocalPath != ""` does this.

3. **Skip Name/Version validation for `EcoNeovim`.** Currently `analyze` requires `<pkg-spec>` syntax. For Neovim, derive Name from the directory basename and Version from the git HEAD SHA at `LocalPath` (or empty if not a git repo).

**Files to edit:**

- `internal/usecase/analyze.go` — relax `Name`/`Version` validation when `Ecosystem == EcoNeovim && LocalPath != ""`. Derive both from the path/git.
- `internal/interface/cli/analyze_command.go` — accept `--ecosystem neovim` paired with a directory positional, no `<name>@<version>` spec required.

Realistic effort: **4-6 hours.** Tests reuse the existing `examples/incidents/` fixture pattern.

---

## v1 invocation

```sh
# Scan a local Neovim plugin checkout
aegis analyze --local ./packer.nvim --ecosystem neovim

# Output: capability findings only. No --enrich integration (no OSV ecosystem).
```

---

## v1.1 — lockfile ingestion

So `aegis snapshot` can treat `lazy-lock.json` (lazy.nvim) as input the same way it treats `package-lock.json`. `lazy-lock.json` is dominant; `nvim-pack-lock.json` is rarer and can wait.

**Files to add:**

- `internal/infra/locksnap/lazy_lock.go` — implements `locksnap.LockfileParser` mirroring `internal/infra/locksnap/package_lock_v3.go` shape.

`lazy-lock.json` schema:

```json
{
  "<plugin-name>": { "branch": "main", "commit": "<sha>" }
}
```

Maps to `[]domain.Dependency{ {Ecosystem: EcoNeovim, Name: "<plugin-name>", Version: "<sha>"}, ... }`.

**Files to edit:**

- `internal/infra/locksnap/registry.go` (or wherever parsers self-register) — register the new parser so `lazy-lock.json` joins the autodiscovery list `aegis image scan` and `aegis snapshot` already walk.

No domain or usecase changes — `Snapshot` is already polymorphic over ecosystem.

Realistic effort: **1 day.**

---

## v1.2 — Neovim-specific heuristics

Domain-layer additions, no AST work:

- **`build = "curl|sh"` in plugin spec.** `internal/infra/scan/heuristics/install_hook.go` already has `CapInstallHookSuspicious` patterns for `curl|sh` / `wget|bash`. Add a Lua spec parser that extracts the `build` string and feeds it into that scanner. Mirrors how npm `scripts` blocks feed the same scanner today.
- **Rev-jump on unpinned spec.** When a plugin in `lazy-lock.json` has no pinned version (`branch: "main"`) and the commit SHA changes between snapshots, emit a drift warning. Lives in `internal/infra/scan/drift/`.

---

## v1.3 — SBOM with git provenance

`internal/infra/sbomcdx/cyclonedx.go` emits PURLs like `pkg:npm/foo@1.2.3`. For `EcoNeovim` deps, PURL spec supports `pkg:github/owner/repo@<sha>`. Add an emitter case keyed on `EcoNeovim`. Falls back to `pkg:generic/<name>?vcs_url=...&commit_id=<sha>` when source URL isn't a github.com repo.

---

## v2 — punted

- **Taint analysis** (`string.char(...) → load(...)`, `vim.api.nvim_exec(http_response)`). Real value but no taint infrastructure exists today; build it cross-cutting (JS would benefit too) instead of Lua-only.
- **LuaRocks rockspec parser + `EcoLuaRocks`.** Low traffic in Neovim land. Land only when a user pulls a rockspec-distributed dep through aegis.
- **`CapNativeBinding` as a first-class Capability.** Wait for the FP rate on the v1 `CapInstallHookExec` mapping to justify the Cloud-schema ripple.
- **AST scanning of `.vim` files.** Vimscript plugin surface is shrinking; Lua coverage closes 95%+.
- **`aegis ci` semantics inside a plugin repo.** Define if/when a user requests it.
- **`aegis image scan` interaction.** If a devcontainer ships `/opt/<plugin>/init.lua`, does the manifest walker (v0.26.0+) recognise it? Edge case — revisit only if requested.

---

## Honesty about the value prop

Lua/Neovim plugins have effectively zero CVE coverage in OSV.dev. `aegis snapshot --enrich` on a `lazy-lock.json` returns nothing useful. The product value for this slice is:

1. **AST capability findings** on plugin source (P0)
2. **Install-hook scanner** for `build = "curl|sh"` patterns (v1.2)
3. **Drift detection** on unpinned plugins (v1.2)
4. **SBOM emission** for downstream tooling (v1.3)

That's a static-analysis-only path. Be explicit about it in user-facing docs so nobody expects a CVE list to appear.

---

## Critical path

```
v1 (3-4 days, shippable):
  P0   Lua tree-sitter scanner (no new caps, no taint)
  P0b  EcoNeovim constant
  P0c  Skip manifest requirement for EcoNeovim + --local

v1.1 (1 day):
  lazy-lock.json parser + registration

v1.2 (1-2 days):
  build = "curl|sh" heuristic
  Rev-jump drift detection

v1.3 (4-6 hours):
  pkg:github PURL emitter

v2: revisit punted items above.
```

That's ~6 days of work end to end to turn aegis-cli from "no signal on Neovim plugins" into "static-analysis-grade coverage for Lua/Neovim plugins, lazy.nvim-aware."

---

## Appendix A — vim.pack lockfile reference

Verified against Neovim 0.12.2 (`/usr/share/nvim/runtime/lua/vim/pack.lua`). Path: `$XDG_CONFIG_HOME/nvim/nvim-pack-lock.json` (resolved at `pack.lua:231`). Written via `vim.json.encode(lock, { indent = '  ', sort_keys = true })` (`pack.lua:831`). Two-space indent, keys sorted, trailing `\n`.

### Top-level shape

```json
{
  "plugins": {
    "<plugin-name>": { /* entry */ }
  }
}
```

Plugin name = `name` field from user spec if present, else basename of `src` URL.

### Entry fields

| Field     | Type   | Notes                                                                                              |
|-----------|--------|----------------------------------------------------------------------------------------------------|
| `src`     | string | Git remote URL. Source of truth for reinstall (`pack.lua:710`).                                    |
| `rev`     | string | 40-char SHA. `git rev-parse HEAD` after install/update (`pack.lua:690`). Always present once installed. |
| `version` | string | Serialized user spec. Tag/branch/SHA strings stored quote-wrapped (`"'v1.0'"`); `vim.version.range(...)` stored as its `tostring()` form (e.g. `"^1.0"`). Absent when user did not pass `version`. |

### Concrete example

```json
{
  "plugins": {
    "mini.icons": {
      "rev": "f8f9d34c2a1bc0e4e9f5d3a2b7c1e9f0d4a5b6c7",
      "src": "https://github.com/echasnovski/mini.icons"
    },
    "nvim-lspconfig": {
      "rev": "a1b2c3d4e5f6789012345678901234567890abcd",
      "src": "https://github.com/neovim/nvim-lspconfig",
      "version": "'v2.0.0'"
    },
    "nvim-treesitter": {
      "rev": "9876543210fedcba9876543210fedcba98765432",
      "src": "https://github.com/nvim-treesitter/nvim-treesitter",
      "version": "^0.10"
    }
  }
}
```

### Semantics

- Lockfile entry's `rev` overrides `version` resolution at startup — reproducible installs across machines (`pack.lua:1296`).
- `lock_repair` (`pack.lua:840-848`) reconstructs `rev` + `src` from disk for entries lost from the JSON. `version` is NOT reconstructable — must come from user spec.
- Entries with corrupted disk state and unrepairable lock data are deleted (`pack.lua:940`).
- Plugins listed in lockfile but missing from disk → auto-installed at recorded `rev`.

### vim.pack-lock vs lazy-lock comparison

Both formats are JSON pin maps but the schemas differ enough to warrant separate parsers in `internal/infra/locksnap/`:

| Aspect              | `nvim-pack-lock.json` (vim.pack)  | `lazy-lock.json` (lazy.nvim) |
|---------------------|-----------------------------------|------------------------------|
| Top level           | `{ "plugins": { ... } }`          | Flat: `{ "<name>": {...} }`  |
| Commit field        | `rev`                             | `commit`                     |
| Source URL          | `src` (recorded)                  | Not recorded                 |
| Version spec        | `version` (quote-wrapped strings) | `branch` only                |
| Source of `<name>`  | spec.name or basename of `src`    | Plugin manager's own key     |

The v1.1 parser slot for `nvim-pack-lock.json` therefore needs:

1. Walk `lock["plugins"]` instead of the root object.
2. Read `rev` instead of `commit`.
3. Strip the outer single-quote wrapping from string `version` values before display: JSON `"'v1.0'"` → Lua source `'v1.0'` → tag `v1.0`.
4. Emit `domain.Dependency{ Ecosystem: EcoNeovim, Name: <key>, Version: <rev>, SourceURL: <src> }`.

`lazy-lock.json` parser (v1.1 primary target, since lazy.nvim is the dominant manager today) skips items 1–3 entirely — flat schema, `commit` field, no embedded URL — but loses the `SourceURL` field on every entry.

---

## Appendix B — packline.nvim integration notes

`packline.nvim` (`/home/qwexvf/projects/packline.nvim/`, internal project; renamed to `pakku.nvim` post-v0.2) is the canonical first consumer:

- Delegates lockfile ownership entirely to `vim.pack` — packline never writes it. Parser written against vim.pack schema works against packline-managed configs unchanged.
- Calls `aegis actions scan` + `aegis sbom --local` per plugin path via `vim.system` (async, fire-and-forget). When `EcoNeovim` lands, the `sbom` invocation should switch to `--ecosystem neovim` so the bare-path code path activates.
- `policy.lua` already enforces host allowlist + HTTPS-only at spec-add time. Mirrors `internal/domain/allowlist.go` semantics in aegis — a future enhancement is to load the same YAML allowlist file from both sides.
- Default branch warning (`require_pinned_version = true` in pakku) lines up with v1.2's "rev-jump on unpinned spec" drift heuristic. Same signal, different layer: pakku warns at config time, aegis warns at snapshot diff time.
