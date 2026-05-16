---
title: Architecture
description: Layered architecture (domain → usecase → interface → presenter → infra), dependency rules, recipe for adding ecosystems.
sidebar:
  order: 1
---


> Audience: anyone modifying the CLI. The shape below is the contract.

## Layered overview

```
┌──────────────────────────────────────────────────────────────────────┐
│ cmd/aegis/main.go              composition root                       │
│   - constructs ALL concrete adapters                                  │
│   - this is the only place that does "new ConcreteThing()"            │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│ internal/interface/cli                                                │
│   - Cobra command tree                                                │
│   - one file per command group: pm/cache/audit/snapshot/allowlist     │
│   - translates argv → use case calls; never speaks domain directly    │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│ internal/usecase                                                      │
│   - InstallGate, Snapshot — orchestration                             │
│   - depends on domain + port interfaces only                          │
│   - never imports infra/                                              │
└──────────────────────────────────────────────────────────────────────┘
                                    │ uses
                                    ▼
                        ┌────────────────────────┐
                        │ internal/usecase ports │
                        │ (interfaces declared    │
                        │  inside usecase/)       │
                        └────────────────────────┘
                                    ▲ implemented by
                                    │
┌──────────────────────────────────────────────────────────────────────┐
│ internal/infra                                                        │
│   - concrete adapters (HTTP, disk, registries, AST scanners, ...)     │
│   - depends on domain only — translates JSON DTOs at the boundary so  │
│     domain types stay pure                                            │
└──────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │
┌──────────────────────────────────────────────────────────────────────┐
│ internal/domain                                                       │
│   - entities (PackageSpec, Decision, Snapshot, Capability, ...)       │
│   - policy (Verdict, Evaluate, RiskScore, DriftScore, AllowSet)       │
│   - PURE — no I/O, no time, no env. The third-party Masterminds       │
│     /semver lib is permitted (CPU-only, no infrastructure)            │
└──────────────────────────────────────────────────────────────────────┘

internal/presenter/cli   sits beside interface/cli. Renders domain.Outcome
                         and usecase.DiffReport into ANSI text. Never
                         imports infra/. Used by interface/cli to print.
```

## Dependency direction

```
cmd      → interface → usecase → domain
                             ↘  ports
                                ↑
                        infra  ─┘   (infra → domain only)
                        presenter → domain (+ usecase types it renders)
```

**Never:**
- `domain → anything else`
- `usecase → infra`
- `interface → infra` directly (uses Deps from cmd)

**OK:**
- `cmd → infra` (it's the wiring layer)
- `cmd → interface` (it builds the command tree)
- `cmd → presenter` (it constructs the renderer)

## Layer responsibilities

| Layer | Owns | Forbidden from |
|---|---|---|
| `domain/` | Entities, value types, pure policy | `os`, `net/http`, `context.Context`, file paths, env vars |
| `usecase/` | Orchestration sequences, port interfaces | Concrete I/O, JSON tags, file paths |
| `interface/cli/` | Cobra wiring, argv → use case calls | Domain logic, scoring, file formats |
| `presenter/cli/` | ANSI text shaping, color, TTY awareness | Decisions, scoring rules |
| `infra/<name>/` | Single-purpose adapters | Cross-adapter coupling, domain rule changes |
| `cmd/aegis/` | Composition root, build-tag-gated wiring | Business logic |

## Directory map (current main)

```
.
├── cmd/aegis/
│   ├── main.go                    composition root
│   └── risk_engine.go             AST scanner wiring (always compiled in)
│
├── internal/
│   ├── domain/                    pure (no I/O)
│   │   ├── spec.go                PackageSpec, Ecosystem
│   │   ├── decision.go            Decision, DecisionKind, Severity, Reason, Source
│   │   ├── policy.go              Action, PolicyContext, Evaluate, ResolvePrompt
│   │   ├── capability.go          Capability enum + CapabilitySet
│   │   ├── install_hook.go        HookPhase, InstallHook
│   │   ├── snapshot.go            Snapshot, Dependency, Fingerprint, SnapshotDelta
│   │   ├── risk.go                RiskScore, DriftScore, Verdict + weights
│   │   ├── allowlist.go           AllowRule, AllowSet, Suppresses, MatchAll
│   │   ├── allowlist_apply.go     RiskAssessment.ApplyAllowlist
│   │   └── builtin_allowlist.go   BuiltinAllowRules() — 20 curated defaults
│   │
│   ├── usecase/                   orchestration + port interfaces
│   │   ├── ports.go               install gate ports
│   │   ├── snapshot_ports.go      snapshot ports + DiffEntry/DiffReport
│   │   ├── install_gate.go        InstallGate.Run
│   │   └── snapshot.go            Snapshot.Save/Show/Diff/Enrich/Verify
│   │
│   ├── interface/cli/             Cobra command tree
│   │   ├── root.go                NewRoot + Deps
│   │   ├── pm_command.go          npm/bun/yarn/pnpm
│   │   ├── cache_command.go       aegis cache list/clear
│   │   ├── audit_command.go       aegis audit tail
│   │   ├── snapshot_command.go    aegis snapshot save/show/diff/enrich/verify
│   │   └── allowlist_command.go   aegis allowlist list/add/remove/test/verify
│   │
│   ├── presenter/cli/             ANSI text rendering
│   │   ├── render.go              base Presenter (color, NO_COLOR, TTY)
│   │   ├── snapshot_render.go     SnapshotPresenter (Outcome, DiffReport)
│   │   └── allowlist_render.go    AllowlistPresenter
│   │
│   └── infra/                     concrete adapters
│       ├── aegisapi/              HTTP DecisionChecker + VulnLookup
│       ├── allowlist/             YAML loader (builtin + user + project)
│       ├── depsdotdev/            deps.dev client (VulnLookup + deprecation)
│       ├── diskcache/             DecisionCache + FingerprintCache + KEV cache
│       ├── envprobe/              CI markers + AEGIS_OVERRIDE/_REASON
│       ├── epss/                  FIRST.org EPSS API client
│       ├── ghsalookup/            GitHub Security Advisories client
│       ├── jspkgsource/           npm tarball fetch + extract
│       ├── kev/                   CISA Known Exploited Vulnerabilities catalog
│       ├── licensefetch/          per-registry license lookup
│       ├── locksnap/              lockfile parsers + snapshot store
│       │   ├── lockfile_npm.go    package-lock.json v1/v2/v3
│       │   ├── lockfile_pnpm.go   pnpm-lock.yaml
│       │   ├── lockfile_yarn.go   yarn.lock classic + berry
│       │   ├── lockfile_bun.go    bun.lock JSONC
│       │   ├── lockfile_pip.go    requirements / Pipfile / poetry / uv
│       │   ├── lockfile_gemfile.go Gemfile.lock
│       │   ├── lockfile_cargo.go  Cargo.lock
│       │   └── lockfile_go.go     go.mod / go.sum
│       ├── ndjsonaudit/           AuditWriter (NDJSON to ~/.aegis/audit.jsonl)
│       ├── npmattestations/       npm SLSA provenance lookup
│       ├── npmregistry/           VersionResolver (npm registry)
│       ├── openvex/               OpenVEX document parser
│       ├── osv/                   VulnLookup against OSV.dev (default)
│       ├── pmwrapper/             PackageManager: npm/bun/yarn/pnpm
│       ├── sarif/                 SARIF 2.1.0 emitter
│       ├── sbomcdx/               CycloneDX + SPDX SBOM builders
│       ├── scan/                  scanner-shaped packages
│       │   ├── ast/               LanguageScanner dispatcher
│       │   │   ├── js/            tree-sitter-javascript + queries.scm
│       │   │   ├── py/            tree-sitter-python
│       │   │   ├── ruby/          tree-sitter-ruby
│       │   │   ├── rust/          tree-sitter-rust
│       │   │   ├── golang/        tree-sitter-go
│       │   │   ├── java/          tree-sitter-java
│       │   │   ├── php/           tree-sitter-php
│       │   │   ├── csharp/        tree-sitter-c-sharp
│       │   │   └── gleam/         tree-sitter-gleam
│       │   ├── actions/           GitHub Actions workflow scanner
│       │   ├── heuristics/        install-hook regex, URL scan, typosquat,
│       │   │                      binary-dropper, hardcoded-secret patterns
│       │   └── drift/             tarball vs upstream git tag drift
│       ├── ttyprompt/             Confirmer (/dev/tty)
│       ├── vulnenrich/            post-lookup EPSS + KEV enrichment
│       └── vulnlookup/            Fallback / MultiSource composers
│
├── Makefile                       build / build-release / size
├── README.md                      user-facing entrypoint
└── go.mod
```

## Adding a new package manager

Goal: support a 5th JS PM, e.g. a hypothetical `nx`.

1. Create `internal/infra/pmwrapper/nx.go`:

```go
type Nx struct{}

func NewNx() *Nx { return &Nx{} }

func (Nx) Name() string                 { return "nx" }
func (Nx) Ecosystem() domain.Ecosystem  { return domain.EcoNpm }
func (Nx) InstallVerb() string          { return "add" }

func (Nx) IsInstallCommand(argv []string) bool {
    return len(argv) > 0 && (argv[0] == "add" || argv[0] == "install")
}

func (Nx) ParseInstallArgs(argv []string) []SpecToken {
    if len(argv) == 0 { return nil }
    return ParseInstallArgsWith(argv[1:], nxTakesValue)
}

func nxTakesValue(flag string) bool { /* nx flags that consume a value */ }

func (Nx) Exec(args []string) error { return execPassthrough("nx", args) }
```

2. `cmd/aegis/main.go`: add `pmwrapper.NewNx()` to the managers slice.
3. Optional: `pmwrapper/nx_test.go` table-driven argv parse cases.

That's it. Domain, usecase, interface, presenter, every other infra
adapter — untouched.

## Adding a new ecosystem (pip / cargo / gem / maven)

Five files under `infra/`, none anywhere else:

| File | Purpose |
|---|---|
| `infra/pmwrapper/<name>.go` | argv parser + `Exec` |
| `infra/<eco>registry/resolver.go` | `usecase.VersionResolver` for the registry |
| `infra/<eco>pkgsource/fetcher.go` | tarball / wheel / crate download + extract |
| `infra/locksnap/lockfile_<name>.go` | parse the lockfile to `[]domain.Dependency` |
| `infra/astscan/<lang>scan/scanner.go` | tree-sitter-<lang> + queries.scm |

Then update:
- `infra/locksnap/scanner.go` — detection priority for the new lockfile
- `infra/astscan/manifest.go` — install-hook detection (e.g. `setup.py` for pypi)
- `cmd/aegis/main.go` — register on the dispatcher

The risk engine, allowlist, snapshot mechanism, presenter — none of
those change. The Capability enum is intentionally language-neutral
(`shell-spawn` is `child_process.exec` in JS, `subprocess.run` in
Python, `Kernel#system` in Ruby — same Capability, three queries).

See `docs/cli-risk-engine.md` for the engine, `docs/cli-snapshot.md`
for the snapshot mechanism.

## Build

One all-in-one binary. Tree-sitter (cgo) is always linked in. `make
build` for a debug build; `make build-release` for a stripped binary
with version ldflags. The AST scanner ships eight tree-sitter grammars
(≈12 MB after strip).
