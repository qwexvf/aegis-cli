---
title: Extending aegis
description: Pluggable interfaces for lockfile parsers, AST scanners, and heuristics — how to add a new ecosystem.
sidebar:
  order: 3
---


How to add support for a new package ecosystem (Maven, Composer, Swift, …) or a new behavior detector. The CLI is built around a small set of pluggable interfaces — most extensions are 1-5 files and don't touch domain or use-case code.

## TL;DR table

| Want to add… | Implement | Register at | Files needed |
|---|---|---|---|
| New lockfile format | `locksnap.LockfileParser` | `locksnap.Register(p)` (composition root or init) | 1-2 |
| New AST language scanner | `astscan.LanguageScanner` | `dispatcher.Register(eco, s)` | 3-5 (parser, queries, scanner, tests) |
| New vulnerability feed | `usecase.VulnLookup` | `snapshot.WithVulnLookup(...)` | 1 (HTTP adapter) |
| New maintainer-metadata source (PyPI / crates.io) | `usecase.MaintainerSignalFetcher` | `snapshot.WithMaintainerSignalFetcher(...)` | 1 |
| New malware heuristic | `usecase.MalwareHeuristics` (or extend `internal/infra/heuristics/`) | `snapshot.WithMalwareHeuristics(...)` | 1-2 |
| New PM wrapper (`aegis nx install …`) | `pmwrapper.PackageManager` | `cmd/aegis/pm_<name>.go` with `//go:build !no<name>` | 1 |

Every interface is in `internal/usecase/snapshot_ports.go` (or `internal/infra/astscan/scanner.go` for the AST one). Domain types live in `internal/domain/`.

## The most common case: adding a lockfile

Steps to add support for, say, Composer (`composer.lock`, PHP):

### 1. Implement the parser

`internal/infra/locksnap/lockfile_composer.go`:

```go
package locksnap

import (
    "encoding/json"
    "github.com/qwexvf/aegis-cli/internal/domain"
)

type composerLock struct {
    Packages    []composerPkg `json:"packages"`
    PackagesDev []composerPkg `json:"packages-dev"`
}
type composerPkg struct {
    Name    string `json:"name"`
    Version string `json:"version"`
}

func parseComposerLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
    var lf composerLock
    if err := json.Unmarshal(raw, &lf); err != nil {
        return nil, err
    }
    out := make([]domain.Dependency, 0, len(lf.Packages)+len(lf.PackagesDev))
    for _, p := range append(lf.Packages, lf.PackagesDev...) {
        out = append(out, domain.Dependency{
            Ecosystem: domain.EcoComposer, // add this constant in the next step
            Name:      p.Name,
            Version:   p.Version,
            Direct:    true, // composer.lock entries are user-declared
        })
    }
    return out, nil
}
```

### 2. Add the Ecosystem constant

`internal/domain/spec.go`:

```go
EcoComposer Ecosystem = "composer"
```

### 3. Register at startup

If it's a built-in (in-tree), edit `internal/infra/locksnap/builtin_register.go`:

```go
Register(newFuncParser("composer.lock", domain.EcoComposer, parseComposerLock))
```

If it's an out-of-tree extension shipping its own binary, register from your `cmd/your-binary/main.go`:

```go
import "github.com/qwexvf/aegis-cli/internal/infra/locksnap"

func init() {
    locksnap.Register(yourComposerParser{})
}
```

### 4. Map to OSV.dev

`internal/infra/osv/client.go` `osvEcosystem()`:

```go
case domain.EcoComposer:
    return "Packagist"
```

OSV's ecosystem identifiers are documented at <https://google.github.io/osv.dev/data/>.

### 5. Test

`internal/infra/locksnap/lockfile_composer_test.go` — same shape as the existing `lockfile_pip_test.go`. Keep at least one positive case (parses a real-world `composer.lock` snippet) and one edge case (malformed JSON returns error, not panic).

That's it. `aegis snapshot save` now detects `composer.lock`, `aegis snapshot enrich` runs OSV vulnerability lookup against the parsed deps, and the heuristics that don't depend on package source (typosquat, maintainer-hijack via custom adapter) apply automatically.

What's NOT automatic for the new ecosystem until separately implemented:

- AST capability scanning (needs an `astscan.LanguageScanner` for the language — tree-sitter has parsers for most things)
- Maintainer-hijack registry data (needs an adapter against the ecosystem's registry, e.g. `infra/packagistregistry/`)
- Source-pattern heuristics (currently JS-only; per-language equivalents are a follow-on)

## Adding an AST language scanner

Same shape as the lockfile pattern but more code (tree-sitter integration is the bulk).

### Files

```
internal/infra/astscan/<lang>scan/
├── scanner.go          ASTAnalyzer implementation, tree-sitter binding
├── queries/
│   ├── shell.scm       tree-sitter query: subprocess / Command / system
│   ├── eval.scm        eval / Function / exec / compile
│   ├── network.scm     fetch / urllib / Net::HTTP
│   └── ...             one query per Capability you care about
└── scanner_test.go     fixture-based tests (synthetic source, expected caps)
```

The dispatcher pattern lives in `internal/infra/astscan/scanner.go` — your scanner implements `LanguageScanner` (one method, `AnalyzeFile`). Register at startup:

```go
import (
    "github.com/qwexvf/aegis-cli/internal/infra/astscan"
    "github.com/qwexvf/aegis-cli/internal/infra/astscan/pyscan"
)

dispatcher := astscan.NewDispatcher()
dispatcher.Register(domain.EcoNpm, jsscan.New())
dispatcher.Register(domain.EcoPyPI, pyscan.New()) // your new one
```

The risk-engine wiring + capability scoring picks it up unchanged — same `domain.Capability` enum, same `domain.RiskScore`, same allowlist application.

## Out-of-tree extension (don't fork)

You don't need to fork the repo to add an ecosystem. Build your own binary that imports our libraries:

```go
// cmd/aegis-with-composer/main.go
package main

import (
    "github.com/qwexvf/aegis-cli/cmd/aegis"               // (hypothetical: factor main into lib)
    "github.com/qwexvf/aegis-cli/internal/infra/locksnap"

    "github.com/yourname/aegis-composer/parser"
)

func main() {
    locksnap.Register(parser.New())
    aegis.Run() // delegates to the standard CLI command tree
}
```

(Note: the standard binary's `main` is currently not exported; if you want this pattern please open an issue and we'll factor it out.)

## Where things live (one-page map)

```
domain/                                pure types — Capability, Dependency, Advisory, Snapshot
usecase/                               port interfaces + orchestration
  ports.go                              VersionResolver, DecisionChecker, ...
  snapshot_ports.go                     LockfileScanner, ASTAnalyzer, VulnLookup,
                                        MalwareHeuristics, MaintainerSignalFetcher
infra/locksnap/                        LockfileParser interface + parsers + Scanner
infra/astscan/                         ASTAnalyzer + LanguageScanner interface + per-lang scanners
infra/osv/                             OSV.dev VulnLookup adapter
infra/heuristics/                      MalwareHeuristics adapter — 7 detectors
infra/npmregistry/                     VersionResolver + PublishedAtResolver +
                                        MaintainerSignalFetcher (npm only)
cmd/aegis/                             composition root — only place that constructs adapters
```

## Design rules (to keep extensions clean)

1. **No infra → infra imports.** Every adapter only depends on `domain` and `usecase`. If two infra packages need to share something, lift it into domain.
2. **No `context.Context` in domain.** Domain stays pure: no I/O, no env reads, no time. Helpers like `splitSemver` belong in domain; HTTP clients don't.
3. **Use the port interface, not concrete types, in use-case code.** `Snapshot.WithVulnLookup` takes the interface; the npm/PyPI/crates.io adapter all satisfy it without the use case knowing.
4. **Capabilities are additive.** Adding a new `domain.Capability` is safe — old snapshots decode with the new value unset, scoring picks it up via the new `case` in `RiskScore`.
5. **Best-effort heuristics — never fail the gate on a flaky signal.** The hijack-fetcher errors silently zero the signal; doesn't fail enrich. Same for advisory lookup.

## Tests

Every parser ships a table-driven test of:

- 1-2 happy-path fixtures (verbatim output from the actual tool)
- 1-2 edge cases (empty, malformed, with comments)
- 1 negative case (skips entries we can't act on — unpinned versions etc.)

Plus, if you add a Capability, add a `domain` test for the scoring branch.

## Questions / proposing a new pluggable surface

Open an issue at <https://github.com/qwexvf/aegis-cli/issues/new/choose>. We'd rather grow the interface set than have downstreams fork.
