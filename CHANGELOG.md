# Changelog

All notable releases of `aegis-cli`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [SemVer](https://semver.org/).

For binary downloads + cosign + SLSA verification: see the matching [GitHub Release](https://github.com/qwexvf/aegis-cli/releases).

## [Unreleased]

## [0.7.1] — 2026-05-04

### Fixed
- **`aegis ci` on no-lockfile projects** — running on a directory without a recognised lockfile (e.g. monorepo roots where lockfiles live in subdirectories) used to print `ci: snapshot vanished after save (this is a bug)` and exit 1. Now PASSes cleanly with 0 deps and a clear info message ("no lockfile found in /path"). Regression test added so this stays fixed.

## [0.7.0] — 2026-05-04

Python AST scanner + curated release notes + advisory column in snapshot show.

### Added
- **Python AST scanner** (`internal/infra/astscan/pyscan/`) — tree-sitter-python integration. Detects the same capability set as the JS scanner across PyPI deps:
  - `shell-spawn`: `subprocess.{run,Popen,check_output,check_call,...}`, `os.{system,popen,exec*,spawn*}`, `pty.spawn`
  - `dynamic-eval`: `eval`, `exec`, `compile`, `__import__`
  - `base64-decode`: `base64`/`codecs`/`binascii` decode functions
  - `net-egress`: `urllib`/`requests`/`httpx`/`aiohttp`/`socket`/`http.client`
  - `env-read`: `os.environ['X']` / `os.environ.get('X')` / `os.getenv('X')` (with credential-shaped name filter)
  - `fs-write-outside-root`: `open(...,'w'/'a')`, `pathlib.Path.write_*`, `shutil.copy*`/`move`
  - `raw-ip-literal`: `http(s)://NNN.NNN.NNN.NNN` URL strings
- **CHANGELOG-driven release notes** — release.yml now extracts the matching CHANGELOG.md section per tag and passes it to `goreleaser release --release-notes`. Falls back to auto-generated notes when the section is missing. `scripts/extract-changelog.sh` is the awk-based extractor.
- **`aegis snapshot show` advisory column** — the rendered table now has CAPS (capability count from AST + heuristics) and ADVISORIES (count + max severity, color-coded) columns. Shows existing data that was being collected since v0.2 but not surfaced.

### Changed
- `astscan.isAnalyzable` recognises `.py` files for `EcoPyPI` deps so the dispatcher routes them to pyscan.
- Composition root (`cmd/aegis/risk_engine.go`) registers the Python scanner alongside the JS one. Best-effort: if pyscan init fails, the rest of the gate keeps working with a stderr warning.

### Tests
- 662 pass with race detector across 25 packages (+41 from v0.6 — all pyscan).
- Pyscan tests cover every capability family with a positive + a negative case (benign code does NOT fire).

### Coverage status
With v0.7, both JS and Python deps get full AST capability detection in addition to OSV vulnerability lookup and the 7 behavior-based heuristics. Rust / Go / Ruby still get OSV + (some) heuristics, but no AST scanner yet.



## [0.6.0] — 2026-05-04

Pluggable lockfile parsers + extension guide.

### Added
- `locksnap.LockfileParser` public interface — third parties can now register a new ecosystem without forking. Pair with `locksnap.Register(p)` from any composition root.
- `locksnap.Registered()` introspection for `aegis doctor`-style reporting.
- `docs/extending.md` — 5-file recipe + interface map + design rules. Targets contributors adding Maven, Composer, Swift, etc.

### Changed
- The built-in lockfile parsers now register through the same public API instead of a package-level function-value table. No behaviour change for end users; opens the surface to external contributors.
- `Scanner.ScanProject` walks the registry instead of a hard-coded slice.

### Tests
- 621 pass with race detector across 24 packages (+4 from v0.5).

## [0.5.0] — 2026-05-04

Maintainer-hijack + patch-version drift detectors. Two new behaviour-based heuristics close the malware-detection gaps the v0.4 set didn't cover.

### Added
- **Heuristic 6: maintainer-hijack score** — fresh publish (< 7d) + long gap from previous version (≥ 180d) + low weekly downloads (< 1000), 2-of-3 fires (`CapMaintainerHijackRisk`, weight 50). Per-dep round-trip to npm registry (full packument + downloads endpoint at api.npmjs.org).
- **Heuristic 7: patch-version capability drift** — `x.y.z → x.y.z+1` that gained capabilities the previous patch didn't have (`CapPatchVersionDrift`, weight 35). Computed at the diff layer.
- `domain.MaintainerSignal` + `usecase.MaintainerSignalFetcher` port. `npmregistry.Resolver.FetchMaintainerSignal` implements it.
- `WithDownloadsURL` option on the npm registry client (self-hosted mirror / httptest).
- Typosquat database expanded from ~150 to ~280 names.

### Tests
- 617 pass (+20).

## [0.4.0] — 2026-05-03

Behavior-based malware heuristics — 5 detectors that fire on shape-of-attack patterns nobody has indexed yet.

### Added
- **Heuristic 1: suspicious install hooks** — postinstall does `curl|sh`, `node -e`, `wget|bash`, base64-piped-to-shell, fetches from Pastebin/Discord webhook/ngrok (`CapInstallHookSuspicious`, weight 70).
- **Heuristic 2: obfuscated payload** — `eval(atob(...))`, `Function(decodeURIComponent(...))`, `require(atob(...))` (`CapObfuscatedPayload`, weight 60).
- **Heuristic 3: suspicious URL targets** — string literals to Pastebin / Discord webhooks / Telegram bots / ngrok / IP-grabbers / IDN-homoglyph hosts (`CapSuspiciousURL`, weight 50).
- **Heuristic 4: binary droppers** — `.exe`/`.dll`/`.so`/`.scpt`/`.ps1` in npm tarballs (`CapBinaryDropper`, weight 35).
- **Heuristic 5: typosquat** — Levenshtein ≤ 2 of a top-150 npm package (`CapTyposquatRisk`, weight 40).
- New package `internal/infra/heuristics/`. Pure-function adapter, no extra fetch cost.
- `usecase.MalwareHeuristics` port + `Snapshot.WithMalwareHeuristics()` setter.
- `AEGIS_NO_HEURISTICS=1` to disable.

### Tests
- 597 pass (+56).

## [0.3.0] — 2026-05-03

Multi-language support — Python, Rust, Go, Ruby.

### Added
- Lockfile parsers: `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock` (PyPI); `Cargo.lock` (crates.io); `go.sum` (Go); `Gemfile.lock` (RubyGems).
- `domain.EcoRubyGems`.
- OSV ecosystem mapping for all five ecosystems.
- Polyglot monorepo support — multiple lockfiles in one project produce a single unified `aegis.lock`.

### Changed
- `usecase.ASTAnalyzer.HasScanner(eco)` port method — non-JS deps gracefully skip the AST stage; OSV vulnerability lookup still applies.
- `Scanner` re-organised around a registry pattern (paved the way for the v0.6 public interface).

### Tests
- 541 pass (+6).

## [0.2.0] — 2026-05-03

Local vulnerability detection without our API.

### Added
- **OSV.dev integration** — every dep cross-referenced against the public OSV vulnerability database. No auth, no signup, no rate limit.
- `domain.Advisory`, `usecase.VulnLookup` port, `Snapshot.WithVulnLookup` setter.
- Two-phase fetch: batch `/v1/querybatch` for IDs, per-ID `/v1/vulns/{id}` for bodies. Disk cache at `~/.aegis/cache/advisories/`.
- Verdict folding: `max(astVerdict, advisoryVerdict)`. Critical/High → block, Medium → prompt, Low → review.
- `aegis ci` text + JSON output gain an "Advisories:" block.
- `AEGIS_OSV_URL` (self-hosted mirror) + `AEGIS_NO_VULN_LOOKUP=1` (offline mode).

### Tests
- 535 pass (+32).

## [0.1.0] — 2026-05-03

First standalone release of `aegis-cli`, extracted from the [qwexvf/aegis](https://github.com/qwexvf/aegis) monorepo.

### Added
- `aegis` CLI binary with subcommands: `npm` / `bun` / `yarn` / `pnpm`, `snapshot`, `ci`, `recheck`, `analyze`, `explain`, `allowlist`, `cache`, `audit`, `hook`, `doctor`, `admin`, `version`.
- Tree-sitter JS AST scanner — 8 capabilities (shell-spawn, dynamic-eval, base64-decode, net-egress, env-cred-read, fs-write-outside-root, raw-ip-literal, install-hook-exec).
- Layered allowlist (builtin + user + project), with `aegis allowlist sync` for org overlay (requires Aegis API).
- NDJSON audit log at `~/.aegis/audit.jsonl`. `AEGIS_OVERRIDE=allow` audited bypass with required `AEGIS_OVERRIDE_REASON`.
- GoReleaser pipeline + cosign keyless OIDC signing of `checksums.txt` + SLSA build provenance attestation. 6 build flavours.
- Six build flavours via Make + GoReleaser: `aegis` (full, JS AST scanner cgo'd in), `aegis-core` (no AST, no cgo), `aegis-{npm,bun,yarn,pnpm}` (per-PM single-tool builds).

### Notes
- The install-gate commands (`aegis npm install …`, `recheck`, `snapshot submit`, `allowlist sync`) require an Aegis API server. The hosted Cloud is not yet available; self-host from the [qwexvf/aegis](https://github.com/qwexvf/aegis) monorepo.

[Unreleased]: https://github.com/qwexvf/aegis-cli/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/qwexvf/aegis-cli/releases/tag/v0.7.1
[0.7.0]: https://github.com/qwexvf/aegis-cli/releases/tag/v0.7.0
[0.6.0]: https://github.com/qwexvf/aegis-cli/releases/tag/v0.6.0
[0.5.0]: https://github.com/qwexvf/aegis-cli/releases/tag/v0.5.0
[0.4.0]: https://github.com/qwexvf/aegis-cli/releases/tag/v0.4.0
[0.3.0]: https://github.com/qwexvf/aegis-cli/releases/tag/v0.3.0
[0.2.0]: https://github.com/qwexvf/aegis-cli/releases/tag/v0.2.0
[0.1.0]: https://github.com/qwexvf/aegis-cli/releases/tag/v0.1.0
