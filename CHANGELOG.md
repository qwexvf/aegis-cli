# Changelog

All notable releases of `aegis-cli`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [SemVer](https://semver.org/).

For binary downloads + cosign + SLSA verification: see the matching [GitHub Release](https://github.com/qwexvf/aegis-cli/releases).

## [0.15.2](https://github.com/qwexvf/aegis-cli/compare/v0.15.1...v0.15.2) (2026-05-11)


### Docs

* drop stale per-pm refs, refresh sizes, document new provenance capabilities ([#60](https://github.com/qwexvf/aegis-cli/issues/60)) ([fa92c02](https://github.com/qwexvf/aegis-cli/commit/fa92c025c767a1345fe4ea67168c07fe3ea4a307))

## [0.15.1](https://github.com/qwexvf/aegis-cli/compare/v0.15.0...v0.15.1) (2026-05-11)


### Fixed

* **release:** split per-pm archives so all four pm tarballs ship ([#58](https://github.com/qwexvf/aegis-cli/issues/58)) ([12f4a66](https://github.com/qwexvf/aegis-cli/commit/12f4a66789eb8aa720af5a13c8bc03dee56667d8))

## [0.15.0](https://github.com/qwexvf/aegis-cli/compare/v0.14.0...v0.15.0) (2026-05-11)


### Added

* maintainer-transfer detector via npm _npmUser ([#46](https://github.com/qwexvf/aegis-cli/issues/46)) ([a5bbc96](https://github.com/qwexvf/aegis-cli/commit/a5bbc96d66ebf2f22d80421157c7d49cd8fe4037))
* tarball-source-drift detector (opt-in via AEGIS_DRIFT=1) ([#45](https://github.com/qwexvf/aegis-cli/issues/45)) ([e56cbe6](https://github.com/qwexvf/aegis-cli/commit/e56cbe602c1201e0735cfaee7353d75895517401))


### Fixed

* scanner noise + pnpm v9 lockfile parser ([#44](https://github.com/qwexvf/aegis-cli/issues/44)) ([79a3730](https://github.com/qwexvf/aegis-cli/commit/79a37307e3cdb5b2bebc0d296a339e60e1a587c8))
* skip drift on truncated github tree ([#48](https://github.com/qwexvf/aegis-cli/issues/48)) ([a58274e](https://github.com/qwexvf/aegis-cli/commit/a58274e0343a7f7998895f2b6903c32881a20047))


### Changed

* restrict tarball-drift to direct deps by default ([#47](https://github.com/qwexvf/aegis-cli/issues/47)) ([63db10e](https://github.com/qwexvf/aegis-cli/commit/63db10e9aa3dd05fb49d4bbfae12a3327edf7fe2))


### Build

* **deps:** bump actions/configure-pages from 5 to 6 ([#37](https://github.com/qwexvf/aegis-cli/issues/37)) ([5d24aa2](https://github.com/qwexvf/aegis-cli/commit/5d24aa2e8b2bf98ed60d7a87f5ea37a636d05574))
* **deps:** bump actions/setup-node from 4 to 6 ([#40](https://github.com/qwexvf/aegis-cli/issues/40)) ([f179cf0](https://github.com/qwexvf/aegis-cli/commit/f179cf0397c5a7fa53205ac44e4ff132c659b16f))
* **deps:** bump actions/upload-pages-artifact from 3 to 5 ([#39](https://github.com/qwexvf/aegis-cli/issues/39)) ([39a57b1](https://github.com/qwexvf/aegis-cli/commit/39a57b1510ebf3f5396a9f430b4f2861c4065391))
* **deps:** bump googleapis/release-please-action from 4 to 5 ([#41](https://github.com/qwexvf/aegis-cli/issues/41)) ([52ca641](https://github.com/qwexvf/aegis-cli/commit/52ca6412ae25f78ab919be1fb892433c3d87b9cf))
* **deps:** bump lodash from 4.17.20 to 4.18.1 in /examples/demo ([#36](https://github.com/qwexvf/aegis-cli/issues/36)) ([3fa07f0](https://github.com/qwexvf/aegis-cli/commit/3fa07f0bf3c7842f21b2892d850cc11dc4703871))
* **deps:** bump lodash in /examples/reachability/cve-in-unused-dep ([#31](https://github.com/qwexvf/aegis-cli/issues/31)) ([a734103](https://github.com/qwexvf/aegis-cli/commit/a73410347b0e720b33f976e3c51d2ed8a0cc03e2))
* **deps:** bump minimist from 1.2.5 to 1.2.6 in /examples/demo ([#34](https://github.com/qwexvf/aegis-cli/issues/34)) ([fceb14c](https://github.com/qwexvf/aegis-cli/commit/fceb14c07a4b5b36f7dd29febd7c0ae3521e2cb1))
* **deps:** bump mlugg/setup-zig from 1 to 2 ([#38](https://github.com/qwexvf/aegis-cli/issues/38)) ([2db285e](https://github.com/qwexvf/aegis-cli/commit/2db285ea649cb60a1cab2f49c2c09ec4dc01efd5))
* **deps:** bump zod in /examples/reachability/cve-in-unused-dep ([#32](https://github.com/qwexvf/aegis-cli/issues/32)) ([b8a49b3](https://github.com/qwexvf/aegis-cli/commit/b8a49b34e2604961e6c894f1758b6581d715d961))


### CI

* add aggregate ci job for branch protection ([#42](https://github.com/qwexvf/aegis-cli/issues/42)) ([3a82705](https://github.com/qwexvf/aegis-cli/commit/3a8270564ef43da4eff16c766380df210aefeaac))

## [0.14.0](https://github.com/qwexvf/aegis-cli/compare/v0.13.0...v0.14.0) (2026-05-08)


### Added

* **astscan:** c#/.NET AST scanner via tree-sitter-c-sharp + nuget lockfile ([0d1b927](https://github.com/qwexvf/aegis-cli/commit/0d1b9270f786f74501e94159f2c8ec35c6aeb70b))
* **diskcache:** per-file usage cache + wire into AnalyzeUsage ([e416400](https://github.com/qwexvf/aegis-cli/commit/e416400c92b638a18c68b9caa14abb868ab59fba))
* **gleam:** add Gleam/Hex ecosystem support ([4e17277](https://github.com/qwexvf/aegis-cli/commit/4e17277d23783f34a773694d2699f1a5108c7045))
* **snapshot:** [unused] marker, --used-only filter, opt-in risk downgrade ([1201e30](https://github.com/qwexvf/aegis-cli/commit/1201e30739f8dbdc4cce1454e080464c83672e64))
* **snapshot:** reachability layer via depusage ([#25](https://github.com/qwexvf/aegis-cli/issues/25) phase 1) ([5b0282b](https://github.com/qwexvf/aegis-cli/commit/5b0282bb84953682f8b2b25028886c6aac3da02a))
* **snapshot:** record UsedSymbols on each Used dep ([3e5b7fa](https://github.com/qwexvf/aegis-cli/commit/3e5b7fa9b8fe5402a113d725a6c73d9345034831))


### Fixed

* **gleamscan:** update fork to use relative include in scanner.c ([1dbb33a](https://github.com/qwexvf/aegis-cli/commit/1dbb33a4f1ac2b3e813327361ca6690dba014926))
* **locksnap:** persist Reachability across snapshot save/load ([829b067](https://github.com/qwexvf/aegis-cli/commit/829b0671256d09ac54df6d6916a3fccf885c96cf))
* **usage:** prefix-match Go module roots when checking import paths ([3502701](https://github.com/qwexvf/aegis-cli/commit/35027018b60a6b80312746a0b0ad89217720a471))


### Docs

* document reachability layer + detection-gap archive ([932fb93](https://github.com/qwexvf/aegis-cli/commit/932fb93a3f513913051328b284b6af4992905459))
* rewrite README, add VHS demo, fix gleamscan queries ([6f26fab](https://github.com/qwexvf/aegis-cli/commit/6f26fab6c2b67005d6da6926c06397cd4c994ecd))


### CI

* **release-please:** revert to GITHUB_TOKEN; document manual re-tag ([5647435](https://github.com/qwexvf/aegis-cli/commit/5647435375381adc16d51575baa186b559887e2f))
* **release-please:** use a PAT instead of GITHUB_TOKEN ([#28](https://github.com/qwexvf/aegis-cli/issues/28)) ([bf38ec9](https://github.com/qwexvf/aegis-cli/commit/bf38ec9213bcb39a4fb6ba8ffa9aeab75eff0dc8))


### Tests

* **e2e:** add 7 more incident fixtures — 30 total across 8 ecosystems ([c24d456](https://github.com/qwexvf/aegis-cli/commit/c24d456d71720cd0a7e1805f2553c980a34af8f2))
* **e2e:** expand incident fixture suite by 6 — famous + recent attacks ([b773398](https://github.com/qwexvf/aegis-cli/commit/b7733986b6931973a5ee86bf0186ffebf0235222))
* **e2e:** reachability fixture — cve-in-unused-dep ([c107d96](https://github.com/qwexvf/aegis-cli/commit/c107d96cbc2a59a160cacf74b353ff8a6607b884))

## [0.13.0](https://github.com/qwexvf/aegis-cli/compare/v0.12.1...v0.13.0) (2026-05-07)


### Added

* thread ctx through long-running file walks + child processes ([bb09043](https://github.com/qwexvf/aegis-cli/commit/bb09043119c41a529080129b19d9f2ea5a9e9315))

## [0.12.1](https://github.com/qwexvf/aegis-cli/compare/v0.12.0...v0.12.1) (2026-05-06)


### Fixed

* **domain:** clamp parseInt at 1e9 to prevent silent int overflow ([f7f9393](https://github.com/qwexvf/aegis-cli/commit/f7f93936115bc15c309874d79aa11fd4ba4f1931))

## [0.12.0](https://github.com/qwexvf/aegis-cli/compare/v0.11.0...v0.12.0) (2026-05-06)


### Added

* **astscan:** java AST scanner via tree-sitter-java + log4j incident fixture ([d392440](https://github.com/qwexvf/aegis-cli/commit/d392440703c915826bc6f2ad6dce6cf492f01c64))
* php AST scanner + maven/composer lockfile parsers ([538a732](https://github.com/qwexvf/aegis-cli/commit/538a732a56a4a084054ae4f04932c4cc9bd8b0f7))


### Docs

* bring site up to date for 5-language scanner / --local / vulnlookup ([6485091](https://github.com/qwexvf/aegis-cli/commit/64850913ddc20f8513e48fea5f885660688b033b))


### CI

* **release:** also fire on 'release: published' for release-please-driven cuts ([79fbf88](https://github.com/qwexvf/aegis-cli/commit/79fbf88c33bb4dab2b2b517b2e6f7e3e92498794))

## [0.11.0](https://github.com/qwexvf/aegis-cli/compare/v0.10.0...v0.11.0) (2026-05-06)


### Added

* **astscan:** go AST scanner via tree-sitter-go + go-module incident fixture ([cb0ffc2](https://github.com/qwexvf/aegis-cli/commit/cb0ffc2db845ab60e326808822e856cf4bdbc7e4))
* **astscan:** rust AST scanner via tree-sitter-rust + 3 crates incident fixtures ([dc581cb](https://github.com/qwexvf/aegis-cli/commit/dc581cba57718c05bfcba1b944e4bc4275c08edf))


### CI

* introduce release-please + zig cache reuse ([3ef0d87](https://github.com/qwexvf/aegis-cli/commit/3ef0d87b2b83bb4d8ab17d9c0b1afa4f7ec2d01a))

## [Unreleased]

## [0.10.0] — 2026-05-06

Ruby AST scanner, real-package fixture testing, and a pluggable vulnerability-lookup interface.

### Added
- **Ruby AST scanner** (`internal/infra/astscan/rbscan/`) — tree-sitter-ruby integration. Detects the same capability set as the JS and Python scanners across RubyGems deps:
  - `shell-spawn`: `system` / `exec` / `spawn` / `fork`, `Kernel.system`, `Process.spawn`, `IO.popen`, `Open3.{popen,capture,pipeline}`, `PTY.{spawn,getpty}`, backticks, `%x{...}`
  - `dynamic-eval`: `eval` / `instance_eval` / `class_eval` / `module_eval`, `send` / `public_send` / `__send__`
  - `base64-decode`: `Base64.{decode64,urlsafe_decode64,strict_decode64}`
  - `net-egress`: `Net::HTTP.*`, `URI.{open,parse,read}`, open-uri, HTTParty / RestClient / Faraday / Excon, raw sockets (`TCPSocket` / `UDPSocket` / `Socket` / `UNIXSocket`)
  - `env-read`: `ENV['NAME']`, `ENV.fetch('NAME')` (literal-key only, with credential-shaped-name filter)
  - `fs-write-outside-root`: `File.open('w'/'a')`, `File.{write,binwrite}`, `IO.write`, `FileUtils.{cp,mv,install,...}`
  - `raw-ip-literal`: `http(s)://NNN.NNN.NNN.NNN` string literals
- **`aegis analyze <spec> --local <dir>`** — skip the registry fetcher and read package source from the on-disk directory at `<dir>`. Enables fixture-based testing and pre-publish self-checks. Spec is still required as a label.
- **`internal/usecase/analyze_local.go`** — directory walker that builds a `PackageSource` like the registry fetcher would. Skips `.git` / `node_modules` / `vendor` / `__pycache__` / `target` / `dist` / `build`. Picks the canonical manifest per ecosystem (handles RubyGems' arbitrary `*.gemspec` filename).
- **`examples/incidents/`** — real-shape fixtures for 10 historical supply-chain incidents (4 RubyGems, 3 PyPI, 3 npm). Each subdirectory mirrors the directory layout of the published-then-yanked malicious package, with the malware payload reduced to its minimum-shape so detectors trigger but the bytes are inert.
- **`tests/e2e/incidents.sh`** — end-to-end harness: runs `aegis analyze --local --json` against every fixture and asserts the expected capabilities. `make test-e2e` is now part of `make precommit`. CI runs it after build-matrix so the published binary is exercised end-to-end on every push.
- **Heuristics in `Analyze.Run`** — the AST scanner pass is now followed by the same heuristic detector set Snapshot.Enrich uses (URL scan, install-hook regex, typosquat, binary dropper, obfuscation patterns). `aegis analyze` and `aegis snapshot enrich` now produce the same capability set on identical input. Disable via `AEGIS_NO_HEURISTICS=1`.
- **`infra/aegisapi.Client.Lookup()`** — implements `usecase.VulnLookup` against `POST /api/v1/vuln/lookup`. Wire format documented inline. Lets the CLI consume an Aegis-managed feed (curated OSV + GHSA + npm advisories + custom curation) once the server endpoint ships.
- **`infra/vulnlookup.Fallback`** — composition helper: try Primary first, fall through to Secondary on error. 5 unit tests cover the failure modes.
- **`AEGIS_VULN_SOURCE` env override** — `osv` / `aegis` / `none` to pin the lookup source explicitly. Default behaviour: when `AEGIS_API_KEY` is set, the Aegis feed is preferred with OSV as fallback; without a key, OSV is used directly (unchanged from v0.9.0).
- **`make precommit` / `make fmt-check` / pre-commit hook** — local CI parity. `scripts/git-hooks/pre-commit` checks staged `.go` files for gofmt issues; `make install-hooks` wires it up. Stops the gofmt-late-discovery loop.

### Changed
- `astscan.isAnalyzable` now routes `.rb` and `.gemspec` files through the Ruby scanner.
- Composition root refactored: a `tryRegister` helper replaces the per-scanner `if err == nil { register } else { warn }` shape (which had `err == nil` as the happy path — a Go anti-pattern). Adding the next non-JS scanner is one line.
- `analyze` command accepts `npm`, `pypi`, `rubygems`, `crates`, `go` ecosystem prefixes (was npm-only). The fetcher path still requires npm; the other ecosystems are usable via `--local`.
- `VulnLookup` interface contract documented with the three implementation paths (OSV, aegisapi, vulnlookup composition helpers).

### Tests
- 738 pass with race detector across 27 packages (+10 from 0.9.0). 10 e2e incident fixtures all pass.

## [0.9.0] — 2026-05-06

Detection-gap roadmap fully closed. Every historical incident in the rogues' gallery (`internal/infra/heuristics/incidents_test.go`) now PASSes — 8 t.Skip blocks lifted across PyPI, RubyGems, and crates.io.

### Added
- **Language-agnostic URL scan** (Plan A) — host-blocklist (pastebin / discord webhooks / telegram bots / ipinfo / cloudflare-dns / ngrok / ...) + IDN-homoglyph detection now runs over `.py`, `.pyi`, `.pyx`, `.rb`, `.gemspec`, `.rs`, and `.go` source, not just JS. New `isAnalyzableSource` gate.
- **Ruby `eval(Net::HTTP.get(...))` detector** (Plan B) — new `rubyObfuscatedPayloadPattern` + `isRubySource` gate covers the canonical Ruby fetch-then-execute idiom (`eval(Net::HTTP.{get,post}(...))`, `eval(open("https://..."))`, `eval(URI.{open,read}(...))`). Catches the 2019 `rest-client` and `strong_password` compromises.
- **Python `exec(urlopen(...))` / `exec(b64decode(...))` detector** (Plan C) — new `pythonObfuscatedPayloadPattern` + `isPythonSource` gate covers `exec`/`eval` of `urllib.request.urlopen`, `urllib2.urlopen`, `requests`/`httpx`/`aiohttp` `.{get,post}`, `base64.b64decode`, `codecs.decode`, and `compile(base64.…)` wrappers.
- **Per-ecosystem typosquat lists** (Plans D + E + F) — `topPackages` is now keyed by `domain.Ecosystem`. Adding an ecosystem = one line + a `top_<eco>_packages.txt` file. New curated lists for PyPI (~120 entries) and crates.io (~80 entries) with cherry-picks for known typosquat targets (`colorama`, `dateutil`, `jellyfish`, `rust_decimal`, `bigdecimal`). Catches 2017 `colourama` and 2022 `rustdecimal`.
- **Cargo `build.rs` install-hook detector** (Plans G + H) — `DetectCargoBuildHook` reuses the existing `scriptMatchesMalwarePattern` set against the contents of `build.rs` when the ecosystem is `EcoCrates`. Catches the 2023 `xrvrv` build-time shell-payload shape.
- **Per-ecosystem binary-dropper carve-outs** (Plans I + J) — `isExpectedNativePath(eco, filename)` recognises canonical "this is supposed to be a binary" packaging shapes. PyPI: CPython ABI-tagged `.so` (`.cpython-*-*.so`, `.abi3.so`), `.pyd`, and bundled-library paths (`<pkg>/.libs/`, `<pkg>/_vendor/`). Crates: no carve-out (legitimate `-sys` crates ship `.a`/`.lib`, the suspicious-extension list never matched those anyway). Catches 2024 `ultralytics` (stray `.so` outside C-extension paths) and 2024 `big_decimal` (precompiled `.so` in a crate).

### Changed
- `DetectTyposquat` no longer hard-gates on `EcoNpm`. Ecosystems without a top-list are silently skipped (no false positives), so adding one is purely additive.
- `DetectBinaryDropper` no longer hard-gates on `EcoNpm`. Same shape — gated on the carve-out function, ecosystems without carve-outs default to "no exception" (everything on the suspicious-extension list flags).

### Tests
- 728 pass with race detector across 26 packages (+53 from 0.8.0). All 20 incident replays in `TestIncidents_*` are now active (was 12 active + 8 skipped).

## [0.8.0] — 2026-05-06

CLI ergonomics + scriptability pass. Signal handling, shell completion, grouped help, and `--json` on every read-only inspection command.

### Added
- **Signal handling** — `aegis` now installs `signal.NotifyContext` for `SIGINT`/`SIGTERM` in `Execute`. Long-running commands (`snapshot enrich`, `ci`, `analyze`, the install gate) cancel cleanly mid-flight instead of dropping HTTP requests. Ctrl-C exits 130 (Unix convention).
- **`aegis completion {bash|zsh|fish|powershell}`** — generates shell completion scripts. Install instructions in the command's `--help`.
- **Grouped help** — `aegis --help` now renders four sections (`Install gate`, `Inspect`, `Configure`, `Maintain`) instead of a flat 14-item list.
- **`--json` output for read-only inspection commands** — for CI scripts that need to parse aegis output:
  - `aegis cache list --json` — emits `[{key, decision, severity, expires_at}, ...]`
  - `aegis audit tail --json` — emits the same snake_case shape as the underlying NDJSON audit log
  - `aegis allowlist list --json` — emits `[{ecosystem, name, version_range, capability, reason, source}, ...]` (composes with `--source` filter)
  - `aegis snapshot show --json` — marshals the saved snapshot directly; respects `--all` for transitive deps
- **`usecase.Snapshot.Load(projectDir)`** — public accessor so callers can render a saved snapshot themselves instead of going through the presenter.

### Changed
- **`NewInstallGate` signature** — 7 positional parameters → `InstallGateDeps` struct. Internal-only (`internal/usecase`), no external API impact.
- **`buildReportRequest`** — 9-parameter signature → internal `reportInputs` struct.
- **`loadDiffOperands`** — 3-case switch body extracted into `loadDiffFromFiles` and `loadDiffSavedVsLive` helpers.
- **`version` subcommand** — `Run` → `RunE`, output via `cmd.OutOrStdout()` for testability.

### Fixed
- **`aegis npm install` exit-code path** — pm wrappers used `os.Exit(1)` directly inside `RunE`, bypassing deferred cleanup and the established `exitCodeError` flow. Now returns a silent exit-code error.
- **`pm` wrapper context** — install gate now runs under `cmd.Context()` instead of `context.Background()`, so Ctrl-C actually cancels the gate.
- **`doctor`/`cache`/`audit` output** — switched from direct `os.Stdout` writes to `cmd.OutOrStdout()` so tests can capture output.
- **Allowlist loader** — removed four `else`-after-return blocks; replaced ad-hoc string concatenation in risk reporting with `strings.Builder`.

### Tests
- 675 pass with race detector across 26 packages (no change in count from 0.7.1 — refactors preserved behaviour).

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
