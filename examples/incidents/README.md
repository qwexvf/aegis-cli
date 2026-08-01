# Incident fixtures

Reconstructions of real supply-chain attacks, used by the `analyze` parity gate
(`cargo run -p xtask -- analyze-parity`, 27 fixtures across 10 ecosystems). The
end-to-end suite in `crates/aegis-cli/tests/incidents.rs` builds its own
fixtures inline and does not read this directory.

## Nothing here executes

**Hard rule: a fixture must not be runnable.** Detectors work by reading source,
so a fixture never needs to actually do anything.

Nine fixtures were removed for breaking it. Each carried a payload that an
ordinary command would have executed:

| removed | ran on |
|---|---|
| `npm/event-stream-3.3.6` | `npm install` (postinstall) |
| `npm/ua-parser-js-0.7.29` | `npm install` (preinstall, `curl \| sh`) |
| `npm/rc-1.2.9` | `npm install` (preinstall) |
| `npm/coa-2.0.3` | `npm install` (postinstall) |
| `crates/xrvrv-1.0.0` | `cargo build` (build script) |
| `cpan/Moosee-1.0.0` | `perl Makefile.PL` (`system("curl \| sh")`, exfil'd `$GITHUB_TOKEN`) |
| `hackage/textt-0.7.0` | `cabal build` (`callCommand`, same exfil) |
| `go/boltdb-go-1.0.0` | Go `init()` at import — POSTed CI tokens, dropped a chmod+x file |
| `go/dep-confusion-pkg-1.0.0` | Go `init()` at import — fetched a `.so` to `/tmp`, mode 0755 |

Removing them cost three ecosystems: **cpan, hackage, and go no longer have
analyze-parity coverage** (10 remain, down from 13). Restoring them means
rebuilding the fixtures with the payload in a file no toolchain runs — a `.pm`
rather than a `Makefile.PL`, a plain function rather than `init()` — and
re-recording goldens against the Go binary.

No remaining fixture has an install hook, a build script, an import-time
side effect, or any other toolchain entry point. The `setup.py` and `.gemspec`
files that remain are pure metadata. Nothing in this tree runs as a side effect
of `npm install`, `pip install`, `bundle install`, `cargo build`, `go build`,
`cabal build`, or `cpanm`.

The weaker residual: a few library files (Ruby `lib/*.rb`, some `index.js`)
still do fetch-then-`eval` at require time. Those only run if you deliberately
`require`/`import` the fixture into your own program, which no build or test
does — `analyze` only ever reads them as text.

## The rest is synthetic

Every fixture is hand-written. Nothing here was copied from a published
malicious package.

- Payload files are hand-written stubs, usually under ten lines, that reproduce
  only the *shape* a detector keys on — an install hook, a `String.fromCharCode`
  chain, a base64-decode-then-eval.
- The two files with executable magic bytes are 46 and 56 bytes: an `ELF`
  header followed by ASCII text saying it is a stub. They exist so the
  binary-dropper detector has something to find. They do not run.
  - `crates/big_decimal-0.1.5/native/payload.so`
  - `pypi/ultralytics-8.3.41/ultralytics/data/.cache/xmrig.so`
- Exfiltration targets are `attacker.example` (RFC 2606 reserved) or the
  service a given campaign abused. Detectors match on the *host* — a blocklist
  in `crates/aegis-heuristics/src/source_patterns.rs` — so the path never
  matters. Every `pastebin.com` reference therefore points at
  `raw/aegis-test-fixture-not-a-real-paste`.

  This is deliberate: the fixtures previously used short IDs copied from the
  real campaigns (`raw/abc`, `raw/uaparserdrop`). Those return 404 today, but
  they are claimable — anyone creating a paste at one of those IDs would have
  turned a fixture into a live dropper. Do not reintroduce a plausible paste ID.
- Each file opens with a comment naming the incident, the date, and which
  detector it is meant to trigger.

## What that still means for you

Two things are true even though the content is inert:

- **Scanners will flag this directory.** Magic bytes plus filenames like
  `xmrig.so` are exactly what endpoint tooling looks for. A corporate EDR or
  GitHub malware scanning may raise on a clone. That is a false positive, not a
  compromise.
- **The manifests pin known-vulnerable versions on purpose** — that is what the
  advisory assertions check. `.github/dependabot.yml` scopes update PRs to the
  workspace root so those pins do not generate update noise, but Dependabot
  *alerts* are repo-wide and will still surface them. Dismiss them as "used in
  tests" rather than bumping the pins: bumping breaks the parity goldens.

## Running one

```sh
cargo run -q -p aegis-cli -- analyze examples/incidents/rubygems/rest-client-1.6.13 \
  --ecosystem rubygems --name rest-client
```

`analyze` takes a directory — there is no `--local` flag and no package spec,
unlike the Go CLI this corpus was originally captured against.

## Layout

```
examples/incidents/<ecosystem>/<name>-<version>/
  <source files at the paths the published package used>
  analyze.golden.json      # verdict + score + capabilities, captured from Go v0.29
```

## Adding a fixture

1. Create `<ecosystem>/<name>-<version>/` with a manifest and the minimum source
   needed to trigger the detector.
2. Head-comment the incident, the date, and the target detector.
3. Stub any payload. Never commit real malicious code, and never commit a
   working C2 host or payload URL.
4. **No execution paths.** No `preinstall`/`postinstall`/`prepare` scripts, no
   `build.rs`, no `setup.py` that does work at import, no gemspec extension, no
   `Makefile`. If a detector reads a lifecycle hook, put the hook string
   somewhere inert — a fixture that a package manager will run does not belong
   in this tree, however inert the payload looks.
5. Record the golden: `cargo run -p xtask -- analyze-parity --record` with the
   Go binary available, or hand-write `analyze.golden.json`.
