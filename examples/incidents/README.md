# Incident fixtures

Reconstructions of real supply-chain attacks, used by the `analyze` parity gate
(`cargo run -p xtask -- analyze-parity`, 36 fixtures across 13 ecosystems) and
by the end-to-end suite in `crates/aegis-cli/tests/incidents.rs`.

## These are not malware

Every fixture is **synthetic**. Nothing here was copied from a published
malicious package.

- Payload files are hand-written stubs, usually under ten lines, that reproduce
  only the *shape* a detector keys on — an install hook, a `String.fromCharCode`
  chain, a base64-decode-then-eval.
- The three files with executable magic bytes are 31–56 bytes each: an `MZ` or
  `ELF` header followed by ASCII text saying it is a stub. They exist so the
  binary-dropper detector has something to find. They do not run.
  - `npm/ua-parser-js-0.7.29/jsextension.exe`
  - `crates/big_decimal-0.1.5/native/payload.so`
  - `pypi/ultralytics-8.3.41/ultralytics/data/.cache/xmrig.so`
- Exfiltration targets are `attacker.example` (RFC 2606 reserved) or the
  service a given campaign abused, referenced by hostname only. There are no
  live C2 endpoints and no working payload URLs.
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
4. Record the golden: `cargo run -p xtask -- analyze-parity --record` with the
   Go binary available, or hand-write `analyze.golden.json`.
