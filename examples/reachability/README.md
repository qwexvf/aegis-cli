# Reachability fixtures

Each subdirectory is a self-contained mini-project that demonstrates a
specific behaviour of the reachability layer (depusage import scan +
`Reachability` field on `domain.Dependency` + `[unused]` UI +
`AEGIS_UNUSED_SUPPRESS` risk downgrade).

These differ from `examples/incidents/`: incidents are single-package
malware shapes consumed via `aegis analyze --local`; reachability
fixtures are full projects consumed via `aegis snapshot save && enrich
&& show`.

## Layout

```
examples/reachability/
  cve-in-unused-dep/          # lockfile has a CVE'd dep that user code never imports
    package.json
    package-lock.json
    src/main.js
```

## Smoke-test runner

`tests/e2e/reachability.sh` builds the binary, runs the full
save/enrich/show flow on each fixture, and asserts the expected output
markers. Run via `make test-e2e-reachability` or directly:

```sh
./tests/e2e/reachability.sh
```
