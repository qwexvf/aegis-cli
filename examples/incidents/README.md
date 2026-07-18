# Real-world supply-chain incident fixtures

Each subdirectory mirrors the directory shape of a published-and-then-yanked malicious package, with the malware payload reduced to its minimum-shape so detectors trigger but the bytes are inert.

These are **detection-test fixtures**, not working malware. Hosts in URLs use known blocklisted domains the URL scanner already covers (`pastebin.com`, `ipinfo.io`); base64 strings are placeholders.

## Running

```sh
aegis analyze rubygems/rest-client@1.6.13 --local examples/incidents/rubygems/rest-client-1.6.13/ --evidence
```

The `--local` flag skips the registry fetch and reads the source from the on-disk directory. The spec (`rubygems/rest-client@1.6.13`) is still required as a label.

The end-to-end smoke test that runs every fixture and asserts the expected capabilities lives at `tests/e2e/incidents.sh`.

## Layout

```
examples/incidents/
  rubygems/
    rest-client-1.6.13/
    strong_password-0.0.7/
    bootstrap-sass-3.2.0.3/
    paranoid2-1.1.6/
```

Add a fixture by:
1. Creating `<ecosystem>/<name>-<version>/` with the source files at the same paths the published gem/package had.
2. Adding an entry to `tests/e2e/incidents.sh` with the expected capabilities.
