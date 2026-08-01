# Releasing

Releases are cut by pushing a tag. `.github/workflows/release.yml` does the
rest: re-runs the full CI gate against the tagged commit, cross-compiles every
target, signs, attests, and publishes.

## Cut a release

1. Bump `version` in the workspace `Cargo.toml`, then `cargo check` so
   `Cargo.lock` picks it up.
2. Move the `## Unreleased` section of `CHANGELOG.md` under the new version
   heading with today's date.
3. Commit both (`release: v0.X.Y`), push to `main`, and wait for CI to go green.
4. Tag and push:
   ```sh
   git tag v0.X.Y
   git push origin v0.X.Y
   ```

The tag must match the `Cargo.toml` version exactly — the `check-version` job
fails the release otherwise, so a mismatched tag never publishes.

A tag containing a hyphen (`v0.30.0-rc.1`) publishes as a **prerelease** and
does not become "Latest".

## Dry run

`workflow_dispatch` on any branch builds, packages, signs, and attests without
creating a release. Use it after changing the workflow itself — the alternative
is discovering a packaging bug with a tag already pushed.

## Targets

| target | notes |
|---|---|
| `x86_64-unknown-linux-gnu` | |
| `x86_64-unknown-linux-musl` | static; alpine / distroless |
| `aarch64-unknown-linux-gnu` | cross-compiled, not smoke-tested |
| `x86_64-apple-darwin` | cross-compiled on an arm64 runner, not smoke-tested |
| `aarch64-apple-darwin` | |
| `x86_64-pc-windows-msvc` | |

The tree-sitter grammar crates compile vendored `parser.c` through `cc`, so a
new cross target needs a C cross-compiler in the matrix `packages` field, not
just a Rust target triple.

## What ships

Per target: a `.tar.gz` (`.zip` on Windows) containing the `aegis` binary plus
`README.md`, `LICENSE`, `CHANGELOG.md`, `SECURITY.md`.

Alongside them: `checksums.txt`, a cosign keyless signature over it
(`checksums.txt.sig` + `checksums.txt.pem`), and SLSA build provenance
attestations covering every archive and the checksum file.

## Verifying a release

```sh
sha256sum -c checksums.txt --ignore-missing

cosign verify-blob checksums.txt \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-identity-regexp 'https://github.com/qwexvf/aegis-cli/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify aegis-v0.X.Y-x86_64-unknown-linux-gnu.tar.gz --owner qwexvf
```

Keyless signing binds the signature to the release workflow's OIDC identity, so
verification proves the artifact was built by this repo's release job — not
uploaded from someone's laptop. The identity regexp above is the check that
matters; a signature that verifies against a different identity is not ours.

No secrets are required. `id-token: write` and `attestations: write` on the
`publish` job supply the OIDC token, and `GITHUB_TOKEN` creates the release.

## Prior art

Releases at `v0.29.1` and earlier were Go builds cut with GoReleaser from the
[`old`](https://github.com/qwexvf/aegis-cli/tree/old) branch. Their assets and
signatures remain valid; nothing about this pipeline invalidates them.
