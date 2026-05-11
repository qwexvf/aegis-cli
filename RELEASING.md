# Releasing

Single command:

```sh
git tag v0.X.Y && git push origin v0.X.Y
```

That's it. `release.yml` fires on the tag push and the rest is automatic.

## What runs automatically

1. **goreleaser** builds the binaries:
   - `aegis_<ver>_linux_amd64.tar.gz` (cgo, full AST scanner)
   - `aegis-core_<ver>_<os>_<arch>` × 6 (linux / darwin / windows × amd64 / arm64, no cgo)
2. **goreleaser** writes the release body — groups commits since the
   previous tag into `Features` / `Bug fixes` / `Documentation` / `Other`
   based on the conventional-commit prefix (see `.goreleaser.yaml`
   → `changelog:`).
3. **cosign** keyless OIDC signs `checksums.txt` → ships
   `checksums.txt.pem` + `checksums.txt.sig`.
4. **`actions/attest-build-provenance`** writes a SLSA attestation
   over every tarball + the checksum file.
5. The GitHub Release is published.

Total wall-clock: ~5 minutes.

## Picking the version

Follow [semver](https://semver.org):

- `v0.X.(Y+1)` — bug fix or doc-only change
- `v0.(X+1).0` — new feature or behaviour change
- `v(X+1).0.0` — breaking change

When in doubt, look at what landed since the previous tag:

```sh
git log --oneline v0.15.2..HEAD
```

A `feat:` commit → minor bump. A `fix:` commit → patch bump. Multiple
of both → minor bump. A `BREAKING CHANGE:` footer → major bump.

## Verifying the release

After the workflow completes:

```sh
gh release view v0.X.Y
gh release download v0.X.Y -p 'aegis-cli_*_linux_amd64.tar.gz' \
                          -p 'checksums.txt' \
                          -p 'checksums.txt.sig' \
                          -p 'checksums.txt.pem'

cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/qwexvf/aegis-cli/.github/workflows/release.yml.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  checksums.txt

sha256sum -c checksums.txt --ignore-missing
gh attestation verify aegis-cli_<ver>_linux_amd64.tar.gz --owner qwexvf
```

## If the build fails

The tag is still pushed but the release has no assets. Fix forward:

```sh
# 1. fix the bug in main (via PR)
# 2. retag at the new HEAD
git fetch origin
gh release delete v0.X.Y --cleanup-tag --yes
git tag v0.X.Y origin/main
git push origin v0.X.Y
```

The new push fires `release.yml` again.

## Local sanity check before tagging

```sh
go test ./...
goreleaser check
goreleaser release --snapshot --clean   # dry-run, builds into ./dist
```

`--snapshot` skips the signing + publish steps, so it works offline
without `GITHUB_TOKEN` / cosign.
