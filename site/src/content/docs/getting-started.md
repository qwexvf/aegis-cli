---
title: Getting started
description: Install aegis and run your first local snapshot in under a minute.
sidebar:
  order: 1
---

## Install

### Pre-built binaries

Download the latest release for your platform from
[Releases](https://github.com/qwexvf/aegis-cli/releases). Artifacts are
signed with [cosign](https://docs.sigstore.dev/cosign/) keyless OIDC and
ship with [SLSA build provenance](https://slsa.dev/). Verify before
running:

```sh
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/qwexvf/aegis-cli/.github/workflows/release.yml.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  checksums.txt
sha256sum -c checksums.txt
gh attestation verify aegis_<version>_linux_amd64.tar.gz --owner qwexvf
```

### From source

Requires Go 1.26 or later.

```sh
go install github.com/qwexvf/aegis-cli/cmd/aegis@latest
aegis version
```

Per-package-manager binaries (`aegis-npm`, `aegis-bun`, `aegis-yarn`,
`aegis-pnpm`) are built from the same source via `make build-<pm>`. They
do not shrink the binary — Go DCE already strips unused PM wrappers — they
exist for distribution clarity.

## First snapshot

These work locally, with no backend, no API key, no cloud account. Drop
the binary on your `$PATH` and run them in any project with a supported
lockfile.

```sh
# Snapshot the resolved dependency tree from the lockfile
aegis snapshot save                    # writes ./aegis.lock

# Walk every package's AST via tree-sitter; populate capability fingerprints
aegis snapshot enrich                  # fills capability scores

# Render
aegis snapshot show                    # direct deps
aegis snapshot show --all              # + transitive
aegis snapshot diff baseline.lock      # detect drift between snapshots
```

## CI gate

```sh
aegis ci --fail-on=block
```

Exits non-zero on any finding at or above the threshold. See
[Cookbook → CI gate](./guides/cookbook/) for full pipeline examples.

## Ad-hoc analysis

```sh
aegis analyze lodash@4.17.21
aegis analyze --evidence ua-parser-js@0.7.29
```

## Allowlist

```sh
aegis allowlist add lodash --capability=dynamic-eval --version='^4' \
    --reason='_.template uses Function() to compile templates'
aegis allowlist list
```

## Where to next

- [Command reference](./reference/commands/) — full flag and exit-code listing
- [Configuration](./reference/configuration/) — env vars, allowlist YAML, CI auto-detection
- [Architecture](./contributing/architecture/) — how the layers fit together
