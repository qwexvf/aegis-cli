#!/usr/bin/env bash
# Run the exact CI matrix locally before pushing. Mirrors .github/workflows/ci.yml
# (build-test + lean-build + parity). If this passes, CI should too.
#
#   scripts/ci-local.sh          # all jobs
#   scripts/ci-local.sh fast     # skip parity (the slow goldens)
#
# Keep in sync with ci.yml — if you change one, change the other.
set -euo pipefail
cd "$(dirname "$0")/.."

bold() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# ── build-test job ─────────────────────────────────────────────────────────
bold "format"
cargo fmt --all --check

bold "clippy (-D warnings)"
cargo clippy --workspace --all-targets -- -D warnings

bold "test"
cargo test --workspace

# ── lean-build job ─────────────────────────────────────────────────────────
# Each feature-gated crate must compile with default features OFF and only a
# minimal feature set on. Catches a leaked optional dep or a missing
# #[cfg(feature = ...)] that a full-featured build hides.
bold "lean feature builds"
cargo build -p aegis-lockfile --no-default-features
cargo build -p aegis-lockfile --no-default-features --features npm
cargo build -p aegis-lockfile --no-default-features --features maven
cargo build -p aegis-lockfile --no-default-features --features hex
cargo build -p aegis-lockfile --no-default-features --features conda
cargo build -p aegis-ast --no-default-features
cargo build -p aegis-ast --no-default-features --features js
cargo build -p aegis-ast --no-default-features --features cocoapods
cargo build -p aegis-ast --no-default-features --features kotlin
cargo build -p aegis-ast --no-default-features --features elixir
cargo build -p aegis-heuristics --no-default-features
cargo build -p aegis-heuristics --no-default-features --features secrets
cargo build -p aegis-heuristics --no-default-features --features install-hook
cargo build -p aegis-heuristics --no-default-features --features maintainer
cargo build -p aegis-sbom --no-default-features
cargo build -p aegis-sbom --no-default-features --features cyclonedx
cargo build -p aegis-pkgbuild --no-default-features
cargo build -p aegis-registry --no-default-features
cargo build -p aegis-registry --no-default-features --features npm
cargo build -p aegis-net --no-default-features
cargo build -p aegis-net --no-default-features --features cassette
cargo build -p aegis-net --no-default-features --features "ureq-backend cassette"

# ── parity job ─────────────────────────────────────────────────────────────
if [ "${1:-}" != "fast" ]; then
  bold "parity (offline goldens)"
  cargo run -q -p xtask -- analyze-parity
  cargo run -q -p xtask -- sbom-parity
  cargo run -q -p xtask -- ci-parity
fi

# ── engine-reach feature (optional; needs network to fetch the ripple git dep) ─
# Not part of ci.yml today, but the feature must still build. Skipped if the
# git dep can't be fetched offline.
if [ "${1:-}" != "fast" ]; then
  bold "engine-reach feature build (best-effort)"
  cargo build -p aegis-cli --features engine-reach || \
    echo "  (skipped: engine git dep not fetchable — needs network)"
fi

bold "ALL GREEN"
