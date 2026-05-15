#!/usr/bin/env bash
# scripts/fetch-real-incidents.sh
#
# Downloads and neutralizes real malicious packages from public registries
# into examples/incidents-real/. Safe to run locally; NEVER run `npm install`,
# `pip install`, or similar inside these directories.
#
# Requirements: npm, pip, gem, cargo (only those needed for ecosystems you want)
#
# Neutralization:
#   - Real C2 URLs → pastebin.com/raw/NEUTRALIZED (still triggers aegis)
#   - Execute bits stripped from all scripts
#   - Binaries renamed to *.neutralized (binary-dropper shape preserved)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# DEST can be overridden by env (used by Docker where /incidents-real is mounted)
DEST="${DEST:-$ROOT/examples/incidents-real}"

mkdir -p "$DEST"

log() { echo "  $*"; }
ok()  { echo "ok  $1"; }
skip(){ echo "skip $1 (already exists)"; }

# --------------------------------------------------------------------------
# Neutralize: replace real C2 URLs with a safe placeholder that still
# triggers aegis's suspicious-URL detector (pastebin.com is in the blocklist).
# --------------------------------------------------------------------------
neutralize_dir() {
    local dir="$1"
    # Replace any real URL paths with /NEUTRALIZED
    find "$dir" -type f \( \
        -name "*.js" -o -name "*.ts" -o -name "*.mjs" \
        -o -name "*.py" -o -name "*.rb" -o -name "*.sh" \
        -o -name "*.go" -o -name "*.rs" \
    \) | while read -r f; do
        # Keep the suspicious host (still triggers detector) but replace the path
        sed -i \
            -e 's|pastebin\.com/raw/[A-Za-z0-9]*|pastebin.com/raw/NEUTRALIZED|g' \
            -e 's|hastebin\.com/[A-Za-z0-9]*|hastebin.com/NEUTRALIZED|g' \
            -e 's|transfer\.sh/[A-Za-z0-9/._-]*|transfer.sh/NEUTRALIZED|g' \
            -e 's|getsession\.org/[A-Za-z0-9/._-]*|getsession.org/NEUTRALIZED|g' \
            -e 's|discord\.com/api/webhooks/[0-9]*/[A-Za-z0-9_-]*|discord.com/api/webhooks/NEUTRALIZED|g' \
            -e 's|api\.telegram\.org/bot[A-Za-z0-9_:]*/[A-Za-z0-9]*|api.telegram.org/bot/NEUTRALIZED|g' \
            "$f" 2>/dev/null || true
    done

    # Strip execute bits from all scripts
    find "$dir" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.rb" \) \
        -exec chmod -x {} \; 2>/dev/null || true

    # Rename binaries so they can't run but the file shape is preserved
    find "$dir" -type f \( -name "*.so" -o -name "*.dylib" -o -name "*.dll" -o -name "*.exe" \) \
        | while read -r b; do mv "$b" "$b.neutralized"; done

    # Add ignore-scripts for npm fixtures
    if [ -f "$dir/package.json" ] && [ ! -f "$dir/.npmrc" ]; then
        echo "ignore-scripts=true" > "$dir/.npmrc"
    fi

    # Mark as neutralized fixture
    echo "{\"neutralized_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"neutralized_by\":\"fetch-real-incidents.sh\"}" \
        > "$dir/.aegis-fixture.json"
}

# --------------------------------------------------------------------------
# npm
# --------------------------------------------------------------------------
fetch_npm() {
    local name="$1" ver="$2"
    local dir="$DEST/npm/${name//\//_}-$ver"
    [ -d "$dir" ] && { skip "npm/$name@$ver"; return; }
    log "fetching npm $name@$ver"
    local tmp; tmp=$(mktemp -d)
    (cd "$tmp" && npm pack "$name@$ver" --quiet 2>/dev/null)
    mkdir -p "$dir"
    tar -xzf "$tmp/"*.tgz -C "$dir" --strip-components=1 2>/dev/null || \
    tar -xzf "$tmp/"*.tgz -C "$dir" 2>/dev/null
    rm -rf "$tmp"
    neutralize_dir "$dir"
    ok "npm/$name@$ver → $dir"
}

# --------------------------------------------------------------------------
# PyPI
# --------------------------------------------------------------------------
fetch_pypi() {
    local name="$1" ver="$2"
    local dir="$DEST/pypi/$name-$ver"
    [ -d "$dir" ] && { skip "pypi/$name@$ver"; return; }
    log "fetching pypi $name@$ver"
    local tmp; tmp=$(mktemp -d)
    pip download "$name==$ver" --no-deps --no-binary :all: -d "$tmp" -q 2>/dev/null || \
    pip download "$name==$ver" --no-deps -d "$tmp" -q 2>/dev/null
    mkdir -p "$dir"
    local archive; archive=$(ls "$tmp"/*.tar.gz "$tmp"/*.whl 2>/dev/null | head -1)
    if [[ "$archive" == *.whl ]]; then
        unzip -q "$archive" -d "$dir"
    else
        tar -xzf "$archive" -C "$dir" --strip-components=1 2>/dev/null || \
        tar -xzf "$archive" -C "$dir"
    fi
    rm -rf "$tmp"
    neutralize_dir "$dir"
    ok "pypi/$name@$ver → $dir"
}

# --------------------------------------------------------------------------
# RubyGems
# --------------------------------------------------------------------------
fetch_gem() {
    local name="$1" ver="$2"
    local dir="$DEST/rubygems/$name-$ver"
    [ -d "$dir" ] && { skip "rubygems/$name@$ver"; return; }
    log "fetching gem $name@$ver"
    local tmp; tmp=$(mktemp -d)
    (cd "$tmp" && gem fetch "$name" --version "$ver" -q 2>/dev/null)
    mkdir -p "$dir"
    gem unpack "$tmp/$name-$ver.gem" --target "$dir" -q 2>/dev/null || \
        tar -xf "$tmp/$name-$ver.gem" -C "$dir"
    rm -rf "$tmp"
    neutralize_dir "$dir"
    ok "rubygems/$name@$ver → $dir"
}

# --------------------------------------------------------------------------
# Known malicious packages — add entries here as you vet them.
# Source: OSSF Malicious Packages, Socket.dev, Phylum advisories.
# --------------------------------------------------------------------------

echo "=== npm ==="
# Still on registry (verified 2026-05-15)
fetch_npm "node-ipc"           "11.0.0"       # protestware: overwrites files on RU/BY IPs
fetch_npm "@solana/web3.js"    "1.95.5"       # supply-chain hijack: exfil via session.org

# Removed from registry — obtain from OSSF malicious-packages archive manually:
#   https://github.com/ossf/malicious-packages
# fetch_npm "event-stream"     "3.3.6"        # 404 — unpublished
# fetch_npm "ua-parser-js"     "0.7.29"       # 404 — unpublished
# fetch_npm "coa"              "2.0.3"        # 404 — unpublished
# fetch_npm "rc"               "1.2.9"        # 404 — unpublished

echo "=== pypi ==="
# PyPI removed these; obtain from OSSF archive manually:
# fetch_pypi "ctx"             "0.2.2"        # 404 — removed
# fetch_pypi "colourama"       "0.1.6"        # 404 — removed

echo "=== rubygems ==="
# RubyGems removed these; obtain from OSSF archive manually:
# fetch_gem  "rest-client"     "1.6.13"       # 404 — removed
# fetch_gem  "strong_password" "0.0.7"        # 404 — removed
# fetch_gem  "bootstrap-sass"  "3.2.0.3"      # 404 — removed

echo ""
echo "Done. Run: AEGIS_REAL_INCIDENTS=1 make test-e2e"
