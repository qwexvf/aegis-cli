#!/usr/bin/env bash
# Zero-day demo: a local malicious package that does NOT exist in any
# CVE / advisory feed. The Aegis AST risk engine flags it on its own
# merits.
#
# Flow:
#   1. Start a tiny mock npm registry that serves pkg/ as
#      @aegis/zero-day-demo@1.0.0.
#   2. Run `aegis snapshot save` against the project (uses the
#      hand-written package-lock.json that pins our package).
#   3. Run `aegis snapshot enrich` with AEGIS_NPM_REGISTRY pointed at
#      the mock — fetches the tarball, runs the AST scanner, writes
#      Fingerprints into aegis.lock.
#   4. Run `aegis snapshot show --all` so you can inspect the verdict.
#
# Usage:  ./scripts/zero-day-demo/run.sh

set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
AEGIS="${AEGIS:-$ROOT/bin/aegis}"

if [ ! -x "$AEGIS" ]; then
  echo "==> building aegis (no binary at $AEGIS)"
  (cd "$ROOT" && make build)
fi

REGISTRY_PORT="${REGISTRY_PORT:-18080}"
REGISTRY_URL="http://localhost:${REGISTRY_PORT}"
PROJECT="$HERE/project"

echo "==> starting mock npm registry on :${REGISTRY_PORT}"
PORT="$REGISTRY_PORT" "$HERE/mock-registry.sh" >/tmp/aegis-zero-day-registry.log 2>&1 &
REG_PID=$!
trap 'kill $REG_PID 2>/dev/null || true' EXIT

# Wait for the registry to come up.
for _ in $(seq 1 25); do
  if curl -fsS -o /dev/null "$REGISTRY_URL/@aegis%2fzero-day-demo"; then
    break
  fi
  sleep 0.1
done

# Use an isolated cache so previous runs don't shadow the fetch.
CACHE_DIR="$(mktemp -d)"
export AEGIS_CACHE_DIR="$CACHE_DIR"
export AEGIS_NPM_REGISTRY="$REGISTRY_URL"
trap 'kill $REG_PID 2>/dev/null || true; rm -rf "$CACHE_DIR"' EXIT

cd "$PROJECT"

echo
echo "==> aegis snapshot save (parses package-lock.json)"
"$AEGIS" snapshot save

echo
echo "==> aegis snapshot show"
"$AEGIS" snapshot show --all

echo
echo "==> aegis snapshot enrich (fetch tarball from mock registry, run AST scanner)"
"$AEGIS" snapshot enrich

echo
echo "==> aegis snapshot show --all (post-enrich, capabilities populated)"
"$AEGIS" snapshot show --all

echo
echo "==> aegis snapshot diff /dev/null aegis.lock (forces a verdict on every dep)"
# Empty baseline → every dep is treated as Added → RiskScore is shown.
echo '{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","aegis_version":"demo","project":"empty","deps":[]}' > /tmp/aegis-empty.lock
"$AEGIS" snapshot diff /tmp/aegis-empty.lock "$PROJECT/aegis.lock" || true
rm -f /tmp/aegis-empty.lock

# Optional: push the analyzed deps to a real Aegis API as community
# reports. The submit endpoint is gated by AEGIS_API_KEY (server-issued
# via `aegis admin gen-key` + an INSERT into submit_api_key). This demo
# defaults to running against the mock registry only — it does NOT hit
# the API. To actually submit, set both AEGIS_API_URL (a real API) and
# AEGIS_API_KEY before running this script. Without them we skip
# cleanly so the demo stays self-contained and offline.
if [ -n "${AEGIS_API_URL:-}" ] && [ -n "${AEGIS_API_KEY:-}" ]; then
  echo
  echo "==> aegis snapshot submit (AEGIS_API_KEY is set — sending to $AEGIS_API_URL)"
  "$AEGIS" snapshot submit || true
else
  echo
  echo "==> skipping snapshot submit (set AEGIS_API_URL + AEGIS_API_KEY to enable)"
fi

echo
echo "==> done. inspect aegis.lock and the marker files in /tmp/aegis-zero-day-*"
