#!/usr/bin/env bash
# tests/e2e/reachability.sh — end-to-end smoke for the reachability
# layer. For each fixture under examples/reachability/, copies it to a
# temp dir, runs save/enrich/show, and asserts that the right deps
# carry the [unused] marker.
#
# Why a copy: snapshot save writes aegis.lock into the project dir,
# which we don't want to leave under examples/.
#
# Run with:
#   ./tests/e2e/reachability.sh
#   AEGIS=/path/to/aegis ./tests/e2e/reachability.sh
#   AEGIS_SKIP_BUILD=1 ./tests/e2e/reachability.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AEGIS="${AEGIS:-$ROOT/bin/aegis}"

if [ "${AEGIS_SKIP_BUILD:-}" != "1" ]; then
    echo "building aegis -> $AEGIS"
    (cd "$ROOT" && go build -o "$AEGIS" ./cmd/aegis)
fi
if [ ! -x "$AEGIS" ]; then
    echo "no aegis binary at $AEGIS; set AEGIS=path or unset AEGIS_SKIP_BUILD"
    exit 1
fi

# Disable network: the fixture lockfiles point at real packages, but
# we don't want to actually download tarballs in CI. The AST scanner's
# best-effort behavior on a missing source is "skip" — fingerprint
# stays empty but reachability still works.
export AEGIS_NO_VULN_LOOKUP=1

PASS=0
FAIL=0
TMPROOT="$(mktemp -d)"
trap 'rm -rf "$TMPROOT"' EXIT

# assert_contains <file> <pattern> <message>
assert_contains() {
    local file="$1"
    local pattern="$2"
    local msg="$3"
    if ! grep -qE "$pattern" "$file"; then
        echo "  FAIL: $msg"
        echo "  -- expected pattern: $pattern"
        echo "  -- actual output:"
        sed 's/^/  | /' "$file"
        FAIL=$((FAIL + 1))
        return 1
    fi
    return 0
}

# assert_not_contains <file> <pattern> <message>
assert_not_contains() {
    local file="$1"
    local pattern="$2"
    local msg="$3"
    if grep -qE "$pattern" "$file"; then
        echo "  FAIL: $msg"
        echo "  -- forbidden pattern: $pattern"
        echo "  -- actual output:"
        sed 's/^/  | /' "$file"
        FAIL=$((FAIL + 1))
        return 1
    fi
    return 0
}

run_fixture() {
    local fixture="$1"
    local name
    name="$(basename "$fixture")"
    local work="$TMPROOT/$name"

    echo "== $name =="
    cp -r "$fixture" "$work"

    # 1. save snapshot
    (cd "$work" && "$AEGIS" snapshot save) > "$work/save.out" 2>&1

    # 2. enrich (AST + reachability scan; no network)
    (cd "$work" && "$AEGIS" snapshot enrich) > "$work/enrich.out" 2>&1

    # 3. show --all (no filter)
    (cd "$work" && "$AEGIS" snapshot show --all) > "$work/show.out" 2>&1

    # 4. show --all --used-only
    (cd "$work" && "$AEGIS" snapshot show --all --used-only) > "$work/used-only.out" 2>&1

    # Per-fixture assertions.
    case "$name" in
        cve-in-unused-dep)
            assert_contains "$work/show.out" 'lodash.*\[unused\]'      "lodash should be marked [unused]"
            assert_not_contains "$work/show.out" 'zod.*\[unused\]'     "zod is imported, must not be [unused]"
            assert_contains "$work/used-only.out" 'zod'                "zod must show under --used-only"
            assert_not_contains "$work/used-only.out" '^[[:space:]]+npm[[:space:]]+lodash' \
                                                                       "lodash must be hidden under --used-only"
            assert_contains "$work/used-only.out" 'hid 1 unused deps'  "footer must report 1 hidden"
            ;;
        *)
            echo "  WARN: no assertions defined for fixture $name"
            ;;
    esac

    if [ "$FAIL" -eq 0 ]; then
        echo "  PASS"
        PASS=$((PASS + 1))
    fi
}

for fixture in "$ROOT"/examples/reachability/*/; do
    [ -d "$fixture" ] || continue
    [ "$(basename "$fixture")" = "README.md" ] && continue
    run_fixture "${fixture%/}"
done

echo
echo "reachability e2e: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
