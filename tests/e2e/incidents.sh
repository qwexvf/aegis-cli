#!/usr/bin/env bash
# tests/e2e/incidents.sh — end-to-end check that `aegis analyze --local`
# detects the expected capabilities on every fixture in
# examples/incidents/.
#
# Run with:
#   make test-e2e
# or directly:
#   ./tests/e2e/incidents.sh           # uses prebuilt ./bin/aegis if present
#   AEGIS=/path/to/aegis ./tests/e2e/incidents.sh
#
# Adding a new fixture: drop it under examples/incidents/<eco>/<name>-<ver>/
# and add a CASE row below. Each row is:
#   <ecosystem>|<name>|<version>|<expected-cap>,<expected-cap>,...

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

# Each row: ecosystem|name|version|cap1,cap2,...
# fixture path is derived as examples/incidents/<eco>/<name>-<ver>/.
CASES=(
    # RubyGems — eval(Net::HTTP.get(...)) family
    "rubygems|rest-client|1.6.13|dynamic-eval,net-egress,obfuscated-payload,suspicious-url"
    "rubygems|strong_password|0.0.7|dynamic-eval,net-egress,obfuscated-payload,suspicious-url"
    "rubygems|bootstrap-sass|3.2.0.3|dynamic-eval,base64-decode"
    "rubygems|paranoid2|1.1.6|dynamic-eval,net-egress,obfuscated-payload,suspicious-url"

    # PyPI
    "pypi|torchtriton|1.0.1|dynamic-eval,net-egress,obfuscated-payload,suspicious-url"
    "pypi|colourama|0.1.6|typosquat-risk,shell-spawn,net-egress"
    "pypi|ultralytics|8.3.41|binary-dropper"

    # npm
    "npm|event-stream|3.3.6|install-hook-suspicious,obfuscated-payload,suspicious-url,dynamic-eval"
    "npm|ua-parser-js|0.7.29|install-hook-suspicious,binary-dropper"
    "npm|coa|2.0.3|install-hook-suspicious"

    # crates.io
    "crates|xrvrv|1.0.0|shell-spawn,install-hook-suspicious,suspicious-url"
    "crates|rustdecimal|1.23.1|net-egress,suspicious-url,typosquat-risk"
    "crates|big_decimal|0.1.5|binary-dropper,typosquat-risk"
)

pass=0
fail=0
for row in "${CASES[@]}"; do
    IFS='|' read -r eco name ver caps <<<"$row"
    fixture="$ROOT/examples/incidents/$eco/$name-$ver"
    if [ ! -d "$fixture" ]; then
        echo "FAIL  $eco/$name@$ver — fixture missing: $fixture"
        fail=$((fail + 1))
        continue
    fi
    out=$("$AEGIS" analyze "$eco/$name@$ver" --local "$fixture" --json 2>&1 || true)

    miss=""
    IFS=',' read -r -a want <<<"$caps"
    for cap in "${want[@]}"; do
        if ! grep -q "\"$cap\"" <<<"$out"; then
            miss+=" $cap"
        fi
    done

    if [ -z "$miss" ]; then
        echo "ok    $eco/$name@$ver — caps: $caps"
        pass=$((pass + 1))
    else
        echo "FAIL  $eco/$name@$ver — missing:$miss"
        echo "      output: $out"
        fail=$((fail + 1))
    fi
done

echo
echo "$pass passed, $fail failed (${#CASES[@]} total)"
[ "$fail" -eq 0 ]
