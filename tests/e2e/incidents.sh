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
    "rubygems|rubygems-update|3.4.99|dynamic-eval,base64-decode,net-egress,suspicious-url"

    # PyPI
    "pypi|torchtriton|1.0.1|dynamic-eval,net-egress,obfuscated-payload,suspicious-url"
    "pypi|colourama|0.1.6|typosquat-risk,shell-spawn,net-egress"
    "pypi|ultralytics|8.3.41|binary-dropper"
    "pypi|ctx|0.2.2|net-egress,suspicious-url"
    "pypi|jeIlyfish|0.7.1|dynamic-eval,base64-decode,net-egress"
    "pypi|pytoileur|1.0.0|dynamic-eval,base64-decode,net-egress,fs-write-outside-root,suspicious-url"
    "pypi|python3-dateutil|2.9.5|dynamic-eval,base64-decode,net-egress,typosquat-risk"

    # npm
    "npm|event-stream|3.3.6|install-hook-suspicious,obfuscated-payload,suspicious-url,dynamic-eval"
    "npm|ua-parser-js|0.7.29|install-hook-suspicious,binary-dropper"
    "npm|coa|2.0.3|install-hook-suspicious"
    "npm|rc|1.2.9|install-hook-suspicious"
    "npm|@solana/web3.js|1.95.5|dynamic-eval,base64-decode,net-egress,obfuscated-payload,suspicious-url"
    "npm|@lottiefiles/lottie-player|2.0.5|dynamic-eval,base64-decode,net-egress,obfuscated-payload,suspicious-url"
    "npm|node-ipc|11.0.0|net-egress,fs-write-outside-root,suspicious-url"

    # crates.io
    "crates|xrvrv|1.0.0|shell-spawn,install-hook-suspicious,suspicious-url"
    "crates|rustdecimal|1.23.1|net-egress,suspicious-url,typosquat-risk"
    "crates|big_decimal|0.1.5|binary-dropper,typosquat-risk"
    "crates|wad|0.0.1|shell-spawn,dynamic-eval,base64-decode,net-egress,suspicious-url"

    # Go modules — init()-time exfil generic shape
    "go|boltdb-go|1.0.0|shell-spawn,net-egress,suspicious-url"
    "go|dep-confusion-pkg|1.0.0|shell-spawn,dynamic-eval,net-egress,fs-write-outside-root,suspicious-url"

    # Maven — Log4Shell shape (CVE-2021-44228) + Spring4Shell (CVE-2022-22965)
    "maven|log4j-core|2.14.1|dynamic-eval,net-egress"
    "maven|spring-core|5.3.17|dynamic-eval,net-egress,fs-write-outside-root"

    # Packagist (PHP) — Composer install-time webshell shape
    "packagist|totally-not-a-shell|1.0.0|dynamic-eval,base64-decode,net-egress,suspicious-url"

    # NuGet (.NET) — module-initializer-time RAT shape
    "nuget|Rougeit|1.0.0|shell-spawn,dynamic-eval,base64-decode,net-egress,fs-write-outside-root,suspicious-url"
    "nuget|SqlMapper|1.0.0|shell-spawn,dynamic-eval,base64-decode,net-egress,fs-write-outside-root,suspicious-url"

    # CRAN (R) — .onLoad typosquat with eval(parse(text=url(...))) + curl|sh exfil
    "cran|ggplott2|1.0.0|obfuscated-payload,suspicious-url,install-hook-suspicious,typosquat-risk"

    # Hackage (Haskell) — Setup.hs curl|sh in custom build phase
    "hackage|textt|0.7.0|suspicious-url,install-hook-suspicious,typosquat-risk"

    # CPAN (Perl) — Makefile.PL curl|sh at configure time
    "cpan|Moosee|1.0.0|suspicious-url,install-hook-suspicious,typosquat-risk"

    # Pub (Dart) — library-level HTTP exfil + Process.run curl|sh
    "pub|dart-exfil|1.0.0|suspicious-url,install-hook-suspicious"

    # Hex (Elixir) — Application.start/2 :os.cmd curl|sh + :httpc exfil
    "hex|ex-aws-mock|0.9.0|suspicious-url,install-hook-suspicious"
)

pass=0
fail=0

run_case() {
    local eco="$1" name="$2" ver="$3" caps="$4" fixture="$5"
    local out miss=""
    out=$("$AEGIS" analyze "$eco/$name@$ver" --local "$fixture" --json 2>&1 || true)
    IFS=',' read -r -a want <<<"$caps"
    for cap in "${want[@]}"; do
        grep -q "\"$cap\"" <<<"$out" || miss+=" $cap"
    done
    if [ -z "$miss" ]; then
        echo "ok    $eco/$name@$ver — caps: $caps"
        pass=$((pass + 1))
    else
        echo "FAIL  $eco/$name@$ver — missing:$miss"
        echo "      output: $out"
        fail=$((fail + 1))
    fi
}

# Synthetic fixtures (always run)
for row in "${CASES[@]}"; do
    IFS='|' read -r eco name ver caps <<<"$row"
    fixture="$ROOT/examples/incidents/$eco/$name-$ver"
    if [ ! -d "$fixture" ]; then
        echo "FAIL  $eco/$name@$ver — fixture missing: $fixture"
        fail=$((fail + 1))
        continue
    fi
    run_case "$eco" "$name" "$ver" "$caps" "$fixture"
done

# Real fixtures — only when AEGIS_REAL_INCIDENTS=1 and directory exists.
# Download via scripts/fetch-real-incidents.sh (never committed to git).
if [ "${AEGIS_REAL_INCIDENTS:-}" = "1" ]; then
    REAL_DIR="$ROOT/examples/incidents-real"
    if [ ! -d "$REAL_DIR" ]; then
        echo "warn: AEGIS_REAL_INCIDENTS=1 but $REAL_DIR not found — run scripts/fetch-real-incidents.sh"
    else
        echo ""
        echo "=== real fixtures ==="
        # Same format: ecosystem|name|version|caps
        # Capabilities verified against real downloaded packages (2026-05-15).
        # Only packages still on registry — see scripts/fetch-real-incidents.sh
        # for packages removed from registries (obtain from OSSF archive).
        REAL_CASES=(
            # npm — still on registry
            "npm|node-ipc|11.0.0|net-egress,fs-write-outside-root,install-hook-exec"
            "npm|@solana/web3.js|1.95.5|base64-decode,net-egress,env-read"

            # Packages removed from registries — skip if not manually downloaded:
            # "npm|event-stream|3.3.6|install-hook-suspicious,obfuscated-payload,suspicious-url,dynamic-eval"
            # "npm|ua-parser-js|0.7.29|install-hook-suspicious,binary-dropper"
            # "pypi|ctx|0.2.2|net-egress,suspicious-url"
            # "rubygems|rest-client|1.6.13|dynamic-eval,net-egress,obfuscated-payload,suspicious-url"
        )
        for row in "${REAL_CASES[@]}"; do
            IFS='|' read -r eco name ver caps <<<"$row"
            fixture="$REAL_DIR/$eco/${name//\//_}-$ver"
            if [ ! -d "$fixture" ]; then
                echo "skip  $eco/$name@$ver — not downloaded yet"
                continue
            fi
            run_case "$eco" "$name" "$ver" "$caps" "$fixture"
        done
    fi
fi

echo
echo "$pass passed, $fail failed (${#CASES[@]} total)"
[ "$fail" -eq 0 ]
