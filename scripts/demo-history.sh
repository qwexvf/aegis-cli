#!/usr/bin/env bash
# Walk through real, documented historical npm supply-chain incidents
# using the aegis CLI against a live API.
#
# Prereqs:
#   - bin/aegis built (run `make build` first)
#   - the API is running (e.g. `docker compose up api -d`)
#   - AEGIS_API_URL points at the API (default http://localhost:4000)
#
# Each scenario is dry-run: bun/yarn/pnpm scenarios still pass through
# to the underlying PM after Aegis renders, so the binaries don't need
# to actually exist for the gate's behavior to be visible.

set -e
cd "$(dirname "$0")/.."

if [ ! -x ./bin/aegis ]; then
    echo "binary not built — run 'make build' first" >&2
    exit 1
fi

export AEGIS_API_URL="${AEGIS_API_URL:-http://localhost:4000}"

# Audit overrides go to a scratch dir so we don't pollute ~/.aegis.
export AEGIS_AUDIT_DIR="$(mktemp -d)"
export AEGIS_CACHE_DIR="$(mktemp -d)"
trap "rm -rf $AEGIS_AUDIT_DIR $AEGIS_CACHE_DIR" EXIT

run_scenario() {
    local title="$1"; shift
    echo
    echo "==> $title"
    echo "    \$ aegis $*"
    "$@" || echo "    [exit code: $?]"
}

echo "Aegis historical incident demo — using API at $AEGIS_API_URL"

run_scenario "1. event-stream@3.3.6 (Nov 2018, GHSA-jvqj-7wpc-9bqp)" \
    ./bin/aegis npm install event-stream@3.3.6

run_scenario "2. flatmap-stream@0.1.1 — the actual payload of the event-stream incident" \
    ./bin/aegis npm install flatmap-stream@0.1.1

run_scenario "3. eslint-scope@3.7.2 (Jul 2018, GHSA-vhwc-9wr2-w98p)" \
    ./bin/aegis npm install eslint-scope@3.7.2

run_scenario "4. ua-parser-js@0.7.29 (Oct 2021, GHSA-pjwm-rvh2-c87w)" \
    ./bin/aegis npm install ua-parser-js@0.7.29

run_scenario "5. coa@2.0.4 (Nov 2021, GHSA-73qr-pfmq-6rp8)" \
    ./bin/aegis bun add coa@2.0.4

run_scenario "6. rc@1.2.9 (Nov 2021, GHSA-g2q5-5433-rhrf)" \
    ./bin/aegis yarn add rc@1.2.9

run_scenario "7. node-ipc@10.1.2 (Mar 2022, peacenotwar protestware)" \
    ./bin/aegis pnpm add node-ipc@10.1.2

run_scenario "8. colors@1.4.44-liberty-2 (Jan 2022, author self-sabotage)" \
    ./bin/aegis npm install colors@1.4.44-liberty-2

run_scenario "9. faker@6.6.6 (Jan 2022, author self-sabotage)" \
    ./bin/aegis npm install faker@6.6.6

echo
echo "==> 10. Audit log captured for these decisions"
./bin/aegis audit tail -n 9 || true

echo
echo "==> 11. A clean install (lodash@4.17.21) for comparison"
./bin/aegis npm install lodash@4.17.21 || true

echo
echo "==> 12. Cache list — second run of the same install would hit cache"
./bin/aegis cache list || true
