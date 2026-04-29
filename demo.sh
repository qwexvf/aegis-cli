#!/usr/bin/env bash
# End-to-end demo of the aegis CLI against the local mock API.
#
# Prereqs:  make build
#
# Runs four scenarios that mirror the build-plan:
#   1. Allow  - lodash@4.17.21
#   2. Block  - @bitwarden/cli@2026.4.0 (the April 2026 incident)
#   3. Prompt - @aegis/suspicious-demo@2.0.0 (HIGH severity)
#   4. Block + override - ua-parser-js@0.7.29

set -e
cd "$(dirname "$0")"

if [ ! -x ./bin/aegis ]; then
    echo "binary not built — run 'make build' first" >&2
    exit 1
fi

PORT=14000
./scripts/mock-api.sh > /tmp/aegis-mock-api.log 2>&1 &
MOCK_PID=$!
trap "kill $MOCK_PID 2>/dev/null || true" EXIT
sleep 1

export AEGIS_API_URL="http://localhost:${PORT}"

run_demo() {
    local title="$1"; shift
    echo
    echo "==> $title"
    echo "    \$ aegis $*"
    "$@" || echo "    [exit code: $?]"
}

run_demo "Demo 1: Allow (lodash@4.17.21)" \
    ./bin/aegis npm install lodash@4.17.21 --dry-run

run_demo "Demo 2: Block (@bitwarden/cli@2026.4.0 — April 2026 incident)" \
    ./bin/aegis npm install @bitwarden/cli@2026.4.0 --dry-run

run_demo "Demo 3: Prompt / Review Required (@aegis/suspicious-demo@2.0.0)" \
    ./bin/aegis npm install @aegis/suspicious-demo@2.0.0 --dry-run

run_demo "Demo 4: Block + override (ua-parser-js@0.7.29)" \
    env AEGIS_OVERRIDE=allow ./bin/aegis npm install ua-parser-js@0.7.29 --dry-run
