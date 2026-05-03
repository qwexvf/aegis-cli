#!/usr/bin/env bash
# Generic shell wrapper for aegis CI audit.
#
# Use this from any CI system that gives you a shell — Buildkite,
# Jenkins, Drone, CircleCI, nix builds, a cron job, etc. Wire it as
# the build step after deps are installed.
#
# Exit codes (propagated from `aegis ci`):
#   0   passed (no findings ≥ AEGIS_FAIL_ON)
#   1   failed (one or more findings ≥ AEGIS_FAIL_ON)
#   2   couldn't reach a verdict (config / network error)
#
# Required env in the calling job:
#   AEGIS_API_URL    URL of the Aegis API (default: http://localhost:4000)
#
# Optional env:
#   AEGIS_FAIL_ON    safe|review|prompt|block (default: block)
#   AEGIS_CACHE_DIR  where to persist the AST fingerprint cache
#                    (default: ~/.aegis/cache; override for ephemeral runners)
#   AEGIS_REPORT     path to write JSON report (default: aegis-report.json)

set -euo pipefail

FAIL_ON="${AEGIS_FAIL_ON:-block}"
REPORT="${AEGIS_REPORT:-aegis-report.json}"

# 1. Sanity — confirm aegis is on PATH
if ! command -v aegis >/dev/null 2>&1; then
    echo "error: 'aegis' not found on PATH" >&2
    echo "       Install: download a pre-built binary from" >&2
    echo "         https://github.com/qwexvf/aegis-cli/releases/latest" >&2
    echo "       or build from source:" >&2
    echo "         go install github.com/qwexvf/aegis-cli/cmd/aegis@latest" >&2
    exit 2
fi

echo "==> aegis version"
aegis version

echo "==> aegis ci --fail-on=${FAIL_ON}"
# Run the audit. We capture the exit code without aborting so we can
# always emit the JSON report afterwards.
set +e
aegis ci --fail-on="${FAIL_ON}"
RC=$?
set -e

echo "==> writing report to ${REPORT}"
# JSON dump always succeeds (the underlying scoring runs again with
# already-warm cache, so this is fast). Use `|| true` to ignore the
# non-zero exit when there are findings.
aegis ci --fail-on="${FAIL_ON}" --json > "${REPORT}" || true

if [[ $RC -eq 0 ]]; then
    echo "==> PASS"
elif [[ $RC -eq 1 ]]; then
    echo "==> FAIL (findings ≥ ${FAIL_ON})"
else
    echo "==> ERROR (couldn't reach a verdict, exit=${RC})"
fi
exit $RC
