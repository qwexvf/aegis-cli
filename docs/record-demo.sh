#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> build aegis"
cd "$REPO_ROOT"
make build-release
export PATH="$REPO_ROOT/bin:$PATH"

echo "==> verify"
aegis version
vhs --version

echo "==> record"
cd "$REPO_ROOT/examples/demo"
vhs "$REPO_ROOT/docs/demo.tape"

echo "==> done: docs/demo.gif"
