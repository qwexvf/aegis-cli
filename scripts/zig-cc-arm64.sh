#!/usr/bin/env bash
# Cross-cgo wrapper used by goreleaser when building linux/arm64.
#
# setup-go exports GOGCCFLAGS containing -m64 (x86-64 only). Go passes
# those flags to CC. zig cc with -target aarch64-linux-gnu rejects -m64
# and the cgo build silently turns off, which excludes every
# tree-sitter binding by build constraint and breaks the cgo flavors.
# Strip arch-specific flags before invoking zig.
set -euo pipefail

args=()
for a in "$@"; do
  case "$a" in
    -m64|-m32|-march=*|-mtune=*) continue ;;
    *) args+=("$a") ;;
  esac
done

exec zig cc -target aarch64-linux-gnu "${args[@]}"
