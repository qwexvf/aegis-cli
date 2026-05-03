#!/usr/bin/env bash
# extract-changelog.sh <version> [<changelog-file>]
#
# Pulls the section for `<version>` out of CHANGELOG.md (Keep a
# Changelog format) and writes it to stdout. Used by the release
# workflow to populate the GitHub release body with the curated
# notes from CHANGELOG.md instead of GoReleaser's commit-list
# auto-generation.
#
# Format expected:
#   ## [0.7.0] — 2026-05-04
#   ... section body ...
#   ## [0.6.0] — ...   (next section terminates the previous)
#
# Exit codes:
#   0 — section found, printed to stdout
#   1 — argument missing
#   2 — section not found (caller should fall back to auto-generated notes)

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <version> [<changelog-file>]" >&2
    exit 1
fi

version="${1#v}" # strip optional v-prefix
changelog="${2:-CHANGELOG.md}"

if [[ ! -f "$changelog" ]]; then
    echo "$changelog not found" >&2
    exit 2
fi

# awk extracts everything between "## [<version>]" and the next "## [".
# `found` flips on at the start of the matching section, off at the next
# section header. The leading section header itself is skipped (printed
# title becomes redundant — goreleaser prefixes with the tag already).
awk -v ver="$version" '
    /^## \[/ {
        if (found) { exit }
        if (index($0, "[" ver "]")) { found = 1; next }
    }
    found { print }
' "$changelog" |
    # Trim trailing blank lines so the goreleaser-injected footer
    # (Apache-2.0 link) sits flush against the section content.
    awk 'NF { last=NR; lines[NR]=$0; next } { lines[NR]=$0 }
         END { for (i = 1; i <= last; i++) print lines[i] }'

# Detect "no section found": awk emits nothing → check stdout via
# wc -l in the caller. We don't exit 2 here because piping makes the
# exit status hard to propagate; the caller inspects the file size.
