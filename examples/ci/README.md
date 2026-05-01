# aegis CI examples

Drop-in templates for running `aegis ci` in your pipeline.

| File | Use it for |
|---|---|
| [`github-actions.yml`](github-actions.yml) | GitHub Actions — copy to `.github/workflows/aegis.yml` in your repo |
| [`gitlab-ci.yml`](gitlab-ci.yml) | GitLab CI — paste the job into your `.gitlab-ci.yml` |
| [`generic.sh`](generic.sh) | Buildkite / Jenkins / Drone / cron — anywhere you have a shell |

All three do the same thing:

1. Install your project's deps (npm/bun/yarn/pnpm)
2. Install aegis (build from source today; release-binary download once available)
3. Cache `~/.aegis/cache` between runs so warm runs only re-scan changed deps
4. Run `aegis ci --fail-on=block` and propagate the exit code

## Tuning

- **Stricter gate**: `--fail-on=prompt` (catches review-or-worse) or `--fail-on=review`.
- **Faster CI** (no AST re-scan): `--fail-on=block --no-enrich`. Useful when you trust the cached fingerprints.
- **JSON output** for downstream tooling: `--json`. The exit code still reflects pass/fail.
- **Quiet output** (summary only): `--quiet`. Per-finding detail goes to logs.

## What aegis CI checks

- Every dep in your lockfile gets AST-scanned for capabilities (install hooks, dynamic eval, network egress, env reads, etc.)
- Each fingerprint is scored, allowlisted (builtin + project-level `.aegis-allowlist.yaml`), and bucketed into safe / review / prompt / block
- Findings ≥ `--fail-on` cause the job to exit non-zero

The fingerprint cache (`~/.aegis/cache/fingerprints`) means warm runs cost a few seconds — only newly-added or version-changed deps incur AST scan cost.
