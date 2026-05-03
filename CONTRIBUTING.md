# Contributing to aegis-cli

Thanks for considering a contribution. This file is short on purpose —
the codebase enforces conventions through linting, tests, and the
release pipeline, not through documentation.

## Before you start

- For non-trivial changes, **open an issue first** to discuss the
  approach. PRs that arrive without prior discussion may be closed if
  the direction doesn't fit the project's scope. Bug fixes and small
  improvements don't need an issue.
- Read [docs/cli-architecture.md](docs/cli-architecture.md) — the
  clean-arch dependency direction (`cmd → interface → usecase →
  domain ← infra`) is enforced by review, not by tooling. PRs that
  cross those boundaries will be rejected.
- Read [SECURITY.md](SECURITY.md) — security issues go through private
  disclosure, not pull requests.

## Local setup

Requires Go 1.26 or later. Verify:

```sh
go version            # go1.26+
make build            # writes ./bin/aegis
./bin/aegis version
```

Useful targets (see `Makefile`):

| Target                     | Purpose                                        |
|----------------------------|------------------------------------------------|
| `make build`               | debug build (default)                          |
| `make build-release`       | stripped release build                         |
| `make build-core`          | release build without the AST scanner          |
| `make build-each-pm`       | per-PM single-tool builds (npm/bun/yarn/pnpm)  |
| `make test` / `test-race`  | unit tests, optionally with the race detector  |
| `make size`                | side-by-side binary size comparison            |

## Workflow

1. Fork or create a topic branch off `main`.
2. Make the change. Keep commits focused — a fix is one commit, a
   refactor is one commit, a test is one commit.
3. Run the full test suite locally:
   ```sh
   go test -race ./...
   golangci-lint run --timeout=5m
   ```
   Both must pass before opening the PR. CI runs the same commands and
   will block merge on failure.
4. Open the PR against `main`. Squash-merge is the default.

## Commit messages

Use conventional commits — the GoReleaser changelog parses these:

- `feat: …` — user-visible feature
- `feat(scope): …` — scoped feature, e.g. `feat(npm): …`
- `fix: …` — bug fix
- `chore: …` — internal cleanup, no user-visible change
- `docs: …` — documentation only
- `ci: …` / `build: …` — pipeline + tooling
- `refactor: …` — internal restructure with no behaviour change

Breaking changes get a `!` after the type: `feat!: drop old config format`.

## Code style

- `gofmt -w .` and `goimports -w .` run on every save (or before commit).
- The linter set in `.golangci.yml` is the source of truth. If you
  disagree with a rule, propose the change to the config in a separate
  PR — don't add `//nolint` comments without one.
- No comments that just describe what the next line does — comment
  *why* if the why is non-obvious. Variable names beat comments.
- Errors get wrapped with `%w` if a caller might want to inspect them;
  otherwise plain `%v` with package context is fine.
- New packages get a one-paragraph package doc on the file that holds
  the most representative type.

## Adding a package manager

A new PM (e.g. `nx`, `npmjs/cli`) needs:

1. One file in `internal/infra/pmwrapper/<name>.go` implementing
   `PackageManager`.
2. Registration in `cmd/aegis/pm_<name>.go` guarded by
   `//go:build !no<name>` so the per-PM build tags work.
3. A line in `cmd/aegis/pm_registry.go` ordering it in the help output.
4. Tests in `internal/infra/pmwrapper/<name>_test.go`.

Domain types stay untouched — the `PackageManager` interface is the
extension point.

## Adding an ecosystem (pip, cargo, gem, …)

Five files under `internal/infra/`:

- `pmwrapper/<eco>.go`         — wrapper for the package-manager CLI
- `pmwrapper/registry.go`      — registration entry
- `<eco>pkgsource/fetcher.go`  — tarball/sdist downloader
- `locksnap/lockfile_<eco>.go` — lockfile parser
- `astscan/<lang>scan/`        — AST scanner if applicable

Plus detection priority in `internal/usecase/snapshot.go` and a
composition-root wire-up in `cmd/aegis/main.go`. See
[docs/cli-architecture.md § Adding a new ecosystem](docs/cli-architecture.md).

## Reviewing

Review takes a few days for small PRs, longer for architectural
changes. We don't merge anything that hasn't been read by a second
human, even from a maintainer.

## License

All contributions are accepted under [Apache-2.0](LICENSE) (the same
license as the repo). By opening a PR you assert that you have the
right to contribute the code under that license.
