BINARY := aegis
BIN_DIR := bin
PKG := ./cmd/aegis

# Stripped release build: drop debug symbols + DWARF.
# Typical reduction: 20-30% on a Go binary.
RELEASE_LDFLAGS := -s -w

# Build tag for opting out of the AST scanner (tree-sitter cgo, ~3MB).
# Use `make build-core` for an incident-DB-only binary that doesn't
# pull in the JS grammar — useful for size-constrained CI runners.
CORE_TAGS := nojsscan

# --- targets ----------------------------------------------------------

.PHONY: build
build:                          ## debug-friendly build (default)
	go build -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: build-release
build-release:                  ## stripped release build (smallest full-feature)
	go build -ldflags='$(RELEASE_LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: build-core
build-core:                     ## release build w/o AST scanner (no tree-sitter)
	go build -tags='$(CORE_TAGS)' -ldflags='$(RELEASE_LDFLAGS)' \
		-o $(BIN_DIR)/$(BINARY)-core $(PKG)

.PHONY: build-all
build-all: build-release build-core   ## both flavors, side by side

# pm build tags (`nonpm`, `nobun`, `noyarn`, `nopnpm`) exclude the
# corresponding pm wrapper. Empirically each saves ~19 KB out of 27 MB,
# so we don't ship per-pm release binaries — but the tags stay around
# for users who want a smaller `go install` build via `-tags=...`.

.PHONY: size
size: build build-release build-core   ## binary sizes side-by-side
	@echo
	@echo "Binary size comparison:"
	@ls -lh \
		$(BIN_DIR)/$(BINARY) \
		$(BIN_DIR)/$(BINARY)-core \
		2>/dev/null | awk '{print $$5"\t"$$NF}'

.PHONY: install
install:
	go install $(PKG)

.PHONY: test
test:
	go test ./...

.PHONY: test-race
test-race:                      ## run tests with the race detector
	go test -race ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:                            ## gofmt every tracked .go file in place
	gofmt -w .

.PHONY: fmt-check
fmt-check:                      ## fail if any .go file is unformatted (mirrors CI lint)
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
	  echo "gofmt issues in:"; \
	  echo "$$out"; \
	  echo; \
	  echo "fix with: make fmt"; \
	  exit 1; \
	fi

.PHONY: test-e2e
test-e2e:                       ## run end-to-end CLI tests (examples/incidents)
	@bash tests/e2e/incidents.sh

.PHONY: test-e2e-real
test-e2e-real:                  ## run e2e tests including real downloaded fixtures (AEGIS_REAL_INCIDENTS=1)
	@AEGIS_REAL_INCIDENTS=1 bash tests/e2e/incidents.sh

.PHONY: fetch-real-incidents
fetch-real-incidents:           ## download + neutralize real malicious packages into examples/incidents-real/
	@bash scripts/fetch-real-incidents.sh

.PHONY: precommit
precommit: fmt-check vet test-race test-e2e  ## run before every commit/push (CI parity)
	@echo "precommit OK"

.PHONY: install-hooks
install-hooks:                  ## install scripts/git-hooks into .git/hooks
	@cp scripts/git-hooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "installed: .git/hooks/pre-commit"

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

.PHONY: run
run: build
	./$(BIN_DIR)/$(BINARY)

.PHONY: docs
docs:                           ## run the docs site dev server (site/)
	cd site && bun run dev

.PHONY: docs-build
docs-build:                     ## build the docs site to site/dist/
	cd site && bun install --frozen-lockfile && bun run build

.PHONY: docs-gen
docs-gen:                       ## regenerate man pages + command markdown from cobra tree
	go run ./cmd/gendocs
