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

# --- per-PM single-tool builds ----------------------------------------
#
# Tags `nonpm`, `nobun`, `noyarn`, `nopnpm` exclude the corresponding
# pm wrapper. Each saves ~5 KB; the value is UX (cleaner --help) +
# distribution (per-team binaries), not size. AST scanner stays on
# (every JS pm uses it); combine with `nojsscan` for gate-only.

PM_OFFTAGS_NPM  := nobun,noyarn,nopnpm
PM_OFFTAGS_BUN  := nonpm,noyarn,nopnpm
PM_OFFTAGS_YARN := nonpm,nobun,nopnpm
PM_OFFTAGS_PNPM := nonpm,nobun,noyarn

.PHONY: build-npm
build-npm:                      ## release build registering only `aegis npm`
	go build -tags='$(PM_OFFTAGS_NPM)' -ldflags='$(RELEASE_LDFLAGS)' \
		-o $(BIN_DIR)/$(BINARY)-npm $(PKG)

.PHONY: build-bun
build-bun:                      ## release build registering only `aegis bun`
	go build -tags='$(PM_OFFTAGS_BUN)' -ldflags='$(RELEASE_LDFLAGS)' \
		-o $(BIN_DIR)/$(BINARY)-bun $(PKG)

.PHONY: build-yarn
build-yarn:                     ## release build registering only `aegis yarn`
	go build -tags='$(PM_OFFTAGS_YARN)' -ldflags='$(RELEASE_LDFLAGS)' \
		-o $(BIN_DIR)/$(BINARY)-yarn $(PKG)

.PHONY: build-pnpm
build-pnpm:                     ## release build registering only `aegis pnpm`
	go build -tags='$(PM_OFFTAGS_PNPM)' -ldflags='$(RELEASE_LDFLAGS)' \
		-o $(BIN_DIR)/$(BINARY)-pnpm $(PKG)

.PHONY: build-each-pm
build-each-pm: build-npm build-bun build-yarn build-pnpm   ## all per-PM flavors

.PHONY: size
size: build build-release build-core build-each-pm   ## binary sizes side-by-side
	@echo
	@echo "Binary size comparison:"
	@ls -lh \
		$(BIN_DIR)/$(BINARY) \
		$(BIN_DIR)/$(BINARY)-core \
		$(BIN_DIR)/$(BINARY)-npm \
		$(BIN_DIR)/$(BINARY)-bun \
		$(BIN_DIR)/$(BINARY)-yarn \
		$(BIN_DIR)/$(BINARY)-pnpm \
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
