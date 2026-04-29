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

.PHONY: size
size: build build-release build-core  ## report binary sizes for comparison
	@echo
	@echo "Binary size comparison:"
	@ls -lh $(BIN_DIR)/$(BINARY) $(BIN_DIR)/$(BINARY)-core 2>/dev/null | awk '{print $$5"\t"$$NF}'

.PHONY: install
install:
	go install $(PKG)

.PHONY: test
test:
	go test ./...

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
