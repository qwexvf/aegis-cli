BINARY := aegis
BIN_DIR := bin
PKG := ./cmd/aegis

# Stripped release build: drop debug symbols + DWARF.
# Typical reduction: 20-30% on a Go binary.
RELEASE_LDFLAGS := -s -w

# --- targets ----------------------------------------------------------

.PHONY: build
build:                          ## debug-friendly build (default)
	go build -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: build-release
build-release:                  ## stripped release build
	go build -ldflags='$(RELEASE_LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: size
size: build build-release       ## binary sizes side-by-side
	@echo
	@echo "Binary size comparison:"
	@ls -lh $(BIN_DIR)/$(BINARY) 2>/dev/null | awk '{print $$5"\t"$$NF}'

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

.PHONY: test-e2e-image
test-e2e-image:                 ## run image scanner e2e tests (requires docker)
	@bash tests/e2e/image.sh

.PHONY: fetch-real-incidents
fetch-real-incidents:           ## download + neutralize real malicious packages into examples/incidents-real/
	@bash scripts/fetch-real-incidents.sh

.PHONY: fetch-real-incidents-docker
fetch-real-incidents-docker:    ## same as above but fully isolated inside Docker (recommended)
	@mkdir -p examples/incidents-real
	docker build -f scripts/Dockerfile.fetch-incidents -t aegis-fetch-incidents scripts/ --quiet
	docker run --rm \
		--network=bridge \
		--cap-drop=ALL \
		--security-opt=no-new-privileges \
		-v "$(PWD)/examples/incidents-real:/incidents-real" \
		aegis-fetch-incidents

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
