BINARY := aegis
BIN_DIR := bin
PKG := ./cmd/aegis

.PHONY: build
build:
	go build -o $(BIN_DIR)/$(BINARY) $(PKG)

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
