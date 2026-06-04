# Chimney — Behaviorally Indistinguishable Session-Parasitic Transport
# Makefile for building, testing, and deployment.

.PHONY: all build build-all test test-race test-coverage integration-local integration-reconnect soak-local soak-remote-download check clean install fmt fmt-check vet staticcheck lint

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet
STATICCHECK=staticcheck

# Binary names
RELAY_BINARY=chimney-relay
CLIENT_BINARY=chimney-client

# Build directories
BUILD_DIR=./build
BIN_DIR=$(BUILD_DIR)/bin

# Installation directory
PREFIX=/usr/local

# Local run defaults. Override from the command line, for example:
#   make run-client RELAY_ADDR=127.0.0.1:8444 SNI=cloudflare.com USER_ID=dev-user
RELAY_ADDR ?= 127.0.0.1:8444
SNI ?= cloudflare.com
DEST_ADDR ?= 127.0.0.1:1
USER_ID ?= dev-user
LISTEN_ADDR ?= 127.0.0.1:1080
FINGERPRINT ?= chrome
CLIENT_CONFIG ?= config/client.yaml

# Default target: build all binaries
all: build

# Build both relay and client
build: build-relay build-client

# Build relay server
build-relay:
	@echo "Building relay server..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIN_DIR)/$(RELAY_BINARY) ./cmd/chimney-relay

# Build client
build-client:
	@echo "Building client..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIN_DIR)/$(CLIENT_BINARY) ./cmd/chimney-client

# Build release-like binaries for common platforms.
build-all:
	@echo "Building cross-platform binaries..."
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) -ldflags="-w -s" -o $(BIN_DIR)/$(RELAY_BINARY)-linux-amd64 ./cmd/chimney-relay
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) -ldflags="-w -s" -o $(BIN_DIR)/$(CLIENT_BINARY)-linux-amd64 ./cmd/chimney-client
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) -ldflags="-w -s" -o $(BIN_DIR)/$(RELAY_BINARY)-windows-amd64.exe ./cmd/chimney-relay
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) -ldflags="-w -s" -o $(BIN_DIR)/$(CLIENT_BINARY)-windows-amd64.exe ./cmd/chimney-client
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) -ldflags="-w -s" -o $(BIN_DIR)/$(RELAY_BINARY)-darwin-amd64 ./cmd/chimney-relay
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) -ldflags="-w -s" -o $(BIN_DIR)/$(CLIENT_BINARY)-darwin-amd64 ./cmd/chimney-client
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) -ldflags="-w -s" -o $(BIN_DIR)/$(RELAY_BINARY)-darwin-arm64 ./cmd/chimney-relay
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) -ldflags="-w -s" -o $(BIN_DIR)/$(CLIENT_BINARY)-darwin-arm64 ./cmd/chimney-client

# Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run race tests. Requires cgo and a working C compiler.
test-race:
	@echo "Running race tests..."
	$(GOTEST) -v -race ./...

# Run a local binary integration smoke/stress test on Windows PowerShell.
integration-local:
	@echo "Running local binary integration test..."
	pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/test-local-binaries.ps1

# Run local binary integration and verify client recovery after relay restart.
integration-reconnect:
	@echo "Running local reconnect integration test..."
	pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/test-local-binaries.ps1 -ReconnectCheck

# Run a longer local binary soak test and emit a JSON memory report.
soak-local:
	@echo "Running local binary soak test..."
	pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/test-local-soak.ps1

# Run a remote relay download soak test through local SOCKS5 client.
soak-remote-download:
	@echo "Running remote download soak test..."
	pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/test-remote-download-soak.ps1

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

# Format all Go files
fmt:
	@echo "Formatting..."
	$(GOFMT) -w -s ./internal ./cmd

# Verify formatting without modifying files.
fmt-check:
	@echo "Checking formatting..."
	@test -z "$$($(GOFMT) -l ./internal ./cmd)"

# Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

# Run staticcheck.
staticcheck:
	@echo "Running staticcheck..."
	$(STATICCHECK) ./...

# Standard local quality gate.
check: fmt-check vet staticcheck test
	@echo "Checks complete"

# Run linter (golangci-lint)
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed, installing..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)

# Install binaries to system
install: build
	@echo "Installing to $(PREFIX)/bin..."
	@install -d $(PREFIX)/bin
	@install -m 755 $(BIN_DIR)/$(RELAY_BINARY) $(PREFIX)/bin/
	@install -m 755 $(BIN_DIR)/$(CLIENT_BINARY) $(PREFIX)/bin/
	@echo "Installation complete. Binaries installed to $(PREFIX)/bin/"

# Uninstall binaries
uninstall:
	@echo "Uninstalling from $(PREFIX)/bin..."
	@rm -f $(PREFIX)/bin/$(RELAY_BINARY)
	@rm -f $(PREFIX)/bin/$(CLIENT_BINARY)

# Generate PSK for configuration
genkey:
	@echo "Generating 256-bit PSK..."
	@openssl rand -hex 32

# Run relay server
run-relay: build-relay
	$(BIN_DIR)/$(RELAY_BINARY) -config config/relay.yaml

# Run client
run-client: build-client
	$(BIN_DIR)/$(CLIENT_BINARY) \
		-relay $(RELAY_ADDR) \
		-sni $(SNI) \
		-dest $(DEST_ADDR) \
		-user-id $(USER_ID) \
		-listen $(LISTEN_ADDR) \
		-fingerprint $(FINGERPRINT)

# Run client from YAML config. CLI flags still override config when supplied.
run-client-config: build-client
	$(BIN_DIR)/$(CLIENT_BINARY) -config $(CLIENT_CONFIG)

# Docker build
docker-build:
	@echo "Building Docker images..."
	docker build -t chimney-relay:latest -f docker/Dockerfile.relay .
	docker build -t chimney-client:latest -f docker/Dockerfile.client .

# Generate protobuf (if needed)
proto:
	@echo "Generating protobuf..."
	@which protoc-gen-go > /dev/null || $(GOGET) google.golang.org/protobuf/cmd/protoc-gen-go
	protoc --go_out=. --go_opt=paths=source_relative pkg/proto/*.proto

# Benchmark
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./internal/...

# CI pipeline
ci: fmt vet test build
	@echo "CI pipeline complete"

# Development setup
dev-setup:
	@echo "Setting up development environment..."
	$(GOMOD) download
	@mkdir -p config
	@cp config/intent.yaml.example config/intent.yaml 2>/dev/null || true
	@cp config/enforce.yaml.example config/enforce.yaml 2>/dev/null || true
	@echo "Dev setup complete. Edit config/*.yaml files with your settings."

# Help
help:
	@echo "Chimney Makefile targets:"
	@echo ""
	@echo "  all              - Build all binaries (default)"
	@echo "  build            - Build relay and client"
	@echo "  build-all        - Build common release binaries"
	@echo "  build-relay      - Build relay server only"
	@echo "  build-client     - Build client only"
	@echo "  test             - Run all tests without race detector"
	@echo "  test-race        - Run race tests (requires cgo/C compiler)"
	@echo "  integration-local - Run local relay/client binary integration test"
	@echo "  integration-reconnect - Verify client recovery after relay restart"
	@echo "  soak-local       - Run local relay/client soak test with memory report"
	@echo "  soak-remote-download - Run remote relay download soak test"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  fmt              - Format Go source files"
	@echo "  fmt-check        - Check Go formatting without modifying files"
	@echo "  vet              - Run go vet"
	@echo "  staticcheck      - Run staticcheck"
	@echo "  check            - Run fmt-check, vet, staticcheck, and tests"
	@echo "  lint             - Run golangci-lint"
	@echo "  tidy             - Tidy Go modules"
	@echo "  deps             - Download dependencies"
	@echo "  clean            - Remove build artifacts"
	@echo "  install          - Install binaries to $(PREFIX)/bin"
	@echo "  uninstall        - Remove installed binaries"
	@echo "  genkey           - Generate a new PSK"
	@echo "  run-relay        - Build and run relay server"
	@echo "  run-client       - Build and run client with Makefile variables"
	@echo "  run-client-config - Build and run client with CLIENT_CONFIG"
	@echo "  docker-build     - Build Docker images"
	@echo "  bench            - Run benchmarks"
	@echo "  ci               - Run CI pipeline (fmt, vet, test, build)"
	@echo "  dev-setup        - Setup development environment"
	@echo "  help             - Show this help message"
