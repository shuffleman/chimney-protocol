# Chimney — Behaviorally Indistinguishable Session-Parasitic Transport
# Makefile for building, testing, and deployment.

.PHONY: all build test clean install fmt vet lint

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet

# Binary names
RELAY_BINARY=chimney-relay
CLIENT_BINARY=chimney-client

# Build directories
BUILD_DIR=./build
BIN_DIR=$(BUILD_DIR)/bin

# Installation directory
PREFIX=/usr/local

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

# Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race ./internal/...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=$(BUILD_DIR)/coverage.out ./internal/...
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

# Format all Go files
fmt:
	@echo "Formatting..."
	$(GOFMT) -w -s ./internal ./cmd

# Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

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
	$(BIN_DIR)/$(CLIENT_BINARY) -config config/client.yaml

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
	@echo "  build-relay      - Build relay server only"
	@echo "  build-client     - Build client only"
	@echo "  test             - Run all tests"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  fmt              - Format Go source files"
	@echo "  vet              - Run go vet"
	@echo "  lint             - Run golangci-lint"
	@echo "  tidy             - Tidy Go modules"
	@echo "  deps             - Download dependencies"
	@echo "  clean            - Remove build artifacts"
	@echo "  install          - Install binaries to $(PREFIX)/bin"
	@echo "  uninstall        - Remove installed binaries"
	@echo "  genkey           - Generate a new PSK"
	@echo "  run-relay        - Build and run relay server"
	@echo "  run-client       - Build and run client"
	@echo "  docker-build     - Build Docker images"
	@echo "  bench            - Run benchmarks"
	@echo "  ci               - Run CI pipeline (fmt, vet, test, build)"
	@echo "  dev-setup        - Setup development environment"
	@echo "  help             - Show this help message"
