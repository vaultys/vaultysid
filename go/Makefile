# VaultysID Go Implementation Makefile

# Variables
GO := go
GOFLAGS := -v
BINARY_NAME := vaultysid
MAIN_PACKAGE := ./cmd/vaultysid
BUILD_DIR := build
COVERAGE_FILE := coverage.out
COVERAGE_HTML := coverage.html

# Version information
VERSION := $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Platforms for cross-compilation
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all
all: clean test build

.PHONY: build
build: ## Build the binary for current platform
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

.PHONY: build-all
build-all: ## Build binaries for all platforms
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d'/' -f1); \
		GOARCH=$$(echo $$platform | cut -d'/' -f2); \
		output=$(BUILD_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH; \
		if [ $$GOOS = "windows" ]; then output="$$output.exe"; fi; \
		echo "Building $$output..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH $(GO) build $(GOFLAGS) $(LDFLAGS) -o $$output $(MAIN_PACKAGE); \
	done

.PHONY: build-minimal
build-minimal: ## Build minimal binary without post-quantum crypto
	@echo "Building minimal $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -tags "nopqc" -o $(BUILD_DIR)/$(BINARY_NAME)-minimal $(MAIN_PACKAGE)

.PHONY: install
install: ## Install the binary to GOPATH/bin
	$(GO) install $(GOFLAGS) $(LDFLAGS) $(MAIN_PACKAGE)

.PHONY: run
run: ## Run the application
	$(GO) run $(GOFLAGS) $(MAIN_PACKAGE)

.PHONY: test
test: ## Run unit tests
	@echo "Running tests..."
	$(GO) test $(GOFLAGS) -race -cover ./...

.PHONY: test-verbose
test-verbose: ## Run tests with verbose output
	$(GO) test $(GOFLAGS) -race -cover -v ./...

.PHONY: test-short
test-short: ## Run short tests only
	$(GO) test $(GOFLAGS) -short ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	$(GO) test $(GOFLAGS) -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "Coverage report generated at $(COVERAGE_HTML)"

.PHONY: test-compatibility
test-compatibility: ## Run compatibility tests with TypeScript implementation
	@echo "Running compatibility tests..."
	$(GO) test $(GOFLAGS) -tags compatibility ./test/compatibility/...

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "Running integration tests..."
	$(GO) test $(GOFLAGS) -tags integration ./test/integration/...

.PHONY: bench
bench: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GO) test $(GOFLAGS) -bench=. -benchmem ./...

.PHONY: bench-compare
bench-compare: ## Run benchmarks and compare with previous results
	@echo "Running benchmarks with comparison..."
	$(GO) test $(GOFLAGS) -bench=. -benchmem ./... | tee bench.new
	@if [ -f bench.old ]; then \
		benchstat bench.old bench.new; \
	else \
		echo "No previous benchmark results found. Run 'make bench-save' to save current results."; \
	fi

.PHONY: bench-save
bench-save: ## Save current benchmark results
	$(GO) test $(GOFLAGS) -bench=. -benchmem ./... > bench.old
	@echo "Benchmark results saved to bench.old"

.PHONY: fuzz
fuzz: ## Run fuzzing tests
	@echo "Running fuzz tests..."
	$(GO) test $(GOFLAGS) -fuzz=FuzzDecode -fuzztime=30s ./pkg/vaultysid
	$(GO) test $(GOFLAGS) -fuzz=FuzzChallenge -fuzztime=30s ./pkg/challenger

.PHONY: lint
lint: ## Run linters
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Install it from https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi

.PHONY: fmt
fmt: ## Format code
	@echo "Formatting code..."
	$(GO) fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "goimports not installed. Run: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	$(GO) vet ./...

.PHONY: check
check: fmt vet lint test ## Run all checks (format, vet, lint, test)
	@echo "All checks passed!"

.PHONY: mod
mod: ## Download and tidy module dependencies
	$(GO) mod download
	$(GO) mod tidy

.PHONY: mod-update
mod-update: ## Update all dependencies to latest versions
	$(GO) get -u ./...
	$(GO) mod tidy

.PHONY: mod-verify
mod-verify: ## Verify module dependencies
	$(GO) mod verify

.PHONY: generate
generate: ## Run go generate
	$(GO) generate ./...

.PHONY: docs
docs: ## Generate documentation
	@echo "Generating documentation..."
	@if command -v godoc >/dev/null 2>&1; then \
		echo "Starting godoc server on http://localhost:6060"; \
		godoc -http=:6060; \
	else \
		echo "godoc not installed. Run: go install golang.org/x/tools/cmd/godoc@latest"; \
	fi

.PHONY: docker
docker: ## Build Docker image
	docker build -t vaultysid-go:$(VERSION) -f Dockerfile .

.PHONY: docker-run
docker-run: docker ## Run Docker container
	docker run --rm -it vaultysid-go:$(VERSION)

.PHONY: proto
proto: ## Generate protobuf code (if needed)
	@if [ -d "proto" ]; then \
		protoc --go_out=. --go_opt=paths=source_relative \
			--go-grpc_out=. --go-grpc_opt=paths=source_relative \
			proto/*.proto; \
	else \
		echo "No proto directory found"; \
	fi

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	@rm -f bench.old bench.new
	@find . -type f -name "*.test" -delete
	@find . -type f -name "*.prof" -delete

.PHONY: setup
setup: ## Setup development environment
	@echo "Setting up development environment..."
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/godoc@latest
	go install golang.org/x/perf/cmd/benchstat@latest
	go install github.com/golang/mock/mockgen@latest
	$(GO) mod download
	@echo "Development environment ready!"

.PHONY: ci
ci: mod-verify check test-coverage bench ## Run CI pipeline

.PHONY: release
release: clean test build-all ## Prepare release artifacts
	@echo "Release artifacts ready in $(BUILD_DIR)/"
	@ls -la $(BUILD_DIR)/

.PHONY: version
version: ## Display version information
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

.PHONY: help
help: ## Display this help message
	@echo "VaultysID Go Implementation - Available targets:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Use 'make <target>' to run a specific target."

.DEFAULT_GOAL := help
