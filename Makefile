# eBPF Network Monitor Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
BINARY_NAME=ebpf-monitor
BINARY_UNIX=$(BINARY_NAME)_unix

# Directories
CMD_DIR=./cmd/monitor
EBPF_DIR=./ebpf
PROTO_DIR=./proto
INTERNAL_DIR=./internal

# eBPF parameters
CLANG=clang
LLC=llc
EBPF_CFLAGS=-O2 -g -Wall -Werror -target bpf

.PHONY: all build clean test deps proto ebpf help

# Default target
all: deps proto ebpf build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) -o $(BINARY_NAME) -v $(CMD_DIR)

# Build for Linux
build-linux:
	@echo "Building $(BINARY_NAME) for Linux..."
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v $(CMD_DIR)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f $(EBPF_DIR)/*.o
	rm -f $(INTERNAL_DIR)/ebpf/*.go
	rm -f $(PROTO_DIR)/*.pb.go

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOGET) -d -v ./...
	$(GOMOD) tidy
	$(GOMOD) verify

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@if ! command -v protoc >/dev/null 2>&1; then \
		echo "Error: protoc is not installed. Please install Protocol Buffers compiler."; \
		echo "Ubuntu/Debian: sudo apt-get install protobuf-compiler"; \
		echo "CentOS/RHEL: sudo yum install protobuf-compiler"; \
		echo "macOS: brew install protobuf"; \
		exit 1; \
	fi
	@if ! $(GOCMD) list -m google.golang.org/protobuf >/dev/null 2>&1; then \
		echo "Installing protobuf Go plugin..."; \
		$(GOGET) google.golang.org/protobuf/cmd/protoc-gen-go; \
		$(GOGET) google.golang.org/grpc/cmd/protoc-gen-go-grpc; \
	fi
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/monitor.proto

# Compile eBPF programs
ebpf:
	@echo "Compiling eBPF programs..."
	@if ! command -v $(CLANG) >/dev/null 2>&1; then \
		echo "Error: clang is not installed. Please install clang."; \
		echo "Ubuntu/Debian: sudo apt-get install clang"; \
		echo "CentOS/RHEL: sudo yum install clang"; \
		exit 1; \
	fi
	@if ! $(GOCMD) list -m github.com/cilium/ebpf >/dev/null 2>&1; then \
		echo "Installing eBPF Go tools..."; \
		$(GOGET) github.com/cilium/ebpf/cmd/bpf2go; \
	fi
	@echo "Generating eBPF Go bindings..."
	cd $(INTERNAL_DIR)/ebpf && $(GOCMD) generate

# Install system dependencies (Ubuntu/Debian)
install-deps-ubuntu:
	@echo "Installing system dependencies for Ubuntu/Debian..."
	sudo apt-get update
	sudo apt-get install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-headers-$(shell uname -r) \
		protobuf-compiler \
		build-essential \
		git

# Install system dependencies (CentOS/RHEL)
install-deps-centos:
	@echo "Installing system dependencies for CentOS/RHEL..."
	sudo yum update -y
	sudo yum install -y \
		clang \
		llvm \
		libbpf-devel \
		kernel-headers \
		kernel-devel \
		protobuf-compiler \
		gcc \
		git

# Run the monitor (requires root privileges)
run:
	@echo "Starting eBPF monitor (requires root privileges)..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: This program requires root privileges to load eBPF programs."; \
		echo "Please run with sudo: sudo make run"; \
		exit 1; \
	fi
	./$(BINARY_NAME) -config=config.toml -log-level=info -interface=eth0

# Run with custom interface
run-interface:
	@echo "Starting eBPF monitor on interface $(INTERFACE)..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: This program requires root privileges to load eBPF programs."; \
		echo "Please run with sudo: sudo make run-interface INTERFACE=<interface_name>"; \
		exit 1; \
	fi
	@if [ -z "$(INTERFACE)" ]; then \
		echo "Error: Please specify INTERFACE. Example: make run-interface INTERFACE=eth0"; \
		exit 1; \
	fi
	./$(BINARY_NAME) -config=config.toml -log-level=info -interface=$(INTERFACE)

# Development build (with debug symbols)
dev-build:
	@echo "Building development version..."
	$(GOBUILD) -gcflags="-N -l" -o $(BINARY_NAME) -v $(CMD_DIR)

# Create release package
release: clean all
	@echo "Creating release package..."
	mkdir -p release
	cp $(BINARY_NAME) release/
	cp config.toml release/
	cp README.md release/ 2>/dev/null || echo "README.md not found, skipping"
	tar -czf release/$(BINARY_NAME)-$(shell date +%Y%m%d-%H%M%S).tar.gz -C release $(BINARY_NAME) config.toml README.md 2>/dev/null || tar -czf release/$(BINARY_NAME)-$(shell date +%Y%m%d-%H%M%S).tar.gz -C release $(BINARY_NAME) config.toml
	@echo "Release package created in release/ directory"

# Docker build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):latest .

# Show available network interfaces
show-interfaces:
	@echo "Available network interfaces:"
	@ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | sed 's/^ *//'

# Check eBPF support
check-ebpf:
	@echo "Checking eBPF support..."
	@if [ ! -d "/sys/fs/bpf" ]; then \
		echo "Warning: BPF filesystem not mounted. Mounting..."; \
		sudo mount -t bpf bpf /sys/fs/bpf; \
	fi
	@if [ -r "/proc/config.gz" ]; then \
		echo "Checking kernel config..."; \
		zcat /proc/config.gz | grep -E "CONFIG_BPF|CONFIG_XDP" | head -10; \
	elif [ -r "/boot/config-$(shell uname -r)" ]; then \
		echo "Checking kernel config..."; \
		grep -E "CONFIG_BPF|CONFIG_XDP" /boot/config-$(shell uname -r) | head -10; \
	else \
		echo "Kernel config not found, but eBPF should work on most modern kernels"; \
	fi
	@echo "Kernel version: $(shell uname -r)"
	@echo "eBPF check completed"

# Format code
fmt:
	@echo "Formatting Go code..."
	$(GOCMD) fmt ./...

# Lint code
lint:
	@echo "Linting Go code..."
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v1.54.2; \
	fi
	golangci-lint run

# Script targets
dev-setup:
	@echo "Setting up development environment..."
	@chmod +x scripts/dev-setup.sh
	@./scripts/dev-setup.sh

deploy:
	@echo "Deploying eBPF monitor..."
	@chmod +x scripts/deploy.sh
	@sudo ./scripts/deploy.sh

test-all:
	@echo "Running comprehensive tests..."
	@chmod +x scripts/test.sh
	@sudo ./scripts/test.sh

benchmark:
	@echo "Running performance benchmarks..."
	@chmod +x scripts/benchmark.sh
	@sudo ./scripts/benchmark.sh

monitor-status:
	@echo "Checking monitor status..."
	@chmod +x scripts/monitor.sh
	@./scripts/monitor.sh status

monitor-watch:
	@echo "Watching monitor status..."
	@chmod +x scripts/monitor.sh
	@./scripts/monitor.sh watch

monitor-logs:
	@echo "Showing monitor logs..."
	@chmod +x scripts/monitor.sh
	@./scripts/monitor.sh logs

service-start:
	@echo "Starting eBPF monitor service..."
	@chmod +x scripts/monitor.sh
	@sudo ./scripts/monitor.sh start

service-stop:
	@echo "Stopping eBPF monitor service..."
	@chmod +x scripts/monitor.sh
	@sudo ./scripts/monitor.sh stop

service-restart:
	@echo "Restarting eBPF monitor service..."
	@chmod +x scripts/monitor.sh
	@sudo ./scripts/monitor.sh restart

test-api:
	@echo "Testing gRPC API..."
	@chmod +x scripts/monitor.sh
	@./scripts/monitor.sh test-api

# Make all scripts executable
scripts-setup:
	@echo "Making scripts executable..."
	@chmod +x scripts/*.sh
	@echo "Scripts are now executable"

# Show help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  build       - Build the eBPF monitor binary"
	@echo "  build-linux - Build for Linux (cross-compile)"
	@echo "  clean       - Clean build artifacts"
	@echo "  release     - Build release version"
	@echo "  docker      - Build Docker image"
	@echo ""
	@echo "Development targets:"
	@echo "  dev-setup   - Set up development environment"
	@echo "  dev         - Development build and run"
	@echo "  test        - Run unit tests"
	@echo "  test-all    - Run comprehensive tests"
	@echo "  benchmark   - Run performance benchmarks"
	@echo "  fmt         - Format code"
	@echo "  lint        - Run linter"
	@echo ""
	@echo "Deployment targets:"
	@echo "  deploy      - Deploy eBPF monitor to system"
	@echo "  service-start   - Start the service"
	@echo "  service-stop    - Stop the service"
	@echo "  service-restart - Restart the service"
	@echo ""
	@echo "Monitoring targets:"
	@echo "  monitor-status - Show current status"
	@echo "  monitor-watch  - Watch status in real-time"
	@echo "  monitor-logs   - Show recent logs"
	@echo "  test-api       - Test gRPC API endpoints"
	@echo ""
	@echo "Utility targets:"
	@echo "  deps        - Download dependencies"
	@echo "  proto       - Generate protobuf files"
	@echo "  ebpf        - Compile eBPF programs"
	@echo "  scripts-setup - Make all scripts executable"
	@echo "  install-deps-ubuntu - Install system dependencies (Ubuntu/Debian)"
	@echo "  install-deps-centos - Install system dependencies (CentOS/RHEL)"
	@echo "  show-interfaces - Show available network interfaces"
	@echo "  check-ebpf  - Check eBPF support"
	@echo "  run         - Run the monitor (requires root)"