#!/bin/bash

# eBPF Network Monitor Development Environment Setup
# This script sets up the development environment for the eBPF monitor project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GO_VERSION="1.21.0"
PROTOC_VERSION="24.4"
PROJECT_DIR=$(pwd)

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release
            DISTRO=$NAME
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="darwin"
        DISTRO="macOS"
    else
        log_error "Unsupported OS: $OSTYPE"
        exit 1
    fi
    log_info "Detected OS: $DISTRO"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

install_go() {
    log_info "Checking Go installation..."
    
    if check_command go; then
        CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Found Go version: $CURRENT_GO_VERSION"
        
        if [[ "$CURRENT_GO_VERSION" == "$GO_VERSION"* ]]; then
            log_success "Go is already installed with correct version"
            return
        fi
    fi
    
    log_info "Installing Go $GO_VERSION..."
    
    # Determine architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="armv6l" ;;
        *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    # Download and install Go
    GO_TARBALL="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
    GO_URL="https://golang.org/dl/${GO_TARBALL}"
    
    cd /tmp
    curl -LO "$GO_URL"
    
    # Remove existing Go installation
    sudo rm -rf /usr/local/go
    
    # Extract new Go
    sudo tar -C /usr/local -xzf "$GO_TARBALL"
    
    # Add to PATH if not already there
    if ! echo "$PATH" | grep -q "/usr/local/go/bin"; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc 2>/dev/null || true
        export PATH=$PATH:/usr/local/go/bin
    fi
    
    cd "$PROJECT_DIR"
    log_success "Go $GO_VERSION installed successfully"
}

install_system_deps() {
    log_info "Installing system dependencies..."
    
    if [[ "$OS" == "linux" ]]; then
        if [[ "$DISTRO" == *"Ubuntu"* ]] || [[ "$DISTRO" == *"Debian"* ]]; then
            sudo apt-get update
            sudo apt-get install -y \
                clang \
                llvm \
                libbpf-dev \
                linux-headers-$(uname -r) \
                protobuf-compiler \
                build-essential \
                git \
                curl \
                pkg-config \
                libssl-dev
        elif [[ "$DISTRO" == *"CentOS"* ]] || [[ "$DISTRO" == *"Red Hat"* ]] || [[ "$DISTRO" == *"Rocky"* ]]; then
            sudo yum update -y
            sudo yum install -y \
                clang \
                llvm \
                libbpf-devel \
                kernel-headers \
                kernel-devel \
                protobuf-compiler \
                gcc \
                git \
                curl \
                pkgconfig \
                openssl-devel
        else
            log_warning "Unknown Linux distribution. Please install dependencies manually."
        fi
    elif [[ "$OS" == "darwin" ]]; then
        if check_command brew; then
            brew install clang-format protobuf llvm
        else
            log_error "Homebrew not found. Please install Homebrew first."
            exit 1
        fi
    fi
    
    log_success "System dependencies installed"
}

install_protoc() {
    log_info "Checking Protocol Buffers compiler..."
    
    if check_command protoc; then
        CURRENT_PROTOC_VERSION=$(protoc --version | awk '{print $2}')
        log_info "Found protoc version: $CURRENT_PROTOC_VERSION"
        
        if [[ "$CURRENT_PROTOC_VERSION" == "$PROTOC_VERSION"* ]]; then
            log_success "protoc is already installed with correct version"
            return
        fi
    fi
    
    log_info "Installing protoc $PROTOC_VERSION..."
    
    # Determine architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) PROTOC_ARCH="x86_64" ;;
        aarch64) PROTOC_ARCH="aarch_64" ;;
        *) log_error "Unsupported architecture for protoc: $ARCH"; exit 1 ;;
    esac
    
    # Download and install protoc
    PROTOC_ZIP="protoc-${PROTOC_VERSION}-${OS}-${PROTOC_ARCH}.zip"
    PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${PROTOC_ZIP}"
    
    cd /tmp
    curl -LO "$PROTOC_URL"
    unzip -o "$PROTOC_ZIP" -d protoc
    
    sudo cp protoc/bin/protoc /usr/local/bin/
    sudo cp -r protoc/include/* /usr/local/include/
    
    rm -rf protoc "$PROTOC_ZIP"
    
    cd "$PROJECT_DIR"
    log_success "protoc $PROTOC_VERSION installed successfully"
}

install_go_tools() {
    log_info "Installing Go development tools..."
    
    # Protocol Buffers Go plugins
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    
    # Code formatting and linting tools
    go install golang.org/x/tools/cmd/goimports@latest
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    
    # Testing tools
    go install github.com/onsi/ginkgo/v2/ginkgo@latest
    go install github.com/onsi/gomega/...@latest
    
    # eBPF tools
    go install github.com/cilium/ebpf/cmd/bpf2go@latest
    
    # Add GOPATH/bin to PATH if not already there
    GOPATH=$(go env GOPATH)
    if ! echo "$PATH" | grep -q "$GOPATH/bin"; then
        echo "export PATH=\$PATH:$GOPATH/bin" >> ~/.bashrc
        echo "export PATH=\$PATH:$GOPATH/bin" >> ~/.zshrc 2>/dev/null || true
        export PATH=$PATH:$GOPATH/bin
    fi
    
    log_success "Go tools installed successfully"
}

setup_git_hooks() {
    log_info "Setting up Git hooks..."
    
    if [[ ! -d ".git" ]]; then
        log_warning "Not a Git repository. Skipping Git hooks setup."
        return
    fi
    
    # Create pre-commit hook
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash

# Pre-commit hook for eBPF Monitor project

set -e

echo "Running pre-commit checks..."

# Format Go code
echo "Formatting Go code..."
gofmt -w .
goimports -w .

# Run linter
echo "Running linter..."
golangci-lint run

# Run tests
echo "Running tests..."
go test ./...

# Build project
echo "Building project..."
make build

echo "Pre-commit checks passed!"
EOF
    
    chmod +x .git/hooks/pre-commit
    
    log_success "Git hooks configured"
}

setup_vscode() {
    log_info "Setting up VS Code configuration..."
    
    mkdir -p .vscode
    
    # VS Code settings
    cat > .vscode/settings.json << 'EOF'
{
    "go.toolsManagement.checkForUpdates": "local",
    "go.useLanguageServer": true,
    "go.gopath": "",
    "go.goroot": "",
    "go.lintTool": "golangci-lint",
    "go.lintFlags": [
        "--fast"
    ],
    "go.formatTool": "goimports",
    "go.testFlags": [
        "-v",
        "-race"
    ],
    "go.buildTags": "integration",
    "go.testTimeout": "30s",
    "files.exclude": {
        "**/.git": true,
        "**/.DS_Store": true,
        "**/node_modules": true,
        "**/*.o": true,
        "**/*.so": true
    },
    "C_Cpp.default.includePath": [
        "/usr/include",
        "/usr/local/include",
        "/usr/include/linux"
    ],
    "C_Cpp.default.defines": [
        "__BPF__"
    ],
    "files.associations": {
        "*.bpf.c": "c",
        "*.h": "c"
    }
}
EOF
    
    # VS Code launch configuration
    cat > .vscode/launch.json << 'EOF'
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch eBPF Monitor",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}/cmd/monitor",
            "args": [
                "-config=${workspaceFolder}/config.toml",
                "-log-level=debug",
                "-interface=lo"
            ],
            "env": {},
            "showLog": true,
            "preLaunchTask": "build"
        },
        {
            "name": "Debug Test",
            "type": "go",
            "request": "launch",
            "mode": "test",
            "program": "${workspaceFolder}",
            "args": [
                "-test.v"
            ]
        }
    ]
}
EOF
    
    # VS Code tasks
    cat > .vscode/tasks.json << 'EOF'
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "build",
            "type": "shell",
            "command": "make",
            "args": ["build"],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "presentation": {
                "echo": true,
                "reveal": "silent",
                "focus": false,
                "panel": "shared"
            },
            "problemMatcher": "$go"
        },
        {
            "label": "test",
            "type": "shell",
            "command": "make",
            "args": ["test"],
            "group": "test",
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "shared"
            }
        },
        {
            "label": "clean",
            "type": "shell",
            "command": "make",
            "args": ["clean"],
            "group": "build"
        }
    ]
}
EOF
    
    # VS Code extensions recommendations
    cat > .vscode/extensions.json << 'EOF'
{
    "recommendations": [
        "golang.go",
        "ms-vscode.cpptools",
        "ms-vscode.cmake-tools",
        "vadimcn.vscode-lldb",
        "zxh404.vscode-proto3",
        "ms-vscode.vscode-json",
        "redhat.vscode-yaml",
        "ms-vscode.makefile-tools"
    ]
}
EOF
    
    log_success "VS Code configuration created"
}

setup_project() {
    log_info "Setting up project dependencies..."
    
    # Download Go modules
    go mod download
    go mod tidy
    
    # Generate protobuf files
    if [[ -f "proto/monitor.proto" ]]; then
        make proto
        log_success "Protocol buffer files generated"
    fi
    
    # Build eBPF programs
    if [[ -f "ebpf/network_monitor.c" ]]; then
        make ebpf
        log_success "eBPF programs compiled"
    fi
    
    log_success "Project setup completed"
}

check_ebpf_support() {
    log_info "Checking eBPF support..."
    
    if [[ "$OS" != "linux" ]]; then
        log_warning "eBPF is only supported on Linux. Development on other platforms is limited."
        return
    fi
    
    # Check kernel version
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    REQUIRED_VERSION="4.18"
    
    if ! awk "BEGIN {exit !($KERNEL_VERSION >= $REQUIRED_VERSION)}"; then
        log_warning "Kernel version $KERNEL_VERSION may not fully support eBPF. Minimum recommended: $REQUIRED_VERSION"
    else
        log_success "Kernel version $KERNEL_VERSION supports eBPF"
    fi
    
    # Check if BPF filesystem is mounted
    if mount | grep -q "/sys/fs/bpf"; then
        log_success "BPF filesystem is mounted"
    else
        log_warning "BPF filesystem is not mounted. Some features may not work."
        log_info "To mount: sudo mount -t bpf bpf /sys/fs/bpf"
    fi
}

show_summary() {
    echo
    echo "=== Development Environment Setup Complete ==="
    echo
    echo "Tools installed:"
    echo "  - Go: $(go version 2>/dev/null || echo 'Not found')"
    echo "  - protoc: $(protoc --version 2>/dev/null || echo 'Not found')"
    echo "  - clang: $(clang --version 2>/dev/null | head -n1 || echo 'Not found')"
    echo
    echo "Next steps:"
    echo "  1. Source your shell profile: source ~/.bashrc (or restart terminal)"
    echo "  2. Build the project: make build"
    echo "  3. Run tests: make test"
    echo "  4. Start development: make dev"
    echo
    echo "Useful commands:"
    echo "  - Build: make build"
    echo "  - Test: make test"
    echo "  - Clean: make clean"
    echo "  - Format: make fmt"
    echo "  - Lint: make lint"
    echo "  - Generate protobuf: make proto"
    echo
    echo "VS Code:"
    echo "  - Configuration files created in .vscode/"
    echo "  - Install recommended extensions when prompted"
    echo "  - Use Ctrl+Shift+P -> 'Go: Install/Update Tools' to install Go tools"
}

# Main setup function
setup() {
    log_info "Starting development environment setup..."
    
    detect_os
    install_system_deps
    install_go
    install_protoc
    install_go_tools
    setup_git_hooks
    setup_vscode
    setup_project
    check_ebpf_support
    show_summary
    
    log_success "Development environment setup completed!"
}

# Script usage
usage() {
    echo "Usage: $0 [setup|check]"
    echo "  setup - Set up development environment"
    echo "  check - Check current environment"
    exit 1
}

check_env() {
    echo "=== Environment Check ==="
    echo
    echo "Operating System: $(uname -s) $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo
    echo "Tools:"
    echo "  Go: $(go version 2>/dev/null || echo 'Not installed')"
    echo "  protoc: $(protoc --version 2>/dev/null || echo 'Not installed')"
    echo "  clang: $(clang --version 2>/dev/null | head -n1 || echo 'Not installed')"
    echo "  git: $(git --version 2>/dev/null || echo 'Not installed')"
    echo
    echo "Go environment:"
    if check_command go; then
        echo "  GOROOT: $(go env GOROOT)"
        echo "  GOPATH: $(go env GOPATH)"
        echo "  GOOS: $(go env GOOS)"
        echo "  GOARCH: $(go env GOARCH)"
    fi
    echo
    echo "Project status:"
    if [[ -f "go.mod" ]]; then
        echo "  Go module: ✓"
    else
        echo "  Go module: ✗"
    fi
    
    if [[ -f "Makefile" ]]; then
        echo "  Makefile: ✓"
    else
        echo "  Makefile: ✗"
    fi
    
    if [[ -d ".vscode" ]]; then
        echo "  VS Code config: ✓"
    else
        echo "  VS Code config: ✗"
    fi
}

# Main script logic
case "${1:-setup}" in
    setup)
        setup
        ;;
    check)
        check_env
        ;;
    *)
        usage
        ;;
esac