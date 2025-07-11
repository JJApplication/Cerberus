#!/bin/bash

# eBPF Network Monitor Test Script
# This script runs comprehensive tests for the eBPF monitor project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_CONFIG="test-config.toml"
TEST_DB="test-monitor.db"
TEST_SOCKET="/tmp/test-ebpf-monitor.sock"
TEST_INTERFACE="lo"
TEST_TIMEOUT=30

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

cleanup() {
    log_info "Cleaning up test environment..."
    
    # Kill test processes
    if [[ -n "$MONITOR_PID" ]]; then
        kill $MONITOR_PID 2>/dev/null || true
        wait $MONITOR_PID 2>/dev/null || true
    fi
    
    # Remove test files
    rm -f "$TEST_CONFIG" "$TEST_DB" "$TEST_SOCKET"
    
    # Remove test network namespace if created
    if [[ -n "$TEST_NETNS" ]]; then
        sudo ip netns delete "$TEST_NETNS" 2>/dev/null || true
    fi
    
    log_success "Cleanup completed"
}

# Set up cleanup on exit
trap cleanup EXIT

check_requirements() {
    log_info "Checking test requirements..."
    
    # Check if running on Linux
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "Tests can only run on Linux"
        exit 1
    fi
    
    # Check if running as root (required for eBPF)
    if [[ $EUID -ne 0 ]]; then
        log_error "Tests must be run as root (required for eBPF)"
        exit 1
    fi
    
    # Check required commands
    local required_commands=("go" "clang" "curl" "nc" "ss" "ip")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Check if project is built
    if [[ ! -f "./ebpf-monitor" ]]; then
        log_info "Building project..."
        make build
    fi
    
    log_success "Requirements check passed"
}

create_test_config() {
    log_info "Creating test configuration..."
    
    cat > "$TEST_CONFIG" << EOF
[network]
max_connections_per_ip = 5
ban_duration_minutes = 1
monitoring_interval_seconds = 1
malicious_url_patterns = [
    "/admin",
    "/wp-admin",
    "/.env",
    "/config",
    "/test-malicious"
]

[system]
cpu_threshold_percent = 80.0
memory_threshold_percent = 85.0
disk_io_threshold_mbps = 100.0
monitoring_window_minutes = 1

[grpc]
listen_address = "127.0.0.1:50052"
uds_socket_path = "$TEST_SOCKET"

[database]
sqlite_path = "$TEST_DB"
max_records = 1000
cleanup_interval_hours = 1
EOF
    
    log_success "Test configuration created"
}

start_monitor() {
    log_info "Starting eBPF monitor for testing..."
    
    # Start monitor in background
    ./ebpf-monitor -config="$TEST_CONFIG" -log-level=debug -interface="$TEST_INTERFACE" &
    MONITOR_PID=$!
    
    # Wait for monitor to start
    sleep 5
    
    # Check if monitor is running
    if ! kill -0 $MONITOR_PID 2>/dev/null; then
        log_error "Failed to start eBPF monitor"
        exit 1
    fi
    
    # Wait for gRPC server to be ready
    local retries=10
    while [[ $retries -gt 0 ]]; do
        if nc -z 127.0.0.1 50052 2>/dev/null; then
            break
        fi
        sleep 1
        ((retries--))
    done
    
    if [[ $retries -eq 0 ]]; then
        log_error "gRPC server failed to start"
        exit 1
    fi
    
    log_success "eBPF monitor started (PID: $MONITOR_PID)"
}

test_unit() {
    log_info "Running unit tests..."
    
    # Run Go unit tests
    go test -v -race -timeout=30s ./...
    
    log_success "Unit tests passed"
}

test_build() {
    log_info "Testing build process..."
    
    # Clean and rebuild
    make clean
    make build
    
    # Check if binary exists and is executable
    if [[ ! -x "./ebpf-monitor" ]]; then
        log_error "Build failed: binary not found or not executable"
        exit 1
    fi
    
    log_success "Build test passed"
}

test_config() {
    log_info "Testing configuration loading..."
    
    # Test with valid config
    timeout 5s ./ebpf-monitor -config="$TEST_CONFIG" -dry-run || true
    
    # Test with invalid config
    echo "invalid toml" > invalid-config.toml
    if timeout 5s ./ebpf-monitor -config=invalid-config.toml -dry-run 2>/dev/null; then
        log_error "Should have failed with invalid config"
        exit 1
    fi
    rm -f invalid-config.toml
    
    log_success "Configuration test passed"
}

test_database() {
    log_info "Testing database operations..."
    
    # Start monitor to initialize database
    start_monitor
    
    # Wait a moment for database initialization
    sleep 2
    
    # Check if database file exists
    if [[ ! -f "$TEST_DB" ]]; then
        log_error "Database file not created"
        exit 1
    fi
    
    # Check database tables using sqlite3 if available
    if command -v sqlite3 &> /dev/null; then
        local tables=$(sqlite3 "$TEST_DB" ".tables")
        if [[ ! "$tables" =~ "malicious_ips" ]] || [[ ! "$tables" =~ "network_stats" ]] || [[ ! "$tables" =~ "system_anomalies" ]]; then
            log_error "Required database tables not found"
            exit 1
        fi
    fi
    
    # Stop monitor
    kill $MONITOR_PID
    wait $MONITOR_PID 2>/dev/null || true
    MONITOR_PID=""
    
    log_success "Database test passed"
}

test_grpc_api() {
    log_info "Testing gRPC API..."
    
    start_monitor
    
    # Test using the example client if available
    if [[ -f "examples/client/main.go" ]]; then
        log_info "Building test client..."
        go build -o test-client examples/client/main.go
        
        # Test getting monitor status
        if ! timeout 10s ./test-client -addr=127.0.0.1:50052 -action=status; then
            log_error "Failed to get monitor status via gRPC"
            exit 1
        fi
        
        # Test getting malicious IPs
        timeout 10s ./test-client -addr=127.0.0.1:50052 -action=malicious-ips || true
        
        rm -f test-client
    else
        log_warning "gRPC client example not found, skipping detailed API tests"
    fi
    
    # Stop monitor
    kill $MONITOR_PID
    wait $MONITOR_PID 2>/dev/null || true
    MONITOR_PID=""
    
    log_success "gRPC API test passed"
}

test_network_monitoring() {
    log_info "Testing network monitoring..."
    
    start_monitor
    
    # Generate some network traffic to localhost
    log_info "Generating test network traffic..."
    
    # Test normal traffic
    curl -s http://127.0.0.1:80/ 2>/dev/null || true
    
    # Test malicious URL patterns
    curl -s http://127.0.0.1:80/test-malicious 2>/dev/null || true
    curl -s http://127.0.0.1:80/admin 2>/dev/null || true
    curl -s http://127.0.0.1:80/.env 2>/dev/null || true
    
    # Generate multiple connections from same IP (should trigger rate limiting)
    for i in {1..10}; do
        curl -s http://127.0.0.1:80/ 2>/dev/null || true
    done
    
    # Wait for monitoring to process events
    sleep 5
    
    # Check if events were recorded (using client if available)
    if [[ -f "examples/client/main.go" ]]; then
        go build -o test-client examples/client/main.go
        timeout 10s ./test-client -addr=127.0.0.1:50052 -action=network-stats || true
        rm -f test-client
    fi
    
    # Stop monitor
    kill $MONITOR_PID
    wait $MONITOR_PID 2>/dev/null || true
    MONITOR_PID=""
    
    log_success "Network monitoring test completed"
}

test_system_monitoring() {
    log_info "Testing system monitoring..."
    
    start_monitor
    
    # Generate some CPU load
    log_info "Generating test system load..."
    
    # Create a short CPU-intensive task
    timeout 5s bash -c 'while true; do :; done' &
    LOAD_PID=$!
    
    # Wait for monitoring to detect the load
    sleep 10
    
    # Kill the load generator
    kill $LOAD_PID 2>/dev/null || true
    wait $LOAD_PID 2>/dev/null || true
    
    # Check if system anomalies were recorded
    if [[ -f "examples/client/main.go" ]]; then
        go build -o test-client examples/client/main.go
        timeout 10s ./test-client -addr=127.0.0.1:50052 -action=system-anomalies || true
        rm -f test-client
    fi
    
    # Stop monitor
    kill $MONITOR_PID
    wait $MONITOR_PID 2>/dev/null || true
    MONITOR_PID=""
    
    log_success "System monitoring test completed"
}

test_performance() {
    log_info "Running performance tests..."
    
    start_monitor
    
    # Monitor resource usage of the eBPF monitor itself
    local start_time=$(date +%s)
    local initial_memory=$(ps -o rss= -p $MONITOR_PID)
    
    # Generate sustained load for performance testing
    log_info "Generating sustained load for performance testing..."
    
    # Generate network traffic
    for i in {1..100}; do
        curl -s http://127.0.0.1:80/ 2>/dev/null || true &
    done
    
    # Wait for all background jobs
    wait
    
    # Check resource usage after load
    sleep 5
    local end_time=$(date +%s)
    local final_memory=$(ps -o rss= -p $MONITOR_PID 2>/dev/null || echo "0")
    
    local duration=$((end_time - start_time))
    local memory_increase=$((final_memory - initial_memory))
    
    log_info "Performance test results:"
    log_info "  Duration: ${duration}s"
    log_info "  Initial memory: ${initial_memory}KB"
    log_info "  Final memory: ${final_memory}KB"
    log_info "  Memory increase: ${memory_increase}KB"
    
    # Basic performance checks
    if [[ $memory_increase -gt 100000 ]]; then  # 100MB
        log_warning "High memory usage increase detected: ${memory_increase}KB"
    fi
    
    # Stop monitor
    kill $MONITOR_PID
    wait $MONITOR_PID 2>/dev/null || true
    MONITOR_PID=""
    
    log_success "Performance test completed"
}

test_integration() {
    log_info "Running integration tests..."
    
    # Test the complete workflow
    start_monitor
    
    # Simulate a complete attack scenario
    log_info "Simulating attack scenario..."
    
    # 1. Generate malicious requests
    for url in "/admin" "/.env" "/config"; do
        curl -s "http://127.0.0.1:80$url" 2>/dev/null || true
    done
    
    # 2. Generate high frequency requests
    for i in {1..20}; do
        curl -s http://127.0.0.1:80/ 2>/dev/null || true
    done
    
    # 3. Wait for processing
    sleep 10
    
    # 4. Check if IP was banned (using client if available)
    if [[ -f "examples/client/main.go" ]]; then
        go build -o test-client examples/client/main.go
        
        # Get malicious IPs
        timeout 10s ./test-client -addr=127.0.0.1:50052 -action=malicious-ips
        
        # Get network stats
        timeout 10s ./test-client -addr=127.0.0.1:50052 -action=network-stats
        
        rm -f test-client
    fi
    
    # Stop monitor
    kill $MONITOR_PID
    wait $MONITOR_PID 2>/dev/null || true
    MONITOR_PID=""
    
    log_success "Integration test completed"
}

run_all_tests() {
    log_info "Starting comprehensive test suite..."
    
    local start_time=$(date +%s)
    
    # Run tests in order
    test_unit
    test_build
    test_config
    test_database
    test_grpc_api
    test_network_monitoring
    test_system_monitoring
    test_performance
    test_integration
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "All tests completed successfully in ${duration}s"
}

show_test_report() {
    echo
    echo "=== Test Report ==="
    echo "Test configuration: $TEST_CONFIG"
    echo "Test database: $TEST_DB"
    echo "Test socket: $TEST_SOCKET"
    echo "Test interface: $TEST_INTERFACE"
    echo
    echo "Test artifacts:"
    if [[ -f "$TEST_DB" ]]; then
        echo "  Database size: $(du -h "$TEST_DB" | cut -f1)"
        if command -v sqlite3 &> /dev/null; then
            echo "  Malicious IPs: $(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM malicious_ips;" 2>/dev/null || echo "N/A")"
            echo "  Network stats: $(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM network_stats;" 2>/dev/null || echo "N/A")"
            echo "  System anomalies: $(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM system_anomalies;" 2>/dev/null || echo "N/A")"
        fi
    fi
    echo
}

# Script usage
usage() {
    echo "Usage: $0 [test_type]"
    echo "Test types:"
    echo "  all         - Run all tests (default)"
    echo "  unit        - Run unit tests only"
    echo "  build       - Test build process"
    echo "  config      - Test configuration loading"
    echo "  database    - Test database operations"
    echo "  grpc        - Test gRPC API"
    echo "  network     - Test network monitoring"
    echo "  system      - Test system monitoring"
    echo "  performance - Run performance tests"
    echo "  integration - Run integration tests"
    exit 1
}

# Main script logic
check_requirements
create_test_config

case "${1:-all}" in
    all)
        run_all_tests
        show_test_report
        ;;
    unit)
        test_unit
        ;;
    build)
        test_build
        ;;
    config)
        test_config
        ;;
    database)
        test_database
        show_test_report
        ;;
    grpc)
        test_grpc_api
        ;;
    network)
        test_network_monitoring
        show_test_report
        ;;
    system)
        test_system_monitoring
        show_test_report
        ;;
    performance)
        test_performance
        ;;
    integration)
        test_integration
        show_test_report
        ;;
    *)
        usage
        ;;
esac

log_success "Test execution completed!"