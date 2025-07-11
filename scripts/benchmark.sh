#!/bin/bash

# eBPF Network Monitor Benchmark Script
# This script runs performance benchmarks for the eBPF monitor project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BENCH_CONFIG="bench-config.toml"
BENCH_DB="bench-monitor.db"
BENCH_SOCKET="/tmp/bench-ebpf-monitor.sock"
BENCH_INTERFACE="lo"
BENCH_DURATION=60  # seconds
BENCH_RESULTS_DIR="benchmark_results"
BENCH_TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Benchmark parameters
CONCURRENT_CONNECTIONS=(1 10 50 100 500 1000)
REQUEST_RATES=(10 100 1000 5000 10000)  # requests per second
PAYLOAD_SIZES=(64 512 1024 4096 8192)   # bytes

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
    log_info "Cleaning up benchmark environment..."
    
    # Kill benchmark processes
    if [[ -n "$MONITOR_PID" ]]; then
        kill $MONITOR_PID 2>/dev/null || true
        wait $MONITOR_PID 2>/dev/null || true
    fi
    
    if [[ -n "$HTTP_SERVER_PID" ]]; then
        kill $HTTP_SERVER_PID 2>/dev/null || true
        wait $HTTP_SERVER_PID 2>/dev/null || true
    fi
    
    # Kill any remaining benchmark processes
    pkill -f "benchmark" 2>/dev/null || true
    pkill -f "wrk" 2>/dev/null || true
    pkill -f "ab" 2>/dev/null || true
    
    # Remove temporary files
    rm -f "$BENCH_CONFIG" "$BENCH_DB" "$BENCH_SOCKET"
    
    log_success "Cleanup completed"
}

# Set up cleanup on exit
trap cleanup EXIT

check_requirements() {
    log_info "Checking benchmark requirements..."
    
    # Check if running on Linux
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "Benchmarks can only run on Linux"
        exit 1
    fi
    
    # Check if running as root (required for eBPF)
    if [[ $EUID -ne 0 ]]; then
        log_error "Benchmarks must be run as root (required for eBPF)"
        exit 1
    fi
    
    # Check required commands
    local required_commands=("go" "clang" "curl" "nc" "ss" "ip" "sar" "iostat" "free")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Check optional but recommended tools
    local optional_commands=("wrk" "ab" "iperf3" "htop")
    for cmd in "${optional_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_warning "Optional tool not found: $cmd (some benchmarks may be skipped)"
        fi
    done
    
    # Check if project is built
    if [[ ! -f "./ebpf-monitor" ]]; then
        log_info "Building project..."
        make build
    fi
    
    # Create results directory
    mkdir -p "$BENCH_RESULTS_DIR"
    
    log_success "Requirements check passed"
}

create_bench_config() {
    log_info "Creating benchmark configuration..."
    
    cat > "$BENCH_CONFIG" << EOF
[network]
max_connections_per_ip = 10000
ban_duration_minutes = 60
monitoring_interval_seconds = 1
malicious_url_patterns = [
    "/admin",
    "/wp-admin",
    "/.env",
    "/config",
    "/bench-malicious"
]

[system]
cpu_threshold_percent = 95.0
memory_threshold_percent = 95.0
disk_io_threshold_mbps = 1000.0
monitoring_window_minutes = 1

[grpc]
listen_address = "127.0.0.1:50053"
uds_socket_path = "$BENCH_SOCKET"

[database]
sqlite_path = "$BENCH_DB"
max_records = 100000
cleanup_interval_hours = 24
EOF
    
    log_success "Benchmark configuration created"
}

start_http_server() {
    log_info "Starting HTTP test server..."
    
    # Create a simple HTTP server for testing
    cat > http_server.py << 'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import threading
import time
import random
import string

class BenchmarkHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Simulate different response times
        if '/slow' in self.path:
            time.sleep(0.1)
        elif '/fast' in self.path:
            time.sleep(0.001)
        
        # Generate response
        if '/large' in self.path:
            content = ''.join(random.choices(string.ascii_letters, k=8192))
        else:
            content = 'OK'
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-length', str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode())
    
    def log_message(self, format, *args):
        # Suppress logging for benchmarks
        pass

if __name__ == '__main__':
    PORT = 8080
    with socketserver.TCPServer(("", PORT), BenchmarkHandler) as httpd:
        print(f"Server running on port {PORT}")
        httpd.serve_forever()
EOF
    
    python3 http_server.py &
    HTTP_SERVER_PID=$!
    
    # Wait for server to start
    sleep 2
    
    # Check if server is running
    if ! nc -z 127.0.0.1 8080 2>/dev/null; then
        log_error "Failed to start HTTP test server"
        exit 1
    fi
    
    log_success "HTTP test server started (PID: $HTTP_SERVER_PID)"
}

start_monitor() {
    log_info "Starting eBPF monitor for benchmarking..."
    
    # Start monitor in background
    ./ebpf-monitor -config="$BENCH_CONFIG" -log-level=warn -interface="$BENCH_INTERFACE" &
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
        if nc -z 127.0.0.1 50053 2>/dev/null; then
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

monitor_system_resources() {
    local output_file="$1"
    local duration="$2"
    
    log_info "Monitoring system resources for ${duration}s..."
    
    # Start resource monitoring
    {
        echo "timestamp,cpu_percent,memory_mb,network_rx_mb,network_tx_mb,disk_read_mb,disk_write_mb"
        
        local start_time=$(date +%s)
        local end_time=$((start_time + duration))
        
        while [[ $(date +%s) -lt $end_time ]]; do
            local timestamp=$(date +%s)
            
            # CPU usage
            local cpu_percent=$(sar -u 1 1 | tail -n 1 | awk '{print 100-$8}')
            
            # Memory usage
            local memory_mb=$(free -m | awk 'NR==2{print $3}')
            
            # Network stats
            local network_stats=$(sar -n DEV 1 1 | grep "$BENCH_INTERFACE" | tail -n 1)
            local network_rx_mb=$(echo "$network_stats" | awk '{print $5/1024}')
            local network_tx_mb=$(echo "$network_stats" | awk '{print $6/1024}')
            
            # Disk I/O
            local disk_stats=$(iostat -d 1 1 | tail -n +4 | head -n 1)
            local disk_read_mb=$(echo "$disk_stats" | awk '{print $3/1024}')
            local disk_write_mb=$(echo "$disk_stats" | awk '{print $4/1024}')
            
            echo "$timestamp,$cpu_percent,$memory_mb,$network_rx_mb,$network_tx_mb,$disk_read_mb,$disk_write_mb"
            
            sleep 1
        done
    } > "$output_file" &
    
    RESOURCE_MONITOR_PID=$!
}

stop_resource_monitoring() {
    if [[ -n "$RESOURCE_MONITOR_PID" ]]; then
        kill $RESOURCE_MONITOR_PID 2>/dev/null || true
        wait $RESOURCE_MONITOR_PID 2>/dev/null || true
        RESOURCE_MONITOR_PID=""
    fi
}

benchmark_throughput() {
    log_info "Running throughput benchmark..."
    
    local results_file="$BENCH_RESULTS_DIR/throughput_${BENCH_TIMESTAMP}.csv"
    
    echo "connections,requests_per_second,avg_latency_ms,p95_latency_ms,p99_latency_ms,errors,cpu_percent,memory_mb" > "$results_file"
    
    for connections in "${CONCURRENT_CONNECTIONS[@]}"; do
        for rps in "${REQUEST_RATES[@]}"; do
            log_info "Testing $connections connections at $rps RPS..."
            
            # Start resource monitoring
            local resource_file="$BENCH_RESULTS_DIR/resources_${connections}_${rps}_${BENCH_TIMESTAMP}.csv"
            monitor_system_resources "$resource_file" 30
            
            # Run benchmark
            if command -v wrk &> /dev/null; then
                # Use wrk if available
                local wrk_output=$(wrk -t$connections -c$connections -d30s -R$rps --latency http://127.0.0.1:8080/ 2>&1)
                
                # Parse wrk output
                local avg_latency=$(echo "$wrk_output" | grep "Latency" | awk '{print $2}' | sed 's/ms//')
                local p95_latency=$(echo "$wrk_output" | grep "95.000%" | awk '{print $2}' | sed 's/ms//')
                local p99_latency=$(echo "$wrk_output" | grep "99.000%" | awk '{print $2}' | sed 's/ms//')
                local errors=$(echo "$wrk_output" | grep "Non-2xx" | awk '{print $4}' || echo "0")
                
            elif command -v ab &> /dev/null; then
                # Use Apache Bench as fallback
                local total_requests=$((rps * 30))
                local ab_output=$(ab -n$total_requests -c$connections http://127.0.0.1:8080/ 2>&1)
                
                # Parse ab output
                local avg_latency=$(echo "$ab_output" | grep "Time per request" | head -n1 | awk '{print $4}')
                local p95_latency=$(echo "$ab_output" | grep "95%" | awk '{print $2}')
                local p99_latency=$(echo "$ab_output" | grep "99%" | awk '{print $2}')
                local errors=$(echo "$ab_output" | grep "Failed requests" | awk '{print $3}' || echo "0")
                
            else
                log_warning "No suitable load testing tool found, using curl"
                
                # Simple curl-based test
                local start_time=$(date +%s.%N)
                for ((i=1; i<=100; i++)); do
                    curl -s http://127.0.0.1:8080/ > /dev/null &
                done
                wait
                local end_time=$(date +%s.%N)
                
                local avg_latency=$(echo "($end_time - $start_time) * 1000 / 100" | bc -l)
                local p95_latency="$avg_latency"
                local p99_latency="$avg_latency"
                local errors="0"
            fi
            
            # Stop resource monitoring
            stop_resource_monitoring
            
            # Get average resource usage
            local avg_cpu=$(tail -n +2 "$resource_file" | awk -F, '{sum+=$2} END {print sum/NR}' || echo "0")
            local avg_memory=$(tail -n +2 "$resource_file" | awk -F, '{sum+=$3} END {print sum/NR}' || echo "0")
            
            # Record results
            echo "$connections,$rps,$avg_latency,$p95_latency,$p99_latency,$errors,$avg_cpu,$avg_memory" >> "$results_file"
            
            # Brief pause between tests
            sleep 5
        done
    done
    
    log_success "Throughput benchmark completed: $results_file"
}

benchmark_latency() {
    log_info "Running latency benchmark..."
    
    local results_file="$BENCH_RESULTS_DIR/latency_${BENCH_TIMESTAMP}.csv"
    
    echo "payload_size,min_latency_ms,avg_latency_ms,max_latency_ms,p50_latency_ms,p95_latency_ms,p99_latency_ms" > "$results_file"
    
    for size in "${PAYLOAD_SIZES[@]}"; do
        log_info "Testing latency with ${size}B payload..."
        
        # Create test endpoint with specific payload size
        local url="http://127.0.0.1:8080/test?size=$size"
        
        # Measure latencies
        local latencies=()
        for ((i=1; i<=1000; i++)); do
            local start_time=$(date +%s.%N)
            curl -s "$url" > /dev/null
            local end_time=$(date +%s.%N)
            local latency=$(echo "($end_time - $start_time) * 1000" | bc -l)
            latencies+=("$latency")
        done
        
        # Calculate statistics
        local sorted_latencies=($(printf '%s\n' "${latencies[@]}" | sort -n))
        local count=${#sorted_latencies[@]}
        
        local min_latency=${sorted_latencies[0]}
        local max_latency=${sorted_latencies[$((count-1))]}
        local avg_latency=$(printf '%s\n' "${latencies[@]}" | awk '{sum+=$1} END {print sum/NR}')
        
        local p50_index=$((count * 50 / 100))
        local p95_index=$((count * 95 / 100))
        local p99_index=$((count * 99 / 100))
        
        local p50_latency=${sorted_latencies[$p50_index]}
        local p95_latency=${sorted_latencies[$p95_index]}
        local p99_latency=${sorted_latencies[$p99_index]}
        
        # Record results
        echo "$size,$min_latency,$avg_latency,$max_latency,$p50_latency,$p95_latency,$p99_latency" >> "$results_file"
    done
    
    log_success "Latency benchmark completed: $results_file"
}

benchmark_memory_usage() {
    log_info "Running memory usage benchmark..."
    
    local results_file="$BENCH_RESULTS_DIR/memory_${BENCH_TIMESTAMP}.csv"
    
    echo "time_seconds,monitor_rss_mb,monitor_vss_mb,total_system_memory_mb,available_memory_mb" > "$results_file"
    
    # Monitor memory usage over time with sustained load
    local start_time=$(date +%s)
    
    # Generate sustained load
    if command -v wrk &> /dev/null; then
        wrk -t10 -c100 -d300s http://127.0.0.1:8080/ > /dev/null 2>&1 &
        local LOAD_PID=$!
    fi
    
    # Monitor for 5 minutes
    for ((i=0; i<300; i++)); do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        # Get monitor process memory usage
        if kill -0 $MONITOR_PID 2>/dev/null; then
            local monitor_memory=$(ps -o rss,vsz -p $MONITOR_PID --no-headers)
            local monitor_rss=$(echo "$monitor_memory" | awk '{print $1/1024}')
            local monitor_vss=$(echo "$monitor_memory" | awk '{print $2/1024}')
        else
            local monitor_rss="0"
            local monitor_vss="0"
        fi
        
        # Get system memory usage
        local memory_info=$(free -m | grep "Mem:")
        local total_memory=$(echo "$memory_info" | awk '{print $2}')
        local available_memory=$(echo "$memory_info" | awk '{print $7}')
        
        # Record data
        echo "$elapsed,$monitor_rss,$monitor_vss,$total_memory,$available_memory" >> "$results_file"
        
        sleep 1
    done
    
    # Stop load generator
    if [[ -n "$LOAD_PID" ]]; then
        kill $LOAD_PID 2>/dev/null || true
        wait $LOAD_PID 2>/dev/null || true
    fi
    
    log_success "Memory usage benchmark completed: $results_file"
}

benchmark_ebpf_overhead() {
    log_info "Running eBPF overhead benchmark..."
    
    local results_file="$BENCH_RESULTS_DIR/ebpf_overhead_${BENCH_TIMESTAMP}.csv"
    
    echo "test_type,packets_per_second,cpu_percent,latency_increase_percent" > "$results_file"
    
    # Baseline test without eBPF
    log_info "Running baseline test (no eBPF)..."
    
    # Stop eBPF monitor
    kill $MONITOR_PID
    wait $MONITOR_PID 2>/dev/null || true
    MONITOR_PID=""
    
    # Run baseline benchmark
    local baseline_resource_file="$BENCH_RESULTS_DIR/baseline_resources_${BENCH_TIMESTAMP}.csv"
    monitor_system_resources "$baseline_resource_file" 60
    
    if command -v wrk &> /dev/null; then
        local baseline_output=$(wrk -t10 -c100 -d60s --latency http://127.0.0.1:8080/ 2>&1)
        local baseline_latency=$(echo "$baseline_output" | grep "Latency" | awk '{print $2}' | sed 's/ms//')
        local baseline_rps=$(echo "$baseline_output" | grep "Requests/sec" | awk '{print $2}')
    fi
    
    stop_resource_monitoring
    
    local baseline_cpu=$(tail -n +2 "$baseline_resource_file" | awk -F, '{sum+=$2} END {print sum/NR}' || echo "0")
    
    # Test with eBPF
    log_info "Running test with eBPF..."
    
    start_monitor
    
    local ebpf_resource_file="$BENCH_RESULTS_DIR/ebpf_resources_${BENCH_TIMESTAMP}.csv"
    monitor_system_resources "$ebpf_resource_file" 60
    
    if command -v wrk &> /dev/null; then
        local ebpf_output=$(wrk -t10 -c100 -d60s --latency http://127.0.0.1:8080/ 2>&1)
        local ebpf_latency=$(echo "$ebpf_output" | grep "Latency" | awk '{print $2}' | sed 's/ms//')
        local ebpf_rps=$(echo "$ebpf_output" | grep "Requests/sec" | awk '{print $2}')
    fi
    
    stop_resource_monitoring
    
    local ebpf_cpu=$(tail -n +2 "$ebpf_resource_file" | awk -F, '{sum+=$2} END {print sum/NR}' || echo "0")
    
    # Calculate overhead
    local cpu_overhead=$(echo "$ebpf_cpu - $baseline_cpu" | bc -l)
    local latency_increase="0"
    if [[ -n "$baseline_latency" ]] && [[ -n "$ebpf_latency" ]]; then
        latency_increase=$(echo "($ebpf_latency - $baseline_latency) / $baseline_latency * 100" | bc -l)
    fi
    
    # Record results
    echo "baseline,$baseline_rps,$baseline_cpu,0" >> "$results_file"
    echo "ebpf,$ebpf_rps,$ebpf_cpu,$latency_increase" >> "$results_file"
    
    log_success "eBPF overhead benchmark completed: $results_file"
    log_info "CPU overhead: ${cpu_overhead}%"
    log_info "Latency increase: ${latency_increase}%"
}

generate_report() {
    log_info "Generating benchmark report..."
    
    local report_file="$BENCH_RESULTS_DIR/benchmark_report_${BENCH_TIMESTAMP}.md"
    
    cat > "$report_file" << EOF
# eBPF Network Monitor Benchmark Report

Generated: $(date)
System: $(uname -a)
Kernel: $(uname -r)
CPU: $(lscpu | grep "Model name" | cut -d: -f2 | xargs)
Memory: $(free -h | grep "Mem:" | awk '{print $2}')

## Test Configuration

- Benchmark Duration: ${BENCH_DURATION}s
- Test Interface: ${BENCH_INTERFACE}
- Concurrent Connections: ${CONCURRENT_CONNECTIONS[*]}
- Request Rates: ${REQUEST_RATES[*]} RPS
- Payload Sizes: ${PAYLOAD_SIZES[*]} bytes

## Results Summary

### Throughput Benchmark

EOF
    
    # Add throughput results if available
    if [[ -f "$BENCH_RESULTS_DIR/throughput_${BENCH_TIMESTAMP}.csv" ]]; then
        echo "\`\`\`" >> "$report_file"
        head -n 10 "$BENCH_RESULTS_DIR/throughput_${BENCH_TIMESTAMP}.csv" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        echo >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
### Latency Benchmark

EOF
    
    # Add latency results if available
    if [[ -f "$BENCH_RESULTS_DIR/latency_${BENCH_TIMESTAMP}.csv" ]]; then
        echo "\`\`\`" >> "$report_file"
        cat "$BENCH_RESULTS_DIR/latency_${BENCH_TIMESTAMP}.csv" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        echo >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
### Memory Usage

EOF
    
    # Add memory results if available
    if [[ -f "$BENCH_RESULTS_DIR/memory_${BENCH_TIMESTAMP}.csv" ]]; then
        local max_memory=$(tail -n +2 "$BENCH_RESULTS_DIR/memory_${BENCH_TIMESTAMP}.csv" | awk -F, 'BEGIN{max=0} {if($2>max) max=$2} END{print max}')
        local avg_memory=$(tail -n +2 "$BENCH_RESULTS_DIR/memory_${BENCH_TIMESTAMP}.csv" | awk -F, '{sum+=$2} END {print sum/NR}')
        
        echo "- Maximum memory usage: ${max_memory} MB" >> "$report_file"
        echo "- Average memory usage: ${avg_memory} MB" >> "$report_file"
        echo >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
### eBPF Overhead

EOF
    
    # Add overhead results if available
    if [[ -f "$BENCH_RESULTS_DIR/ebpf_overhead_${BENCH_TIMESTAMP}.csv" ]]; then
        echo "\`\`\`" >> "$report_file"
        cat "$BENCH_RESULTS_DIR/ebpf_overhead_${BENCH_TIMESTAMP}.csv" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        echo >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
## Files Generated

EOF
    
    # List all generated files
    find "$BENCH_RESULTS_DIR" -name "*${BENCH_TIMESTAMP}*" -type f | while read file; do
        echo "- $(basename "$file")" >> "$report_file"
    done
    
    log_success "Benchmark report generated: $report_file"
}

run_all_benchmarks() {
    log_info "Starting comprehensive benchmark suite..."
    
    local start_time=$(date +%s)
    
    # Start services
    start_http_server
    start_monitor
    
    # Run benchmarks
    benchmark_throughput
    benchmark_latency
    benchmark_memory_usage
    benchmark_ebpf_overhead
    
    # Generate report
    generate_report
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "All benchmarks completed successfully in ${duration}s"
    log_info "Results saved in: $BENCH_RESULTS_DIR"
}

# Script usage
usage() {
    echo "Usage: $0 [benchmark_type]"
    echo "Benchmark types:"
    echo "  all         - Run all benchmarks (default)"
    echo "  throughput  - Run throughput benchmark"
    echo "  latency     - Run latency benchmark"
    echo "  memory      - Run memory usage benchmark"
    echo "  overhead    - Run eBPF overhead benchmark"
    echo "  report      - Generate report from existing results"
    exit 1
}

# Main script logic
check_requirements
create_bench_config

case "${1:-all}" in
    all)
        run_all_benchmarks
        ;;
    throughput)
        start_http_server
        start_monitor
        benchmark_throughput
        ;;
    latency)
        start_http_server
        start_monitor
        benchmark_latency
        ;;
    memory)
        start_http_server
        start_monitor
        benchmark_memory_usage
        ;;
    overhead)
        start_http_server
        benchmark_ebpf_overhead
        ;;
    report)
        generate_report
        ;;
    *)
        usage
        ;;
esac

log_success "Benchmark execution completed!"