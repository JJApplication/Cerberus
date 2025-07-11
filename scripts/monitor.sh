#!/bin/bash

# eBPF Network Monitor Status Script
# This script provides real-time monitoring and status information

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
MONITOR_SERVICE="ebpf-monitor"
CONFIG_FILE="/opt/ebpf-monitor/config.toml"
DATA_DIR="/var/lib/ebpf-monitor"
LOG_DIR="/var/log/ebpf-monitor"
SOCKET_PATH="/var/lib/ebpf-monitor/ebpf-monitor.sock"
GRPC_ENDPOINT="127.0.0.1:50051"
REFRESH_INTERVAL=2
MAX_LOG_LINES=50

# Global variables
CLIENT_BINARY=""
TEMP_DIR="/tmp/ebpf-monitor-status"

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

print_header() {
    local title="$1"
    local width=80
    local padding=$(( (width - ${#title}) / 2 ))
    
    echo -e "${CYAN}"
    printf '=%.0s' $(seq 1 $width)
    echo
    printf '%*s%s%*s\n' $padding '' "$title" $padding ''
    printf '=%.0s' $(seq 1 $width)
    echo -e "${NC}"
}

print_section() {
    local title="$1"
    echo -e "\n${MAGENTA}=== $title ===${NC}"
}

format_bytes() {
    local bytes=$1
    if [[ $bytes -gt 1073741824 ]]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc)GB"
    elif [[ $bytes -gt 1048576 ]]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc)MB"
    elif [[ $bytes -gt 1024 ]]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc)KB"
    else
        echo "${bytes}B"
    fi
}

format_duration() {
    local seconds=$1
    local days=$((seconds / 86400))
    local hours=$(((seconds % 86400) / 3600))
    local minutes=$(((seconds % 3600) / 60))
    local secs=$((seconds % 60))
    
    if [[ $days -gt 0 ]]; then
        echo "${days}d ${hours}h ${minutes}m ${secs}s"
    elif [[ $hours -gt 0 ]]; then
        echo "${hours}h ${minutes}m ${secs}s"
    elif [[ $minutes -gt 0 ]]; then
        echo "${minutes}m ${secs}s"
    else
        echo "${secs}s"
    fi
}

check_dependencies() {
    # Check if systemctl is available
    if ! command -v systemctl &> /dev/null; then
        log_warning "systemctl not available, some features may not work"
    fi
    
    # Check if grpcurl is available
    if command -v grpcurl &> /dev/null; then
        CLIENT_BINARY="grpcurl"
    elif [[ -f "examples/client/main.go" ]]; then
        # Build client if source is available
        mkdir -p "$TEMP_DIR"
        if go build -o "$TEMP_DIR/client" examples/client/main.go 2>/dev/null; then
            CLIENT_BINARY="$TEMP_DIR/client"
        fi
    fi
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
}

cleanup() {
    # Clean up temporary files
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

get_service_status() {
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet "$MONITOR_SERVICE"; then
            echo -e "${GREEN}Running${NC}"
        elif systemctl is-enabled --quiet "$MONITOR_SERVICE"; then
            echo -e "${YELLOW}Stopped (Enabled)${NC}"
        else
            echo -e "${RED}Stopped (Disabled)${NC}"
        fi
    else
        # Check if process is running
        if pgrep -f "ebpf-monitor" > /dev/null; then
            echo -e "${GREEN}Running${NC}"
        else
            echo -e "${RED}Stopped${NC}"
        fi
    fi
}

get_process_info() {
    local pid=$(pgrep -f "ebpf-monitor" | head -n1)
    
    if [[ -n "$pid" ]]; then
        local start_time=$(ps -o lstart= -p "$pid" 2>/dev/null | xargs)
        local elapsed=$(ps -o etime= -p "$pid" 2>/dev/null | xargs)
        local cpu_percent=$(ps -o %cpu= -p "$pid" 2>/dev/null | xargs)
        local memory_kb=$(ps -o rss= -p "$pid" 2>/dev/null | xargs)
        local memory_mb=$(echo "scale=2; $memory_kb / 1024" | bc 2>/dev/null || echo "0")
        
        echo "PID: $pid"
        echo "Started: $start_time"
        echo "Uptime: $elapsed"
        echo "CPU: ${cpu_percent}%"
        echo "Memory: ${memory_mb}MB"
    else
        echo "Process not running"
    fi
}

get_network_interfaces() {
    echo "Available network interfaces:"
    ip link show | grep -E '^[0-9]+:' | while read line; do
        local interface=$(echo "$line" | cut -d: -f2 | sed 's/^ *//')
        local state=$(echo "$line" | grep -o 'state [A-Z]*' | cut -d' ' -f2)
        
        if [[ "$state" == "UP" ]]; then
            echo -e "  ${GREEN}$interface${NC} ($state)"
        else
            echo -e "  ${YELLOW}$interface${NC} ($state)"
        fi
    done
}

get_ebpf_maps() {
    echo "eBPF maps:"
    
    if command -v bpftool &> /dev/null; then
        bpftool map list 2>/dev/null | grep -E "(ip_stats|network_events|system_events|banned_ips)" || echo "  No eBPF maps found"
    else
        # Check /sys/fs/bpf if mounted
        if [[ -d "/sys/fs/bpf" ]]; then
            find /sys/fs/bpf -name "*ebpf*" -o -name "*monitor*" 2>/dev/null | head -10 || echo "  No eBPF maps found"
        else
            echo "  bpftool not available and /sys/fs/bpf not mounted"
        fi
    fi
}

get_database_info() {
    local db_path="$DATA_DIR/monitor.db"
    
    if [[ -f "$db_path" ]]; then
        local db_size=$(du -h "$db_path" | cut -f1)
        echo "Database: $db_path ($db_size)"
        
        if command -v sqlite3 &> /dev/null; then
            echo "Tables:"
            local malicious_count=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM malicious_ips;" 2>/dev/null || echo "N/A")
            local network_count=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM network_stats;" 2>/dev/null || echo "N/A")
            local system_count=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM system_anomalies;" 2>/dev/null || echo "N/A")
            
            echo "  Malicious IPs: $malicious_count"
            echo "  Network Stats: $network_count"
            echo "  System Anomalies: $system_count"
        fi
    else
        echo "Database not found: $db_path"
    fi
}

get_grpc_status() {
    if nc -z $(echo $GRPC_ENDPOINT | tr ':' ' ') 2>/dev/null; then
        echo -e "gRPC Server: ${GREEN}Running${NC} ($GRPC_ENDPOINT)"
        
        if [[ -n "$CLIENT_BINARY" ]]; then
            echo "API Status:"
            
            if [[ "$CLIENT_BINARY" == "grpcurl" ]]; then
                # Use grpcurl
                if timeout 5s grpcurl -plaintext "$GRPC_ENDPOINT" monitor.MonitorService/GetMonitorStatus &>/dev/null; then
                    echo -e "  GetMonitorStatus: ${GREEN}OK${NC}"
                else
                    echo -e "  GetMonitorStatus: ${RED}Failed${NC}"
                fi
            else
                # Use custom client
                if timeout 5s "$CLIENT_BINARY" -addr="$GRPC_ENDPOINT" -action=status &>/dev/null; then
                    echo -e "  API Endpoints: ${GREEN}OK${NC}"
                else
                    echo -e "  API Endpoints: ${RED}Failed${NC}"
                fi
            fi
        fi
    else
        echo -e "gRPC Server: ${RED}Not Running${NC} ($GRPC_ENDPOINT)"
    fi
}

get_recent_logs() {
    local log_file="$LOG_DIR/ebpf-monitor.log"
    
    echo "Recent logs:"
    
    if command -v journalctl &> /dev/null && systemctl is-active --quiet "$MONITOR_SERVICE"; then
        # Use journalctl for systemd service
        journalctl -u "$MONITOR_SERVICE" -n "$MAX_LOG_LINES" --no-pager -o short-iso | tail -n 20
    elif [[ -f "$log_file" ]]; then
        # Use log file
        tail -n "$MAX_LOG_LINES" "$log_file" | tail -n 20
    else
        echo "  No logs available"
    fi
}

get_system_resources() {
    echo "System Resources:"
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    echo "  CPU Usage: ${cpu_usage}%"
    
    # Memory usage
    local memory_info=$(free -m | grep "Mem:")
    local total_mem=$(echo "$memory_info" | awk '{print $2}')
    local used_mem=$(echo "$memory_info" | awk '{print $3}')
    local mem_percent=$(echo "scale=1; $used_mem * 100 / $total_mem" | bc)
    echo "  Memory Usage: ${used_mem}MB / ${total_mem}MB (${mem_percent}%)"
    
    # Disk usage
    local disk_usage=$(df -h / | tail -n1 | awk '{print $5}' | sed 's/%//')
    echo "  Disk Usage: ${disk_usage}%"
    
    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    echo "  Load Average: $load_avg"
}

get_network_stats() {
    if [[ -n "$CLIENT_BINARY" ]]; then
        echo "Network Statistics:"
        
        if [[ "$CLIENT_BINARY" == "grpcurl" ]]; then
            # Use grpcurl to get network stats
            local stats=$(timeout 5s grpcurl -plaintext "$GRPC_ENDPOINT" monitor.MonitorService/GetNetworkStats 2>/dev/null || echo "{}")
            echo "  $stats" | head -5
        else
            # Use custom client
            timeout 5s "$CLIENT_BINARY" -addr="$GRPC_ENDPOINT" -action=network-stats 2>/dev/null | head -10 || echo "  Unable to fetch network stats"
        fi
    else
        echo "Network Statistics: Client not available"
    fi
}

get_malicious_ips() {
    if [[ -n "$CLIENT_BINARY" ]]; then
        echo "Recent Malicious IPs:"
        
        if [[ "$CLIENT_BINARY" == "grpcurl" ]]; then
            # Use grpcurl to get malicious IPs
            local ips=$(timeout 5s grpcurl -plaintext "$GRPC_ENDPOINT" monitor.MonitorService/GetMaliciousIPs 2>/dev/null || echo "{}")
            echo "  $ips" | head -5
        else
            # Use custom client
            timeout 5s "$CLIENT_BINARY" -addr="$GRPC_ENDPOINT" -action=malicious-ips -limit=10 2>/dev/null | head -10 || echo "  Unable to fetch malicious IPs"
        fi
    else
        echo "Malicious IPs: Client not available"
    fi
}

show_status() {
    clear
    print_header "eBPF Network Monitor Status"
    
    print_section "Service Status"
    echo "Service: $(get_service_status)"
    get_process_info
    
    print_section "Configuration"
    echo "Config File: $CONFIG_FILE"
    echo "Data Directory: $DATA_DIR"
    echo "Socket Path: $SOCKET_PATH"
    
    print_section "Network Information"
    get_network_interfaces
    
    print_section "eBPF Information"
    get_ebpf_maps
    
    print_section "Database Information"
    get_database_info
    
    print_section "gRPC API"
    get_grpc_status
    
    print_section "System Resources"
    get_system_resources
    
    print_section "Network Statistics"
    get_network_stats
    
    print_section "Security Information"
    get_malicious_ips
    
    echo -e "\n${CYAN}Last updated: $(date)${NC}"
    echo -e "${CYAN}Press Ctrl+C to exit${NC}"
}

show_logs() {
    print_header "eBPF Network Monitor Logs"
    get_recent_logs
}

show_detailed_status() {
    print_header "eBPF Network Monitor Detailed Status"
    
    print_section "Service Information"
    if command -v systemctl &> /dev/null; then
        systemctl status "$MONITOR_SERVICE" --no-pager -l || echo "Service not found"
    else
        get_process_info
    fi
    
    print_section "Configuration File"
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "Configuration ($CONFIG_FILE):"
        cat "$CONFIG_FILE" | head -50
    else
        echo "Configuration file not found: $CONFIG_FILE"
    fi
    
    print_section "Recent Logs"
    get_recent_logs
    
    print_section "System Information"
    echo "Kernel: $(uname -r)"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 2>/dev/null || uname -s)"
    echo "Architecture: $(uname -m)"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    
    print_section "Network Interfaces Detail"
    ip addr show | head -50
    
    print_section "eBPF Programs"
    if command -v bpftool &> /dev/null; then
        bpftool prog list 2>/dev/null | head -20 || echo "No eBPF programs found"
    else
        echo "bpftool not available"
    fi
}

watch_status() {
    while true; do
        show_status
        sleep "$REFRESH_INTERVAL"
    done
}

control_service() {
    local action="$1"
    
    if ! command -v systemctl &> /dev/null; then
        log_error "systemctl not available"
        exit 1
    fi
    
    case "$action" in
        start)
            log_info "Starting $MONITOR_SERVICE..."
            sudo systemctl start "$MONITOR_SERVICE"
            log_success "Service started"
            ;;
        stop)
            log_info "Stopping $MONITOR_SERVICE..."
            sudo systemctl stop "$MONITOR_SERVICE"
            log_success "Service stopped"
            ;;
        restart)
            log_info "Restarting $MONITOR_SERVICE..."
            sudo systemctl restart "$MONITOR_SERVICE"
            log_success "Service restarted"
            ;;
        enable)
            log_info "Enabling $MONITOR_SERVICE..."
            sudo systemctl enable "$MONITOR_SERVICE"
            log_success "Service enabled"
            ;;
        disable)
            log_info "Disabling $MONITOR_SERVICE..."
            sudo systemctl disable "$MONITOR_SERVICE"
            log_success "Service disabled"
            ;;
        *)
            log_error "Unknown action: $action"
            exit 1
            ;;
    esac
}

test_api() {
    print_header "eBPF Monitor API Test"
    
    if [[ -z "$CLIENT_BINARY" ]]; then
        log_error "No gRPC client available"
        exit 1
    fi
    
    log_info "Testing API endpoints..."
    
    if [[ "$CLIENT_BINARY" == "grpcurl" ]]; then
        # Test with grpcurl
        echo "Available services:"
        timeout 10s grpcurl -plaintext "$GRPC_ENDPOINT" list || log_error "Failed to list services"
        
        echo "\nTesting GetMonitorStatus:"
        timeout 10s grpcurl -plaintext "$GRPC_ENDPOINT" monitor.MonitorService/GetMonitorStatus || log_error "GetMonitorStatus failed"
        
        echo "\nTesting GetMaliciousIPs:"
        timeout 10s grpcurl -plaintext "$GRPC_ENDPOINT" monitor.MonitorService/GetMaliciousIPs || log_error "GetMaliciousIPs failed"
        
    else
        # Test with custom client
        echo "Testing monitor status:"
        timeout 10s "$CLIENT_BINARY" -addr="$GRPC_ENDPOINT" -action=status || log_error "Status check failed"
        
        echo "\nTesting malicious IPs:"
        timeout 10s "$CLIENT_BINARY" -addr="$GRPC_ENDPOINT" -action=malicious-ips || log_error "Malicious IPs check failed"
        
        echo "\nTesting network stats:"
        timeout 10s "$CLIENT_BINARY" -addr="$GRPC_ENDPOINT" -action=network-stats || log_error "Network stats check failed"
    fi
    
    log_success "API test completed"
}

# Script usage
usage() {
    echo "Usage: $0 [command] [options]"
    echo
    echo "Commands:"
    echo "  status      - Show current status (default)"
    echo "  watch       - Watch status in real-time"
    echo "  logs        - Show recent logs"
    echo "  detailed    - Show detailed status information"
    echo "  start       - Start the service"
    echo "  stop        - Stop the service"
    echo "  restart     - Restart the service"
    echo "  enable      - Enable service auto-start"
    echo "  disable     - Disable service auto-start"
    echo "  test-api    - Test gRPC API endpoints"
    echo
    echo "Options:"
    echo "  -c, --config FILE    - Configuration file path"
    echo "  -e, --endpoint ADDR  - gRPC endpoint address"
    echo "  -i, --interval SEC   - Refresh interval for watch mode"
    echo "  -h, --help          - Show this help"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -e|--endpoint)
            GRPC_ENDPOINT="$2"
            shift 2
            ;;
        -i|--interval)
            REFRESH_INTERVAL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            log_error "Unknown option: $1"
            usage
            ;;
        *)
            break
            ;;
    esac
done

# Initialize
check_dependencies

# Main script logic
case "${1:-status}" in
    status)
        show_status
        ;;
    watch)
        watch_status
        ;;
    logs)
        show_logs
        ;;
    detailed)
        show_detailed_status
        ;;
    start|stop|restart|enable|disable)
        control_service "$1"
        ;;
    test-api)
        test_api
        ;;
    *)
        log_error "Unknown command: $1"
        usage
        ;;
esac