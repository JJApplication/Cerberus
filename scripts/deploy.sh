#!/bin/bash

# eBPF Network Monitor Deployment Script
# This script automates the installation and setup process

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="ebpf-monitor"
APP_USER="ebpf"
APP_DIR="/opt/ebpf-monitor"
SERVICE_FILE="/etc/systemd/system/ebpf-monitor.service"
CONFIG_FILE="$APP_DIR/config.toml"
LOG_DIR="/var/log/ebpf-monitor"
DATA_DIR="/var/lib/ebpf-monitor"

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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS version"
        exit 1
    fi
    log_info "Detected OS: $OS $VER"
}

install_dependencies() {
    log_info "Installing system dependencies..."
    
    if [[ $OS == *"Ubuntu"* ]] || [[ $OS == *"Debian"* ]]; then
        apt-get update
        apt-get install -y \
            clang \
            llvm \
            libbpf-dev \
            linux-headers-$(uname -r) \
            protobuf-compiler \
            build-essential \
            git \
            curl \
            systemd
    elif [[ $OS == *"CentOS"* ]] || [[ $OS == *"Red Hat"* ]] || [[ $OS == *"Rocky"* ]]; then
        yum update -y
        yum install -y \
            clang \
            llvm \
            libbpf-devel \
            kernel-headers \
            kernel-devel \
            protobuf-compiler \
            gcc \
            git \
            curl \
            systemd
    else
        log_error "Unsupported OS: $OS"
        exit 1
    fi
    
    log_success "Dependencies installed successfully"
}

check_ebpf_support() {
    log_info "Checking eBPF support..."
    
    # Check kernel version
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    REQUIRED_VERSION="4.18"
    
    if ! awk "BEGIN {exit !($KERNEL_VERSION >= $REQUIRED_VERSION)}"; then
        log_error "Kernel version $KERNEL_VERSION is too old. Minimum required: $REQUIRED_VERSION"
        exit 1
    fi
    
    # Mount BPF filesystem if not mounted
    if ! mount | grep -q "/sys/fs/bpf"; then
        log_info "Mounting BPF filesystem..."
        mount -t bpf bpf /sys/fs/bpf
        echo "bpf /sys/fs/bpf bpf defaults 0 0" >> /etc/fstab
    fi
    
    log_success "eBPF support verified"
}

create_user() {
    log_info "Creating application user..."
    
    if ! id "$APP_USER" &>/dev/null; then
        useradd -r -s /bin/false -d $APP_DIR $APP_USER
        log_success "User $APP_USER created"
    else
        log_info "User $APP_USER already exists"
    fi
}

setup_directories() {
    log_info "Setting up directories..."
    
    # Create application directory
    mkdir -p $APP_DIR
    mkdir -p $LOG_DIR
    mkdir -p $DATA_DIR
    
    # Set permissions
    chown -R $APP_USER:$APP_USER $APP_DIR
    chown -R $APP_USER:$APP_USER $LOG_DIR
    chown -R $APP_USER:$APP_USER $DATA_DIR
    
    chmod 755 $APP_DIR
    chmod 755 $LOG_DIR
    chmod 755 $DATA_DIR
    
    log_success "Directories created and configured"
}

install_binary() {
    log_info "Installing application binary..."
    
    if [[ -f "./ebpf-monitor" ]]; then
        cp ./ebpf-monitor $APP_DIR/
        chmod +x $APP_DIR/ebpf-monitor
        chown $APP_USER:$APP_USER $APP_DIR/ebpf-monitor
        log_success "Binary installed to $APP_DIR"
    else
        log_error "Binary ./ebpf-monitor not found. Please build the application first."
        exit 1
    fi
}

install_config() {
    log_info "Installing configuration file..."
    
    if [[ -f "./config.toml" ]]; then
        cp ./config.toml $CONFIG_FILE
        
        # Update paths in config
        sed -i "s|sqlite_path = \"./monitor.db\"|sqlite_path = \"$DATA_DIR/monitor.db\"|" $CONFIG_FILE
        sed -i "s|uds_socket_path = \"/tmp/ebpf-monitor.sock\"|uds_socket_path = \"$DATA_DIR/ebpf-monitor.sock\"|" $CONFIG_FILE
        
        chown $APP_USER:$APP_USER $CONFIG_FILE
        chmod 644 $CONFIG_FILE
        log_success "Configuration installed to $CONFIG_FILE"
    else
        log_error "Configuration file ./config.toml not found"
        exit 1
    fi
}

create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > $SERVICE_FILE << EOF
[Unit]
Description=eBPF Network Monitor
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$APP_DIR/ebpf-monitor -config=$CONFIG_FILE -log-level=info -interface=eth0
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ebpf-monitor

# Security settings
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR /sys/fs/bpf

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Environment
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service created"
}

setup_logrotate() {
    log_info "Setting up log rotation..."
    
    cat > /etc/logrotate.d/ebpf-monitor << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $APP_USER $APP_USER
    postrotate
        systemctl reload ebpf-monitor || true
    endscript
}
EOF

    log_success "Log rotation configured"
}

setup_firewall() {
    log_info "Configuring firewall..."
    
    # Check if ufw is available
    if command -v ufw &> /dev/null; then
        ufw allow 50051/tcp comment "eBPF Monitor gRPC"
        log_success "UFW firewall rule added"
    # Check if firewalld is available
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=50051/tcp
        firewall-cmd --reload
        log_success "Firewalld rule added"
    else
        log_warning "No supported firewall found. Please manually open port 50051/tcp"
    fi
}

get_network_interface() {
    log_info "Detecting network interfaces..."
    
    # Get the default route interface
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -n "$DEFAULT_INTERFACE" ]]; then
        log_info "Default network interface: $DEFAULT_INTERFACE"
        
        # Update service file with detected interface
        sed -i "s|-interface=eth0|-interface=$DEFAULT_INTERFACE|" $SERVICE_FILE
        systemctl daemon-reload
        
        log_success "Service configured for interface: $DEFAULT_INTERFACE"
    else
        log_warning "Could not detect default network interface. Using eth0 as default."
        log_warning "You may need to manually edit $SERVICE_FILE"
    fi
    
    # Show available interfaces
    echo "Available network interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | sed 's/^ *//'
}

start_service() {
    log_info "Starting eBPF Monitor service..."
    
    systemctl enable ebpf-monitor
    systemctl start ebpf-monitor
    
    # Wait a moment and check status
    sleep 3
    
    if systemctl is-active --quiet ebpf-monitor; then
        log_success "eBPF Monitor service started successfully"
    else
        log_error "Failed to start eBPF Monitor service"
        log_info "Check logs with: journalctl -u ebpf-monitor -f"
        exit 1
    fi
}

show_status() {
    echo
    echo "=== eBPF Monitor Status ==="
    systemctl status ebpf-monitor --no-pager -l
    echo
    echo "=== Service Information ==="
    echo "Service file: $SERVICE_FILE"
    echo "Configuration: $CONFIG_FILE"
    echo "Data directory: $DATA_DIR"
    echo "Log directory: $LOG_DIR"
    echo "gRPC endpoint: localhost:50051"
    echo
    echo "=== Useful Commands ==="
    echo "View logs: journalctl -u ebpf-monitor -f"
    echo "Restart service: systemctl restart ebpf-monitor"
    echo "Stop service: systemctl stop ebpf-monitor"
    echo "Edit config: nano $CONFIG_FILE"
    echo "Test API: curl -X POST http://localhost:50051 (requires grpcurl)"
}

# Main deployment function
deploy() {
    log_info "Starting eBPF Monitor deployment..."
    
    check_root
    detect_os
    install_dependencies
    check_ebpf_support
    create_user
    setup_directories
    install_binary
    install_config
    create_systemd_service
    setup_logrotate
    setup_firewall
    get_network_interface
    start_service
    show_status
    
    log_success "eBPF Monitor deployed successfully!"
}

# Uninstall function
uninstall() {
    log_info "Uninstalling eBPF Monitor..."
    
    # Stop and disable service
    systemctl stop ebpf-monitor || true
    systemctl disable ebpf-monitor || true
    
    # Remove files
    rm -f $SERVICE_FILE
    rm -f /etc/logrotate.d/ebpf-monitor
    rm -rf $APP_DIR
    rm -rf $LOG_DIR
    rm -rf $DATA_DIR
    
    # Remove user
    userdel $APP_USER || true
    
    systemctl daemon-reload
    
    log_success "eBPF Monitor uninstalled"
}

# Script usage
usage() {
    echo "Usage: $0 [deploy|uninstall|status]"
    echo "  deploy    - Install and configure eBPF Monitor"
    echo "  uninstall - Remove eBPF Monitor"
    echo "  status    - Show service status"
    exit 1
}

# Main script logic
case "${1:-deploy}" in
    deploy)
        deploy
        ;;
    uninstall)
        check_root
        uninstall
        ;;
    status)
        show_status
        ;;
    *)
        usage
        ;;
esac