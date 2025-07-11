# Multi-stage build for eBPF Network Monitor

# Build stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    golang-1.21 \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    protobuf-compiler \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set Go path
ENV PATH=/usr/lib/go-1.21/bin:$PATH
ENV GOPATH=/go
ENV GO111MODULE=on

# Create app directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Install protobuf Go plugins
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Add Go bin to PATH
ENV PATH=$GOPATH/bin:$PATH

# Generate protobuf files
RUN make proto

# Generate eBPF Go bindings
RUN make ebpf

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o ebpf-monitor ./cmd/monitor

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libbpf0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (note: the app still needs to run as root for eBPF)
RUN groupadd -r ebpf && useradd -r -g ebpf ebpf

# Create app directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/ebpf-monitor .

# Copy configuration file
COPY --from=builder /app/config.toml .

# Create data directory for SQLite database
RUN mkdir -p /app/data && chown ebpf:ebpf /app/data

# Create directory for Unix Domain Socket
RUN mkdir -p /tmp && chmod 755 /tmp

# Expose gRPC port
EXPOSE 50051

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep ebpf-monitor || exit 1

# Note: Container must run in privileged mode with host network for eBPF
# docker run --privileged --network=host -v /sys/fs/bpf:/sys/fs/bpf ebpf-monitor

# Default command
CMD ["./ebpf-monitor", "-config=config.toml", "-log-level=info", "-interface=eth0"]