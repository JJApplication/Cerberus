# eBPF Network Monitor

一个基于eBPF技术的Linux网络流量监控和安全防护系统，能够实时监控网络异常流量、系统资源使用情况，并自动封禁恶意IP地址。

## 功能特性

### 网络监控
- 🌐 实时监控网络流量和连接
- 🚫 自动检测和封禁恶意IP地址
- 🔍 恶意URL模式检测
- 📊 网络流量统计和分析
- ⏰ 可配置的封禁时间和规则

### 系统资源监控
- 💻 CPU使用率监控
- 🧠 内存使用率监控
- 💾 磁盘I/O监控
- 📈 进程级别的资源使用分析
- ⚠️ 异常资源使用告警

### 数据存储和API
- 🗄️ SQLite数据库存储
- 🔌 gRPC API接口
- 🔧 TOML配置文件
- 📡 Unix Domain Socket支持
- 🧹 自动数据清理

## 系统要求

- **操作系统**: Linux (内核版本 >= 4.18)
- **架构**: x86_64
- **权限**: root权限（加载eBPF程序需要）
- **依赖**: 
  - Go 1.21+
  - clang
  - libbpf
  - Protocol Buffers编译器

## 快速开始

### 方法一：自动化部署（推荐）

```bash
# 设置开发环境（首次使用）
make dev-setup

# 构建项目
make build

# 部署到系统（需要root权限）
make deploy

# 启动服务
make service-start

# 查看状态
make monitor-status
```

### 方法二：手动安装

#### 1. 安装系统依赖

**Ubuntu/Debian:**
```bash
sudo make install-deps-ubuntu
```

**CentOS/RHEL:**
```bash
sudo make install-deps-centos
```

**手动安装:**
```bash
# Ubuntu/Debian
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r) protobuf-compiler build-essential

# CentOS/RHEL
sudo yum install clang llvm libbpf-devel kernel-headers kernel-devel protobuf-compiler gcc
```

#### 2. 编译项目

```bash
# 下载依赖、生成代码并编译
make all

# 或者分步执行
make deps     # 下载Go依赖
make proto    # 生成protobuf代码
make ebpf     # 编译eBPF程序
make build    # 编译Go程序
```

#### 3. 配置

编辑 `config.toml` 文件来自定义监控参数：

```toml
[network]
max_connections_per_ip = 100      # 单个IP最大连接数
ban_duration_minutes = 60         # 封禁时长（分钟）
monitoring_interval_seconds = 10  # 监控间隔（秒）

# 恶意URL模式
malicious_url_patterns = [
    "/admin",
    "/wp-admin",
    "/.env",
    "/config"
]

[system]
cpu_threshold_percent = 80.0      # CPU使用率阈值
memory_threshold_percent = 85.0   # 内存使用率阈值
disk_io_threshold_mbps = 100.0    # 磁盘IO阈值（MB/s）

[grpc]
listen_address = "127.0.0.1:50051"
uds_socket_path = "/tmp/ebpf-monitor.sock"

[database]
sqlite_path = "./monitor.db"
max_records = 10000
```

#### 4. 运行

```bash
# 检查eBPF支持
make check-ebpf

# 查看可用网络接口
make show-interfaces

# 启动监控（需要root权限）
sudo make run

# 或指定网络接口
sudo make run-interface INTERFACE=eth0

# 手动运行
sudo ./ebpf-monitor -config=config.toml -log-level=info -interface=eth0
```

## 服务管理

### 服务控制

```bash
# 启动服务
make service-start

# 停止服务
make service-stop

# 重启服务
make service-restart

# 查看服务状态
make monitor-status

# 实时监控状态
make monitor-watch

# 查看日志
make monitor-logs
```

### 测试和基准测试

```bash
# 运行全面测试
make test-all

# 运行性能基准测试
make benchmark

# 测试API接口
make test-api
```

### 开发工具

```bash
# 设置开发环境
make dev-setup

# 格式化代码
make fmt

# 代码检查
make lint

# 使脚本可执行
make scripts-setup
```

## API使用

### gRPC接口

项目提供了完整的gRPC API，可以通过以下方式调用：

```bash
# 使用grpcurl测试API
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 monitor.MonitorService/GetMonitorStatus
```

### 使用示例客户端

```bash
# 编译客户端
go build -o client examples/client/main.go

# 获取监控状态
./client -addr=127.0.0.1:50051 -action=status

# 获取恶意IP列表
./client -addr=127.0.0.1:50051 -action=malicious-ips

# 获取网络统计
./client -addr=127.0.0.1:50051 -action=network-stats

# 获取系统异常
./client -addr=127.0.0.1:50051 -action=system-anomalies

# 封禁IP
./client -addr=127.0.0.1:50051 -action=ban-ip -ip=192.168.1.100

# 解封IP
./client -addr=127.0.0.1:50051 -action=unban-ip -ip=192.168.1.100
```

### 主要API接口

- `GetMaliciousIPs` - 获取恶意IP列表
- `GetNetworkStats` - 获取网络流量统计
- `GetSystemAnomalies` - 获取系统资源异常记录
- `BanIP` - 手动封禁IP
- `UnbanIP` - 解封IP
- `GetMonitorStatus` - 获取监控状态

## 项目结构

```
ebpf-monitor/
├── cmd/monitor/           # 主程序入口
├── internal/
│   ├── config/           # 配置管理
│   ├── database/         # 数据库操作
│   ├── ebpf/            # eBPF程序管理
│   ├── grpc/            # gRPC服务
│   └── system/          # 系统资源监控
├── ebpf/                # eBPF C代码
├── proto/               # Protocol Buffers定义
├── config.toml          # 配置文件
├── go.mod              # Go模块定义
└── Makefile            # 构建脚本
```

## 开发指南

### 开发环境设置

```bash
# 克隆项目
git clone <repository-url>
cd ebpf-monitor

# 安装依赖
make deps

# 开发构建（包含调试符号）
make dev-build

# 代码格式化
make fmt

# 代码检查
make lint

# 运行测试
make test
```

### 添加新的监控规则

1. 修改 `config.toml` 中的规则配置
2. 在 `internal/ebpf/monitor.go` 中添加检测逻辑
3. 更新数据库模型（如需要）
4. 重新编译和测试

### 自定义eBPF程序

1. 修改 `ebpf/network_monitor.c`
2. 运行 `make ebpf` 重新生成Go绑定
3. 更新 `internal/ebpf/monitor.go` 中的事件处理逻辑

## 监控数据

### 数据库表结构

- `malicious_ips` - 恶意IP记录
- `network_stats` - 网络流量统计
- `system_anomalies` - 系统资源异常记录

### 日志级别

- `debug` - 详细调试信息
- `info` - 一般信息（默认）
- `warn` - 警告信息
- `error` - 错误信息

## 性能优化

### eBPF程序优化
- 使用高效的数据结构（HashMap、RingBuffer）
- 最小化内核空间的计算
- 合理设置Map大小

### 用户空间优化
- 批量处理事件
- 异步数据库操作
- 定期清理历史数据

## 脚本说明

项目提供了多个脚本来简化开发、部署和管理：

### scripts/dev-setup.sh
开发环境设置脚本，自动安装和配置开发所需的工具：
- Go语言环境
- Protocol Buffers编译器
- eBPF开发工具
- 代码格式化和检查工具
- VS Code配置
- Git hooks

### scripts/deploy.sh
生产环境部署脚本：
- 系统依赖安装
- 用户和目录创建
- 服务配置
- 防火墙设置
- 自动启动配置

### scripts/test.sh
综合测试脚本：
- 单元测试
- 集成测试
- 网络监控测试
- 系统资源监控测试
- 性能测试

### scripts/benchmark.sh
性能基准测试脚本：
- 吞吐量测试
- 延迟测试
- 内存使用测试
- eBPF开销测试

### scripts/monitor.sh
监控和管理脚本：
- 服务状态查看
- 实时监控
- 日志查看
- API测试
- 服务控制

## 故障排除

### 常见问题

1. **权限错误**
   ```bash
   # 检查当前用户权限
   id
   
   # 确保以root权限运行
   sudo ./ebpf-monitor
   
   # 检查服务状态
   make monitor-status
   ```

2. **eBPF加载失败**
   ```bash
   # 检查内核版本
   uname -r
   
   # 检查eBPF支持
   make check-ebpf
   
   # 挂载BPF文件系统
   sudo mount -t bpf bpf /sys/fs/bpf
   ```

3. **网络接口问题**
   ```bash
   # 查看可用接口
   make show-interfaces
   
   # 检查接口状态
   ip link show
   
   # 指定正确的接口
   sudo ./ebpf-monitor -interface=eth0
   ```

4. **数据库问题**
   ```bash
   # 检查数据库文件
   ls -la /var/lib/ebpf-monitor/
   
   # 检查磁盘空间
   df -h
   
   # 查看数据库状态
   make monitor-status
   ```

5. **gRPC连接问题**
   ```bash
   # 检查端口占用
   ss -tlnp | grep 50051
   
   # 测试API连接
   make test-api
   
   # 检查防火墙
   sudo ufw status
   ```

6. **服务启动问题**
   ```bash
   # 查看详细日志
   make monitor-logs
   
   # 检查systemd状态
   sudo systemctl status ebpf-monitor
   
   # 手动启动调试
   sudo ./ebpf-monitor -config=config.toml -log-level=debug
   ```

### 调试技巧

1. **启用详细日志**
   ```bash
   # 使用debug级别日志
   sudo ./ebpf-monitor -log-level=debug
   ```

2. **检查eBPF程序状态**
   ```bash
   # 查看加载的eBPF程序
   sudo bpftool prog list
   
   # 查看eBPF maps
   sudo bpftool map list
   ```

3. **监控系统资源**
   ```bash
   # 实时监控
   make monitor-watch
   
   # 运行基准测试
   make benchmark
   ```

4. **网络调试**
   ```bash
   # 监控网络流量
   sudo tcpdump -i any -n
   
   # 检查连接状态
   ss -tuln
   ```

### 调试模式

```bash
# 启用调试日志
sudo ./ebpf-monitor -log-level=debug

# 使用开发构建（包含调试符号）
make dev-build
sudo gdb ./ebpf-monitor
```

## 安全考虑

- 程序需要root权限运行，请确保在安全的环境中使用
- 定期更新系统和依赖库
- 监控日志文件，及时发现异常
- 合理配置封禁规则，避免误封

## 贡献指南

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 创建Pull Request

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 联系方式

如有问题或建议，请通过以下方式联系：
- 提交Issue
- 发送邮件
- 参与讨论

---

**注意**: 本项目仅用于学习和研究目的，请在合法合规的环境中使用。