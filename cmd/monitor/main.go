package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"ebpf-monitor/internal/config"
	"ebpf-monitor/internal/database"
	"ebpf-monitor/internal/ebpf"
	"ebpf-monitor/internal/grpc"
	"ebpf-monitor/internal/system"
)

var (
	configPath = flag.String("config", "config.toml", "Path to configuration file")
)

type MonitorService struct {
	config        *config.Config
	logger        *logrus.Logger
	db            *database.Database
	ebpfMonitor   *ebpf.Monitor
	systemMonitor *system.ResourceMonitor
	grpcServer    *grpc.Server
	ctx           context.Context
	cancel        context.CancelFunc
}

func main() {
	flag.Parse()

	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		logrus.Fatalf("Invalid config: %v", err)
	}

	// 初始化日志
	logger := logrus.New()
	level, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		logger.Fatalf("Invalid log level: %v", err)
	}
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logger.Info("Starting eBPF Network Monitor")

	// 创建监控服务
	service, err := NewMonitorService(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to create monitor service: %v", err)
	}

	// 启动服务
	if err := service.Start(cfg.Network.Interface); err != nil {
		logger.Fatalf("Failed to start monitor service: %v", err)
	}

	// 等待信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Monitor service started successfully")
	logger.Infof("gRPC server listening on %s", cfg.GRPC.ListenAddress)
	logger.Infof("Monitoring interface: %s", cfg.Network.Interface)

	<-sigChan
	logger.Info("Received shutdown signal")

	// 优雅关闭
	service.Stop()
	logger.Info("Monitor service stopped")
}

func NewMonitorService(cfg *config.Config, logger *logrus.Logger) (*MonitorService, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// 初始化数据库
	db, err := database.NewDatabase(cfg.Database.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// 初始化eBPF监控器
	ebpfMonitor, err := ebpf.NewMonitor(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize eBPF monitor: %w", err)
	}

	// 初始化系统资源监控器
	systemMonitor := system.NewResourceMonitor(
		logger,
		cfg.System.GetMonitoringWindow(),
		cfg.System.CPUThresholdPercent,
		cfg.System.MemoryThresholdPercent,
		cfg.System.DiskIOThresholdMbps,
	)

	// 初始化gRPC服务器
	grpcServer := grpc.NewServer(db, cfg, logger)

	service := &MonitorService{
		config:        cfg,
		logger:        logger,
		db:            db,
		ebpfMonitor:   ebpfMonitor,
		systemMonitor: systemMonitor,
		grpcServer:    grpcServer,
		ctx:           ctx,
		cancel:        cancel,
	}

	// 设置事件处理器
	service.setupEventHandlers()

	return service, nil
}

func (ms *MonitorService) Start(interfaceName string) error {
	// 启动eBPF监控
	if err := ms.ebpfMonitor.Start(interfaceName); err != nil {
		return fmt.Errorf("failed to start eBPF monitor: %w", err)
	}

	// 启动系统资源监控
	ms.systemMonitor.Start()

	// 启动gRPC服务器
	if err := ms.grpcServer.Start(); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}

	// 启动定期清理任务
	go ms.startCleanupTask()

	// 启动封禁检查任务
	go ms.startBanCheckTask()

	return nil
}

func (ms *MonitorService) Stop() {
	ms.cancel()

	// 停止各个组件
	if ms.ebpfMonitor != nil {
		ms.ebpfMonitor.Stop()
	}

	if ms.systemMonitor != nil {
		ms.systemMonitor.Stop()
	}

	if ms.grpcServer != nil {
		ms.grpcServer.Stop()
	}

	if ms.db != nil {
		ms.db.Close()
	}
}

func (ms *MonitorService) setupEventHandlers() {
	// 设置网络事件处理器
	ms.ebpfMonitor.NetworkEventHandler = func(event *ebpf.NetworkEvent) {
		ms.handleNetworkEvent(event)
	}

	// 设置系统事件处理器
	ms.ebpfMonitor.SystemEventHandler = func(event *ebpf.SystemEvent) {
		ms.handleSystemEvent(event)
	}

	// 设置系统资源异常处理器
	ms.systemMonitor.AnomalyHandler = func(anomaly *system.ResourceAnomaly) {
		ms.handleResourceAnomaly(anomaly)
	}
}

func (ms *MonitorService) handleNetworkEvent(event *ebpf.NetworkEvent) {
	// 记录网络统计
	networkStat := &database.NetworkStat{
		IPAddress:       event.SrcIP.String(),
		Timestamp:       event.Timestamp,
		BytesSent:       int64(event.Bytes),
		BytesReceived:   0, // 这里简化处理
		ConnectionCount: 1,
		RequestedURL:    event.URL,
	}

	if err := ms.db.InsertNetworkStat(networkStat); err != nil {
		ms.logger.Errorf("Failed to insert network stat: %v", err)
	}

	// 检查是否为恶意行为
	ms.checkMaliciousBehavior(event)
}

func (ms *MonitorService) handleSystemEvent(event *ebpf.SystemEvent) {
	// 处理系统事件（如进程启动等）
	ms.logger.Debugf("System event: PID=%d, Comm=%s", event.PID, event.Comm)
}

func (ms *MonitorService) handleResourceAnomaly(anomaly *system.ResourceAnomaly) {
	// 记录系统资源异常
	systemAnomaly := &database.SystemAnomaly{
		Timestamp:   anomaly.Timestamp,
		AnomalyType: anomaly.AnomalyType,
		Value:       anomaly.Value,
		Threshold:   anomaly.Threshold,
		ProcessName: anomaly.ProcessName,
		ProcessID:   anomaly.ProcessID,
		Description: anomaly.Description,
	}

	if err := ms.db.InsertSystemAnomaly(systemAnomaly); err != nil {
		ms.logger.Errorf("Failed to insert system anomaly: %v", err)
	}
}

func (ms *MonitorService) checkMaliciousBehavior(event *ebpf.NetworkEvent) {
	ipAddress := event.SrcIP.String()

	// 检查恶意URL
	if event.URL != "" && ebpf.IsMaliciousURL(event.URL, ms.config.Network.MaliciousURLPatterns) {
		ms.logger.Warnf("Malicious URL detected from IP %s: %s", ipAddress, event.URL)
		ms.banMaliciousIP(ipAddress, fmt.Sprintf("Malicious URL access: %s", event.URL))
		return
	}

	// 检查连接频率
	existingIP, err := ms.db.GetMaliciousIPByAddress(ipAddress)
	if err != nil {
		ms.logger.Errorf("Failed to get malicious IP: %v", err)
		return
	}

	if existingIP != nil {
		// 更新现有记录
		existingIP.LastSeen = event.Timestamp
		existingIP.ConnectionCount++
		if err := ms.db.InsertOrUpdateMaliciousIP(existingIP); err != nil {
			ms.logger.Errorf("Failed to update malicious IP: %v", err)
		}

		// 检查是否超过连接阈值
		if existingIP.ConnectionCount >= ms.config.Network.MaxConnectionsPerIP {
			ms.logger.Warnf("IP %s exceeded connection threshold (%d)", ipAddress, existingIP.ConnectionCount)
			ms.banMaliciousIP(ipAddress, fmt.Sprintf("Exceeded connection threshold: %d", existingIP.ConnectionCount))
		}
	} else {
		// 创建新记录
		newIP := &database.MaliciousIP{
			IPAddress:       ipAddress,
			FirstSeen:       event.Timestamp,
			LastSeen:        event.Timestamp,
			ConnectionCount: 1,
			Reason:          "Network activity detected",
			IsBanned:        false,
		}
		if err := ms.db.InsertOrUpdateMaliciousIP(newIP); err != nil {
			ms.logger.Errorf("Failed to insert malicious IP: %v", err)
		}
	}
}

func (ms *MonitorService) banMaliciousIP(ipAddress, reason string) {
	// 在数据库中标记为封禁
	duration := ms.config.Network.GetBanDuration()
	if err := ms.db.BanIP(ipAddress, duration, reason); err != nil {
		ms.logger.Errorf("Failed to ban IP %s in database: %v", ipAddress, err)
		return
	}

	// 在eBPF中封禁IP
	ip := net.ParseIP(ipAddress)
	if ip != nil {
		if err := ms.ebpfMonitor.BanIP(ip); err != nil {
			ms.logger.Errorf("Failed to ban IP %s in eBPF: %v", ipAddress, err)
		} else {
			ms.logger.Infof("IP %s banned for %v, reason: %s", ipAddress, duration, reason)
		}
	}
}

func (ms *MonitorService) startCleanupTask() {
	cleanupInterval := ms.config.Database.GetCleanupInterval()
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ms.ctx.Done():
			return
		case <-ticker.C:
			ms.logger.Info("Starting database cleanup")
			if err := ms.db.CleanupOldRecords(ms.config.Database.MaxRecords); err != nil {
				ms.logger.Errorf("Failed to cleanup database: %v", err)
			} else {
				ms.logger.Info("Database cleanup completed")
			}
		}
	}
}

func (ms *MonitorService) startBanCheckTask() {
	// 每分钟检查一次过期的封禁
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ms.ctx.Done():
			return
		case <-ticker.C:
			ms.checkExpiredBans()
		}
	}
}

func (ms *MonitorService) checkExpiredBans() {
	// 获取所有被封禁的IP
	bannedIPs, err := ms.db.GetBannedIPs()
	if err != nil {
		ms.logger.Errorf("Failed to get banned IPs: %v", err)
		return
	}

	now := time.Now()
	for _, bannedIP := range bannedIPs {
		// 检查封禁是否过期
		if bannedIP.BanUntil != nil && now.After(*bannedIP.BanUntil) {
			// 解封IP
			if err := ms.db.UnbanIP(bannedIP.IPAddress); err != nil {
				ms.logger.Errorf("Failed to unban IP %s in database: %v", bannedIP.IPAddress, err)
				continue
			}

			// 在eBPF中解封IP
			ip := net.ParseIP(bannedIP.IPAddress)
			if ip != nil {
				if err := ms.ebpfMonitor.UnbanIP(ip); err != nil {
					ms.logger.Errorf("Failed to unban IP %s in eBPF: %v", bannedIP.IPAddress, err)
				} else {
					ms.logger.Infof("IP %s ban expired and removed", bannedIP.IPAddress)
				}
			}
		}
	}

	// 更新gRPC服务器的统计信息
	activeBans := 0
	for _, bannedIP := range bannedIPs {
		if bannedIP.BanUntil == nil || now.Before(*bannedIP.BanUntil) {
			activeBans++
		}
	}
	ms.grpcServer.UpdateActiveConnections(int32(activeBans))
}
