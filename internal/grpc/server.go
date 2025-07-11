package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"github.com/sirupsen/logrus"

	"ebpf-monitor/internal/config"
	"ebpf-monitor/internal/database"
	"ebpf-monitor/proto"
)

type Server struct {
	proto.UnimplementedMonitorServiceServer
	db       *database.Database
	config   *config.Config
	logger   *logrus.Logger
	grpcServer *grpc.Server
	startTime  time.Time

	// 统计信息
	activeConnections int32
	bannedIPsCount    int32
}

func NewServer(db *database.Database, cfg *config.Config, logger *logrus.Logger) *Server {
	return &Server{
		db:        db,
		config:    cfg,
		logger:    logger,
		startTime: time.Now(),
	}
}

func (s *Server) Start() error {
	// 创建gRPC服务器
	s.grpcServer = grpc.NewServer()
	proto.RegisterMonitorServiceServer(s.grpcServer, s)

	// 启用反射（用于调试）
	reflection.Register(s.grpcServer)

	// 监听地址
	lis, err := net.Listen("tcp", s.config.GRPC.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.GRPC.ListenAddress, err)
	}

	s.logger.Infof("gRPC server starting on %s", s.config.GRPC.ListenAddress)

	// 启动服务器
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			s.logger.Errorf("gRPC server error: %v", err)
		}
	}()

	return nil
}

func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
		s.logger.Info("gRPC server stopped")
	}
}

// GetMaliciousIPs 获取恶意IP列表
func (s *Server) GetMaliciousIPs(ctx context.Context, req *proto.GetMaliciousIPsRequest) (*proto.GetMaliciousIPsResponse, error) {
	limit := int(req.Limit)
	offset := int(req.Offset)

	if limit <= 0 {
		limit = 100 // 默认限制
	}
	if limit > 1000 {
		limit = 1000 // 最大限制
	}

	ips, err := s.db.GetMaliciousIPs(limit, offset)
	if err != nil {
		s.logger.Errorf("Failed to get malicious IPs: %v", err)
		return nil, fmt.Errorf("failed to get malicious IPs: %w", err)
	}

	totalCount, err := s.db.GetMaliciousIPCount()
	if err != nil {
		s.logger.Errorf("Failed to get malicious IP count: %v", err)
		totalCount = 0
	}

	var protoIPs []*proto.MaliciousIP
	for _, ip := range ips {
		protoIP := &proto.MaliciousIP{
			IpAddress:       ip.IPAddress,
			FirstSeen:       ip.FirstSeen.Unix(),
			LastSeen:        ip.LastSeen.Unix(),
			ConnectionCount: int32(ip.ConnectionCount),
			Reason:          ip.Reason,
			IsBanned:        ip.IsBanned,
		}
		if ip.BanUntil != nil {
			protoIP.BanUntil = ip.BanUntil.Unix()
		}
		protoIPs = append(protoIPs, protoIP)
	}

	return &proto.GetMaliciousIPsResponse{
		Ips:        protoIPs,
		TotalCount: int32(totalCount),
	}, nil
}

// GetNetworkStats 获取网络流量统计
func (s *Server) GetNetworkStats(ctx context.Context, req *proto.GetNetworkStatsRequest) (*proto.GetNetworkStatsResponse, error) {
	startTime := time.Unix(req.StartTime, 0)
	endTime := time.Unix(req.EndTime, 0)

	// 验证时间范围
	if endTime.Before(startTime) {
		return nil, fmt.Errorf("end time must be after start time")
	}

	// 限制查询时间范围（最多7天）
	if endTime.Sub(startTime) > 7*24*time.Hour {
		return nil, fmt.Errorf("time range too large, maximum 7 days")
	}

	stats, err := s.db.GetNetworkStats(startTime, endTime)
	if err != nil {
		s.logger.Errorf("Failed to get network stats: %v", err)
		return nil, fmt.Errorf("failed to get network stats: %w", err)
	}

	var protoStats []*proto.NetworkStat
	for _, stat := range stats {
		protoStat := &proto.NetworkStat{
			IpAddress:       stat.IPAddress,
			Timestamp:       stat.Timestamp.Unix(),
			BytesSent:       stat.BytesSent,
			BytesReceived:   stat.BytesReceived,
			ConnectionCount: int32(stat.ConnectionCount),
			RequestedUrl:    stat.RequestedURL,
		}
		protoStats = append(protoStats, protoStat)
	}

	return &proto.GetNetworkStatsResponse{
		Stats: protoStats,
	}, nil
}

// GetSystemAnomalies 获取系统资源异常记录
func (s *Server) GetSystemAnomalies(ctx context.Context, req *proto.GetSystemAnomaliesRequest) (*proto.GetSystemAnomaliesResponse, error) {
	startTime := time.Unix(req.StartTime, 0)
	endTime := time.Unix(req.EndTime, 0)
	anomalyType := req.AnomalyType

	// 验证时间范围
	if endTime.Before(startTime) {
		return nil, fmt.Errorf("end time must be after start time")
	}

	// 限制查询时间范围（最多30天）
	if endTime.Sub(startTime) > 30*24*time.Hour {
		return nil, fmt.Errorf("time range too large, maximum 30 days")
	}

	// 验证异常类型
	if anomalyType != "" && anomalyType != "cpu" && anomalyType != "memory" && anomalyType != "disk_io" {
		return nil, fmt.Errorf("invalid anomaly type, must be one of: cpu, memory, disk_io")
	}

	anomalies, err := s.db.GetSystemAnomalies(startTime, endTime, anomalyType)
	if err != nil {
		s.logger.Errorf("Failed to get system anomalies: %v", err)
		return nil, fmt.Errorf("failed to get system anomalies: %w", err)
	}

	var protoAnomalies []*proto.SystemAnomaly
	for _, anomaly := range anomalies {
		protoAnomaly := &proto.SystemAnomaly{
			Timestamp:   anomaly.Timestamp.Unix(),
			AnomalyType: anomaly.AnomalyType,
			Value:       anomaly.Value,
			Threshold:   anomaly.Threshold,
			ProcessName: anomaly.ProcessName,
			ProcessId:   int32(anomaly.ProcessID),
			Description: anomaly.Description,
		}
		protoAnomalies = append(protoAnomalies, protoAnomaly)
	}

	return &proto.GetSystemAnomaliesResponse{
		Anomalies: protoAnomalies,
	}, nil
}

// BanIP 手动封禁IP
func (s *Server) BanIP(ctx context.Context, req *proto.BanIPRequest) (*proto.BanIPResponse, error) {
	ipAddress := req.IpAddress
	durationMinutes := req.DurationMinutes
	reason := req.Reason

	// 验证IP地址
	if net.ParseIP(ipAddress) == nil {
		return &proto.BanIPResponse{
			Success: false,
			Message: "Invalid IP address format",
		}, nil
	}

	// 验证封禁时长
	if durationMinutes <= 0 {
		durationMinutes = int32(s.config.Network.BanDurationMinutes) // 使用默认时长
	}

	if reason == "" {
		reason = "Manual ban"
	}

	duration := time.Duration(durationMinutes) * time.Minute
	err := s.db.BanIP(ipAddress, duration, reason)
	if err != nil {
		s.logger.Errorf("Failed to ban IP %s: %v", ipAddress, err)
		return &proto.BanIPResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to ban IP: %v", err),
		}, nil
	}

	s.logger.Infof("IP %s banned for %d minutes, reason: %s", ipAddress, durationMinutes, reason)

	return &proto.BanIPResponse{
		Success: true,
		Message: fmt.Sprintf("IP %s banned successfully for %d minutes", ipAddress, durationMinutes),
	}, nil
}

// UnbanIP 解封IP
func (s *Server) UnbanIP(ctx context.Context, req *proto.UnbanIPRequest) (*proto.UnbanIPResponse, error) {
	ipAddress := req.IpAddress

	// 验证IP地址
	if net.ParseIP(ipAddress) == nil {
		return &proto.UnbanIPResponse{
			Success: false,
			Message: "Invalid IP address format",
		}, nil
	}

	err := s.db.UnbanIP(ipAddress)
	if err != nil {
		s.logger.Errorf("Failed to unban IP %s: %v", ipAddress, err)
		return &proto.UnbanIPResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to unban IP: %v", err),
		}, nil
	}

	s.logger.Infof("IP %s unbanned", ipAddress)

	return &proto.UnbanIPResponse{
		Success: true,
		Message: fmt.Sprintf("IP %s unbanned successfully", ipAddress),
	}, nil
}

// GetMonitorStatus 获取实时监控状态
func (s *Server) GetMonitorStatus(ctx context.Context, req *proto.GetMonitorStatusRequest) (*proto.GetMonitorStatusResponse, error) {
	uptime := time.Since(s.startTime)

	// 获取被封禁IP数量
	bannedCount, err := s.db.GetBannedIPCount()
	if err != nil {
		s.logger.Errorf("Failed to get banned IP count: %v", err)
		bannedCount = 0
	}

	return &proto.GetMonitorStatusResponse{
		IsRunning:         true,
		UptimeSeconds:     int64(uptime.Seconds()),
		ActiveConnections: s.activeConnections,
		BannedIpsCount:    int32(bannedCount),
	}, nil
}

// UpdateActiveConnections 更新活跃连接数
func (s *Server) UpdateActiveConnections(count int32) {
	s.activeConnections = count
}