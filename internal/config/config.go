package config

import (
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Network  NetworkConfig  `toml:"network"`
	System   SystemConfig   `toml:"system"`
	GRPC     GRPCConfig     `toml:"grpc"`
	Database DatabaseConfig `toml:"database"`
	Logging  LoggingConfig  `toml:"logging"`
}

type NetworkConfig struct {
	Interface                 string   `toml:"interface"`
	MaxConnectionsPerIP       int      `toml:"max_connections_per_ip"`
	BanDurationMinutes        int      `toml:"ban_duration_minutes"`
	MonitoringIntervalSeconds int      `toml:"monitoring_interval_seconds"`
	MaliciousURLPatterns      []string `toml:"malicious_url_patterns"`
}

type SystemConfig struct {
	CPUThresholdPercent       float64 `toml:"cpu_threshold_percent"`
	MemoryThresholdPercent    float64 `toml:"memory_threshold_percent"`
	DiskIOThresholdMbps       float64 `toml:"disk_io_threshold_mbps"`
	MonitoringWindowMinutes   int     `toml:"monitoring_window_minutes"`
}

type GRPCConfig struct {
	ListenAddress string `toml:"listen_address"`
	UDSSocketPath string `toml:"uds_socket_path"`
}

type DatabaseConfig struct {
	SQLitePath            string `toml:"sqlite_path"`
	MaxRecords            int    `toml:"max_records"`
	CleanupIntervalHours  int    `toml:"cleanup_interval_hours"`
}

type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
	Output string `toml:"output"`
}

// GetBanDuration returns the ban duration as time.Duration
func (n *NetworkConfig) GetBanDuration() time.Duration {
	return time.Duration(n.BanDurationMinutes) * time.Minute
}

// GetMonitoringInterval returns the monitoring interval as time.Duration
func (n *NetworkConfig) GetMonitoringInterval() time.Duration {
	return time.Duration(n.MonitoringIntervalSeconds) * time.Second
}

// GetMonitoringWindow returns the monitoring window as time.Duration
func (s *SystemConfig) GetMonitoringWindow() time.Duration {
	return time.Duration(s.MonitoringWindowMinutes) * time.Minute
}

// GetCleanupInterval returns the cleanup interval as time.Duration
func (d *DatabaseConfig) GetCleanupInterval() time.Duration {
	return time.Duration(d.CleanupIntervalHours) * time.Hour
}

// LoadConfig loads configuration from TOML file
func LoadConfig(configPath string) (*Config, error) {
	var config Config

	// Set default values
	config.Network.Interface = "eth0"
	config.Network.MaxConnectionsPerIP = 100
	config.Network.BanDurationMinutes = 60
	config.Network.MonitoringIntervalSeconds = 10
	config.Network.MaliciousURLPatterns = []string{
		"/admin", "/wp-admin", "/.env", "/config", "/backup", "/phpmyadmin",
	}

	config.System.CPUThresholdPercent = 80.0
	config.System.MemoryThresholdPercent = 85.0
	config.System.DiskIOThresholdMbps = 100.0
	config.System.MonitoringWindowMinutes = 5

	config.GRPC.ListenAddress = "127.0.0.1:50051"
	config.GRPC.UDSSocketPath = "/tmp/ebpf-monitor.sock"

	config.Database.SQLitePath = "./monitor.db"
	config.Database.MaxRecords = 10000
	config.Database.CleanupIntervalHours = 24

	config.Logging.Level = "info"
	config.Logging.Format = "text"
	config.Logging.Output = "stdout"

	// Load from file if provided
	if configPath != "" {
		if _, err := toml.DecodeFile(configPath, &config); err != nil {
			return nil, fmt.Errorf("failed to decode config file: %w", err)
		}
	}

	return &config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Network.Interface == "" {
		return fmt.Errorf("network interface must be specified")
	}

	if c.Network.MaxConnectionsPerIP <= 0 {
		return fmt.Errorf("max_connections_per_ip must be positive")
	}

	if c.Network.BanDurationMinutes <= 0 {
		return fmt.Errorf("ban_duration_minutes must be positive")
	}

	if c.Network.MonitoringIntervalSeconds <= 0 {
		return fmt.Errorf("monitoring_interval_seconds must be positive")
	}

	if c.System.CPUThresholdPercent <= 0 || c.System.CPUThresholdPercent > 100 {
		return fmt.Errorf("cpu_threshold_percent must be between 0 and 100")
	}

	if c.System.MemoryThresholdPercent <= 0 || c.System.MemoryThresholdPercent > 100 {
		return fmt.Errorf("memory_threshold_percent must be between 0 and 100")
	}

	if c.System.DiskIOThresholdMbps <= 0 {
		return fmt.Errorf("disk_io_threshold_mbps must be positive")
	}

	if c.System.MonitoringWindowMinutes <= 0 {
		return fmt.Errorf("monitoring_window_minutes must be positive")
	}

	if c.Database.MaxRecords <= 0 {
		return fmt.Errorf("max_records must be positive")
	}

	if c.Database.CleanupIntervalHours <= 0 {
		return fmt.Errorf("cleanup_interval_hours must be positive")
	}

	if c.Logging.Level == "" {
		return fmt.Errorf("logging level must be specified")
	}

	validLevels := []string{"debug", "info", "warn", "error"}
	validLevel := false
	for _, level := range validLevels {
		if c.Logging.Level == level {
			validLevel = true
			break
		}
	}
	if !validLevel {
		return fmt.Errorf("invalid logging level: %s, must be one of: debug, info, warn, error", c.Logging.Level)
	}

	return nil
}