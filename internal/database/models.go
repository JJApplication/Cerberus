package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sql.DB
}

type MaliciousIP struct {
	ID            int64     `json:"id"`
	IPAddress     string    `json:"ip_address"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	ConnectionCount int     `json:"connection_count"`
	Reason        string    `json:"reason"`
	IsBanned      bool      `json:"is_banned"`
	BanUntil      *time.Time `json:"ban_until,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type NetworkStat struct {
	ID            int64     `json:"id"`
	IPAddress     string    `json:"ip_address"`
	Timestamp     time.Time `json:"timestamp"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
	ConnectionCount int     `json:"connection_count"`
	RequestedURL  string    `json:"requested_url"`
	CreatedAt     time.Time `json:"created_at"`
}

type SystemAnomaly struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	AnomalyType string    `json:"anomaly_type"` // cpu, memory, disk_io
	Value       float64   `json:"value"`
	Threshold   float64   `json:"threshold"`
	ProcessName string    `json:"process_name"`
	ProcessID   int       `json:"process_id"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	d := &Database{db: db}
	if err := d.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return d, nil
}

func (d *Database) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS malicious_ips (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT UNIQUE NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			connection_count INTEGER DEFAULT 0,
			reason TEXT NOT NULL,
			is_banned BOOLEAN DEFAULT FALSE,
			ban_until DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS network_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			bytes_sent INTEGER DEFAULT 0,
			bytes_received INTEGER DEFAULT 0,
			connection_count INTEGER DEFAULT 0,
			requested_url TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS system_anomalies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			anomaly_type TEXT NOT NULL,
			value REAL NOT NULL,
			threshold REAL NOT NULL,
			process_name TEXT,
			process_id INTEGER,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_malicious_ips_ip ON malicious_ips(ip_address)`,
		`CREATE INDEX IF NOT EXISTS idx_malicious_ips_banned ON malicious_ips(is_banned)`,
		`CREATE INDEX IF NOT EXISTS idx_network_stats_ip ON network_stats(ip_address)`,
		`CREATE INDEX IF NOT EXISTS idx_network_stats_timestamp ON network_stats(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_system_anomalies_timestamp ON system_anomalies(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_system_anomalies_type ON system_anomalies(anomaly_type)`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query %s: %w", query, err)
		}
	}

	return nil
}

func (d *Database) Close() error {
	return d.db.Close()
}