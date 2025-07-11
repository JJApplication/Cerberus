package database

import (
	"database/sql"
	"fmt"
	"time"
)

// MaliciousIP operations
func (d *Database) InsertOrUpdateMaliciousIP(ip *MaliciousIP) error {
	query := `
		INSERT INTO malicious_ips (ip_address, first_seen, last_seen, connection_count, reason, is_banned, ban_until)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip_address) DO UPDATE SET
			last_seen = excluded.last_seen,
			connection_count = connection_count + excluded.connection_count,
			reason = excluded.reason,
			is_banned = excluded.is_banned,
			ban_until = excluded.ban_until,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := d.db.Exec(query, ip.IPAddress, ip.FirstSeen, ip.LastSeen, ip.ConnectionCount, ip.Reason, ip.IsBanned, ip.BanUntil)
	return err
}

func (d *Database) GetMaliciousIPs(limit, offset int) ([]*MaliciousIP, error) {
	query := `
		SELECT id, ip_address, first_seen, last_seen, connection_count, reason, is_banned, ban_until, created_at, updated_at
		FROM malicious_ips
		ORDER BY last_seen DESC
		LIMIT ? OFFSET ?
	`
	rows, err := d.db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*MaliciousIP
	for rows.Next() {
		ip := &MaliciousIP{}
		err := rows.Scan(&ip.ID, &ip.IPAddress, &ip.FirstSeen, &ip.LastSeen, &ip.ConnectionCount, &ip.Reason, &ip.IsBanned, &ip.BanUntil, &ip.CreatedAt, &ip.UpdatedAt)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

func (d *Database) GetMaliciousIPByAddress(ipAddress string) (*MaliciousIP, error) {
	query := `
		SELECT id, ip_address, first_seen, last_seen, connection_count, reason, is_banned, ban_until, created_at, updated_at
		FROM malicious_ips
		WHERE ip_address = ?
	`
	ip := &MaliciousIP{}
	err := d.db.QueryRow(query, ipAddress).Scan(&ip.ID, &ip.IPAddress, &ip.FirstSeen, &ip.LastSeen, &ip.ConnectionCount, &ip.Reason, &ip.IsBanned, &ip.BanUntil, &ip.CreatedAt, &ip.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ip, nil
}

func (d *Database) BanIP(ipAddress string, duration time.Duration, reason string) error {
	banUntil := time.Now().Add(duration)
	query := `
		INSERT INTO malicious_ips (ip_address, first_seen, last_seen, connection_count, reason, is_banned, ban_until)
		VALUES (?, ?, ?, 1, ?, TRUE, ?)
		ON CONFLICT(ip_address) DO UPDATE SET
			is_banned = TRUE,
			ban_until = excluded.ban_until,
			reason = excluded.reason,
			updated_at = CURRENT_TIMESTAMP
	`
	now := time.Now()
	_, err := d.db.Exec(query, ipAddress, now, now, reason, banUntil)
	return err
}

func (d *Database) UnbanIP(ipAddress string) error {
	query := `UPDATE malicious_ips SET is_banned = FALSE, ban_until = NULL, updated_at = CURRENT_TIMESTAMP WHERE ip_address = ?`
	_, err := d.db.Exec(query, ipAddress)
	return err
}

func (d *Database) GetBannedIPs() ([]*MaliciousIP, error) {
	query := `
		SELECT id, ip_address, first_seen, last_seen, connection_count, reason, is_banned, ban_until, created_at, updated_at
		FROM malicious_ips
		WHERE is_banned = TRUE AND (ban_until IS NULL OR ban_until > ?)
	`
	rows, err := d.db.Query(query, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*MaliciousIP
	for rows.Next() {
		ip := &MaliciousIP{}
		err := rows.Scan(&ip.ID, &ip.IPAddress, &ip.FirstSeen, &ip.LastSeen, &ip.ConnectionCount, &ip.Reason, &ip.IsBanned, &ip.BanUntil, &ip.CreatedAt, &ip.UpdatedAt)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// NetworkStat operations
func (d *Database) InsertNetworkStat(stat *NetworkStat) error {
	query := `
		INSERT INTO network_stats (ip_address, timestamp, bytes_sent, bytes_received, connection_count, requested_url)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := d.db.Exec(query, stat.IPAddress, stat.Timestamp, stat.BytesSent, stat.BytesReceived, stat.ConnectionCount, stat.RequestedURL)
	return err
}

func (d *Database) GetNetworkStats(startTime, endTime time.Time) ([]*NetworkStat, error) {
	query := `
		SELECT id, ip_address, timestamp, bytes_sent, bytes_received, connection_count, requested_url, created_at
		FROM network_stats
		WHERE timestamp BETWEEN ? AND ?
		ORDER BY timestamp DESC
	`
	rows, err := d.db.Query(query, startTime, endTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []*NetworkStat
	for rows.Next() {
		stat := &NetworkStat{}
		err := rows.Scan(&stat.ID, &stat.IPAddress, &stat.Timestamp, &stat.BytesSent, &stat.BytesReceived, &stat.ConnectionCount, &stat.RequestedURL, &stat.CreatedAt)
		if err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}

	return stats, nil
}

// SystemAnomaly operations
func (d *Database) InsertSystemAnomaly(anomaly *SystemAnomaly) error {
	query := `
		INSERT INTO system_anomalies (timestamp, anomaly_type, value, threshold, process_name, process_id, description)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err := d.db.Exec(query, anomaly.Timestamp, anomaly.AnomalyType, anomaly.Value, anomaly.Threshold, anomaly.ProcessName, anomaly.ProcessID, anomaly.Description)
	return err
}

func (d *Database) GetSystemAnomalies(startTime, endTime time.Time, anomalyType string) ([]*SystemAnomaly, error) {
	query := `
		SELECT id, timestamp, anomaly_type, value, threshold, process_name, process_id, description, created_at
		FROM system_anomalies
		WHERE timestamp BETWEEN ? AND ?
	`
	args := []interface{}{startTime, endTime}

	if anomalyType != "" {
		query += " AND anomaly_type = ?"
		args = append(args, anomalyType)
	}

	query += " ORDER BY timestamp DESC"

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var anomalies []*SystemAnomaly
	for rows.Next() {
		anomaly := &SystemAnomaly{}
		err := rows.Scan(&anomaly.ID, &anomaly.Timestamp, &anomaly.AnomalyType, &anomaly.Value, &anomaly.Threshold, &anomaly.ProcessName, &anomaly.ProcessID, &anomaly.Description, &anomaly.CreatedAt)
		if err != nil {
			return nil, err
		}
		anomalies = append(anomalies, anomaly)
	}

	return anomalies, nil
}

// Cleanup operations
func (d *Database) CleanupOldRecords(maxRecords int) error {
	tables := []string{"network_stats", "system_anomalies"}

	for _, table := range tables {
		query := fmt.Sprintf(`
			DELETE FROM %s
			WHERE id NOT IN (
				SELECT id FROM %s
				ORDER BY created_at DESC
				LIMIT ?
			)
		`, table, table)
		_, err := d.db.Exec(query, maxRecords)
		if err != nil {
			return fmt.Errorf("failed to cleanup %s: %w", table, err)
		}
	}

	return nil
}

func (d *Database) GetMaliciousIPCount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM malicious_ips").Scan(&count)
	return count, err
}

func (d *Database) GetBannedIPCount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM malicious_ips WHERE is_banned = TRUE AND (ban_until IS NULL OR ban_until > ?)", time.Now()).Scan(&count)
	return count, err
}