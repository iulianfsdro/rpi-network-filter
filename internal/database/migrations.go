package database

import (
	"database/sql"
	"fmt"
	"log"
)

var migrations = []string{
	// v1: core schema
	`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac_address TEXT NOT NULL UNIQUE,
		ip_address TEXT DEFAULT '',
		hostname TEXT DEFAULT '',
		alias TEXT DEFAULT '',
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		is_blocked INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS firewall_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		description TEXT DEFAULT '',
		direction TEXT NOT NULL CHECK(direction IN ('inbound','outbound','forward')),
		protocol TEXT CHECK(protocol IN ('tcp','udp','icmp','all')),
		source_ip TEXT DEFAULT '',
		dest_ip TEXT DEFAULT '',
		dest_port TEXT DEFAULT '',
		action TEXT NOT NULL CHECK(action IN ('drop','reject','accept')),
		device_mac TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		priority INTEGER DEFAULT 100,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS dns_blocklist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		category TEXT DEFAULT 'custom',
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS bandwidth_limits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_mac TEXT NOT NULL UNIQUE,
		download_kbps INTEGER DEFAULT 0,
		upload_kbps INTEGER DEFAULT 0,
		enabled INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		action TEXT NOT NULL,
		details TEXT DEFAULT '',
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT OR IGNORE INTO settings (key, value) VALUES
		('ap_ssid', 'NetFilter'),
		('ap_password', 'changeme123'),
		('ap_channel', '6'),
		('dns_upstream', '1.1.1.1,8.8.8.8');`,

	// v2: query log table for persistent traffic history
	`CREATE TABLE IF NOT EXISTS query_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		client_ip TEXT DEFAULT '',
		domain TEXT DEFAULT '',
		dst_ip TEXT DEFAULT '',
		dst_port TEXT DEFAULT '',
		protocol TEXT DEFAULT '',
		action TEXT DEFAULT 'query',
		client_mac TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log(domain);
	CREATE INDEX IF NOT EXISTS idx_query_log_client ON query_log(client_ip);`,

	// v3: kv store for journalctl cursors and other state
	`CREATE TABLE IF NOT EXISTS kv_store (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT OR IGNORE INTO settings (key, value) VALUES
		('log_retention_days', '30');`,

	// v4: dynamic allow list via dnsmasq nftset integration
	`CREATE TABLE IF NOT EXISTS allowed_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		description TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
}

func Migrate(db *sql.DB) error {
	var currentVersion int
	row := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version")
	if err := row.Scan(&currentVersion); err != nil {
		// Table might not exist yet — that's fine, start from 0
		currentVersion = 0
	}

	for i := currentVersion; i < len(migrations); i++ {
		version := i + 1
		log.Printf("[DB] Applying migration v%d", version)

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration v%d: %w", version, err)
		}

		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration v%d: %w", version, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", version); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration v%d: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d: %w", version, err)
		}

		log.Printf("[DB] Migration v%d applied", version)
	}

	return nil
}
