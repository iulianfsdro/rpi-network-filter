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

	// v5: explicit block list — domains that can never be allow-listed,
	// DNS-sinkholed to 0.0.0.0 so they fail to resolve even if the firewall
	// is bypassed. Seeded with Tesla firmware/diagnostic endpoints to prevent
	// accidental allow-list inclusion via the traffic monitor.
	`CREATE TABLE IF NOT EXISTS blocked_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		match_type TEXT NOT NULL DEFAULT 'suffix' CHECK(match_type IN ('exact','suffix')),
		reason TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT OR IGNORE INTO blocked_domains (domain, match_type, reason) VALUES
		('ota.vn.tesla.services',       'exact',  'Tesla firmware update channel'),
		('ota.cn.tesla.services',       'exact',  'Tesla firmware update channel (China)'),
		('firmware.vn.tesla.services',  'suffix', 'Tesla firmware metadata'),
		('software-update.tesla.com',   'suffix', 'Tesla update orchestration'),
		('dl.tesla.com',                'exact',  'Tesla firmware blob CDN'),
		('tesla-cdn.com',               'suffix', 'Tesla asset and firmware CDN'),
		('tesla-cdn.net',               'suffix', 'Tesla asset and firmware CDN'),
		('diag.vn.tesla.services',      'exact',  'Tesla remote diagnostics'),
		('remote-diagnostics.tesla.com','suffix', 'Tesla remote service access');`,

	// v6: per-policy allow-listing — replaces the single global allow list with
	// named policies that can be assigned to specific devices. Each policy has
	// its own mode ('permissive' falls back to the global default chain on a
	// miss; 'strict' drops on a miss) and its own set of allowed domains that
	// populate a dedicated nftables IP set.
	//
	// Default policy ships as STRICT with an EMPTY allow list. Unassigned
	// devices fall back to Default, so new devices joining the hotspot are
	// blocked by default until explicitly authorised in the UI. This is a
	// deliberate departure from v1's "permissive global list" model — security
	// posture first.
	//
	// Existing v1 allowed_domains entries are intentionally NOT migrated (per
	// user decision during v2 design). Users who want to restore them can
	// re-add from the v1 DB snapshot kept at /var/lib/netfilterd/netfilter.db.
	//
	// Tesla policy is strict with exactly one entry (connman.vn.tesla.services)
	// — the connection-manager endpoint that keeps the car online without
	// exposing OTA/diagnostic channels.
	//
	// Per-entry resolution metadata (resolved_ips, last_resolved_at, hit_count)
	// is populated by the re-resolve cron so the UI can answer "is this rule
	// actually working?" — addresses the main v1 UX complaint.
	`CREATE TABLE IF NOT EXISTS policies (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL UNIQUE,
		mode        TEXT NOT NULL DEFAULT 'permissive' CHECK(mode IN ('permissive','strict')),
		description TEXT DEFAULT '',
		is_default  INTEGER DEFAULT 0,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_default ON policies(is_default) WHERE is_default = 1;

	CREATE TABLE IF NOT EXISTS policy_allowed_domains (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		policy_id         INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
		domain            TEXT NOT NULL,
		description       TEXT DEFAULT '',
		enabled           INTEGER DEFAULT 1,
		resolved_ips      TEXT DEFAULT '',
		last_resolved_at  DATETIME,
		hit_count         INTEGER DEFAULT 0,
		created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(policy_id, domain)
	);

	CREATE INDEX IF NOT EXISTS idx_policy_domains_policy ON policy_allowed_domains(policy_id);

	CREATE TABLE IF NOT EXISTS device_policies (
		device_mac   TEXT PRIMARY KEY,
		policy_id    INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
		assigned_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT OR IGNORE INTO policies (name, mode, description, is_default) VALUES
		('Default', 'strict', 'Fallback policy for devices with no explicit assignment. Strict + empty by default — unassigned devices are blocked until you authorise them.', 1),
		('Tesla',   'strict', 'Tesla vehicle policy: connman keeps the car online; everything else blocked including OTA, diagnostics, and CDN.', 0);

	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'connman.vn.tesla.services', 'Tesla connection-manager; keeps car online without exposing OTA.'
	FROM policies WHERE name='Tesla';

	DROP TABLE allowed_domains;`,

	// v7: traffic monitor split — tag each query_log row with the source
	// stream (dns|forward) and, for forward rows, the policy name that
	// produced the verdict. The UI reads `source` to split DNS events
	// from firewall events into separate tabs so users stop confusing
	// dnsmasq query logs with actual packet drops/accepts.
	`ALTER TABLE query_log ADD COLUMN source TEXT DEFAULT 'forward';
	ALTER TABLE query_log ADD COLUMN policy TEXT DEFAULT '';
	UPDATE query_log SET source='dns' WHERE action='query';
	CREATE INDEX IF NOT EXISTS idx_query_log_source ON query_log(source);`,

	// v8: wipe device_policies rows with URL-encoded MACs that a
	// prior handler bug (no PathUnescape on the {mac} path param)
	// inserted as literal "aa%3abb%3a..." strings. Those strings
	// ended up verbatim in the generated nftables ruleset and broke
	// the Apply() call with "unexpected string, expecting colon".
	`DELETE FROM device_policies WHERE instr(device_mac, '%') > 0;`,

	// v9: add 'open' as a valid policy mode. An open-mode policy's
	// chain is a single `accept` rule — the hard block-list and the
	// DoH/DoT chokepoint still apply (they run before the per-MAC
	// vmap dispatch), but everything else is unconditionally allowed.
	// Required for trusted devices (owner phone, laptop, TV) where
	// curating a hostname allow list is impractical.
	//
	// SQLite can't ALTER a CHECK constraint in place — rebuild the
	// table and copy rows. FK references from device_policies use
	// the plain id so the drop+rename is safe (PRAGMA foreign_keys
	// defaults off in this build).
	`CREATE TABLE policies_new (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL UNIQUE,
		mode        TEXT NOT NULL DEFAULT 'permissive' CHECK(mode IN ('permissive','strict','open')),
		description TEXT DEFAULT '',
		is_default  INTEGER DEFAULT 0,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT INTO policies_new (id, name, mode, description, is_default, created_at)
	SELECT id, name, mode, description, is_default, created_at FROM policies;

	DROP TABLE policies;
	ALTER TABLE policies_new RENAME TO policies;

	CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_default ON policies(is_default) WHERE is_default = 1;

	INSERT OR IGNORE INTO policies (name, mode, description, is_default) VALUES
		('Open', 'open', 'Trusted devices — no allow-list filtering. Hard block-list + DoH/DoT chokepoint still apply.', 0);`,
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
