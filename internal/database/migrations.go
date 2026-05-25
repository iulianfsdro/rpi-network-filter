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

	// v10: Tesla MCU3 Preset B block-list + Tesla-policy allow list expansion.
	//
	// Derived from a per-endpoint impact analysis of Tesla Model 3 MCU3
	// firmware 2026.8.6 (fw_dump/TESLA_DOMAINS_BLOCKLIST.md in the sibling
	// fsd/ project). Preset B = "no config changes / FSD retention": Tesla
	// can no longer push firmware, rotate features, downgrade tier, or
	// VIN-ban; all surveillance/telemetry/upload pipes die; nav, maps,
	// Supercharger, account auth, and music services still work. Mobile
	// app loses live features (live status, remote lock) because those
	// ride the Hermes channel we're killing.
	//
	// The blocked entries go into blocked_domains (DNS-sinkholed globally,
	// pre-empting any policy allow list). The Tesla policy allow list also
	// grows so the car doesn't just hit connman in isolation — it can
	// resolve go.tesla.services (nav), auth.tesla.com (OAuth),
	// managed-charging (Supercharger billing + music tokens), and
	// maps.googleapis.com (fallback geocoding).
	`INSERT OR IGNORE INTO blocked_domains (domain, match_type, reason) VALUES
		-- Control plane (OTA + Hermes command channel)
		('mothership.vn.teslamotors.com',                           'suffix', 'Tesla fleet command/sync (Preset B)'),
		('firmware-ota.vn.teslamotors.com',                         'suffix', 'Tesla OTA push orchestration'),
		('firmware-bundles.vn.teslamotors.com',                     'suffix', 'Tesla OTA firmware bundle CDN'),
		('firmware-media.vn.teslamotors.com',                       'suffix', 'Tesla firmware media assets'),
		('firmware-media-adapter.vn.teslamotors.com',               'suffix', 'Tesla firmware media adapter'),
		('hermes-prd.ap.tesla.services',                            'suffix', 'Tesla Hermes mTLS command WebSocket'),
		('hermes-api.prd.aus07.vn.cloud.tesla.com',                 'suffix', 'Tesla Hermes REST companion'),
		('hermes-stream-api.prd.aus07.vn.cloud.tesla.com',          'suffix', 'Tesla Hermes streaming pipeline'),
		('hermes-prd1.i.tslans.net',                                'suffix', 'Tesla Hermes cellular fallback'),
		('hermes-stream-prd1.i.tslans.net',                         'suffix', 'Tesla Hermes stream cellular'),
		('apf-api.prd.vn.cloud.tesla.com',                          'suffix', 'Tesla AP Firmware API'),
		-- Telemetry / surveillance / upload
		('telemetry-prd.ap.tesla.services',                         'suffix', 'Tesla AP telemetry live stream'),
		('telemetry-prd.vn.tesla.services',                         'suffix', 'Tesla MCU interaction telemetry'),
		('logupload-prod.vn.tesla.services',                        'suffix', 'Tesla car log upload'),
		('x1.ap.tesla.services',                                    'suffix', 'Tesla FSD parking-lot data upload'),
		('x3-prod.obs.tesla.com',                                   'suffix', 'Tesla Sentry / dashcam cloud upload'),
		('x3-static.obs.tesla.com',                                 'suffix', 'Tesla Sentry static assets'),
		('s3.ap.tesla.services',                                    'exact',  'Tesla S3 bulk upload'),
		('tesla-hermes-snapshot.s3.us-west-2.amazonaws.com',        'exact',  'Tesla Sentry snapshot bucket (US)'),
		('tesla-hermes-snapshot-eu.s3.eu-central-1.amazonaws.com',  'exact',  'Tesla Sentry snapshot bucket (EU)'),
		('fake.hypnos.vn.tesla.services',                           'suffix', 'Tesla a/b test + feature-flag sink'),
		('remote-access-registry.ap.teslamotors.com',               'suffix', 'Tesla engineering remote SSH gateway'),
		('info-server.mo.tesla.services',                           'suffix', 'Tesla manufacturing info server'),
		('mes.mo.tesla.services',                                   'suffix', 'Tesla Manufacturing Execution System'),
		('sim-fac.mo.tesla.services',                               'suffix', 'Tesla SIM provisioning registry'),
		('api-prd.ap.tesla.services',                               'suffix', 'Tesla AP diagnostic log API'),
		-- Engineering (should never be reached by production cars)
		('api-eng.ap.tesla.services',                               'suffix', 'Tesla engineering AP API'),
		('hermes-eng.ap.tesla.services',                            'suffix', 'Tesla engineering Hermes'),
		('telemetry-eng.ap.tesla.services',                         'suffix', 'Tesla engineering AP telemetry'),
		('telemetry-eng.vn.tesla.services',                         'suffix', 'Tesla engineering VN telemetry'),
		('logupload-eng.vn.tesla.services',                         'suffix', 'Tesla engineering log upload'),
		('x3-eng.obs.tesla.com',                                    'suffix', 'Tesla engineering object storage'),
		('apf-api.eng.vn.cloud.tesla.com',                          'suffix', 'Tesla engineering AP firmware'),
		('webapp-eng.vn.cloud.tesla.com',                           'suffix', 'Tesla engineering webapps'),
		('navsrv.eng.go.tesla.services',                            'suffix', 'Tesla engineering nav (beats go.tesla.services allow)'),
		('api-fac-vn-tesla-services.i.tslans.net',                  'suffix', 'Tesla factory provisioning'),
		('tesla-hermes-snapshot-eng.s3.us-west-2.amazonaws.com',    'exact',  'Tesla engineering snapshot bucket'),
		('tesla-hermes-snapshot-eng-eu.s3.eu-central-1.amazonaws.com','exact','Tesla engineering snapshot bucket EU'),
		-- Corporate (never from a car)
		('typhoon.fw.teslamotors.com',                              'suffix', 'Tesla internal Jenkins build server'),
		('github-fw.tesla.com',                                     'suffix', 'Tesla internal GitHub'),
		('stash.teslamotors.com',                                   'exact',  'Tesla internal Bitbucket'),
		('confluence.teslamotors.com',                              'exact',  'Tesla internal wiki'),
		('artifactory.teslamotors.com',                             'exact',  'Tesla internal artifactory'),
		('toolbox.tesla.com',                                       'exact',  'Tesla Toolbox service portal'),
		('toolbox.teslamotors.com',                                 'exact',  'Tesla Toolbox service portal'),
		('toolbox-beta.teslamotors.com',                            'suffix', 'Tesla Toolbox beta'),
		('toolbox-stg.teslamotors.com',                             'suffix', 'Tesla Toolbox staging'),
		('toolbox-external-stg.teslamotors.com',                    'suffix', 'Tesla Toolbox external staging'),
		('toolbox-mfg.teslamotors.com',                             'suffix', 'Tesla Toolbox manufacturing'),
		('va.teslamotors.com',                                      'exact',  'Tesla internal va service'),
		('epc.tesla.com',                                           'exact',  'Tesla Electronic Parts Catalog'),
		('parts.tesla.com',                                         'exact',  'Tesla parts portal');

	-- Expand Tesla policy allow list so the car keeps useful features.
	-- go.tesla.services is a suffix match — covers maps-%1, maps-ap-%1,
	-- maps-eu-%1, maps-kr-%1, and apmv3.go.tesla.services in one entry.
	-- navsrv.eng.go.tesla.services (blocked above) beats this via the
	-- most-specific-match DNS sinkhole rule.
	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'auth.tesla.com',                   'Tesla OAuth — mobile app pairing, supercharger billing'
	FROM policies WHERE name='Tesla';

	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'managed-charging.sn.tesla.services','Supercharger billing + music-service OAuth proxy'
	FROM policies WHERE name='Tesla';

	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'go.tesla.services',                'Tesla map tile + routing (covers maps-*, apmv3 via suffix)'
	FROM policies WHERE name='Tesla';

	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'maps.googleapis.com',              'Google maps / geocoding / timezone fallback'
	FROM policies WHERE name='Tesla';`,

	// v11: per-device opt-out from traffic logging. The flag is purely a
	// log-suppression hint — firewall rules still apply as configured;
	// only the query_log INSERT is skipped for events sourced from this
	// device. Default 0 means existing devices keep being logged. Used
	// to silence chatty trusted devices (e.g. owner laptop generating
	// thousands of DNS lookups per minute) so the traffic monitor stays
	// useful for spotting anomalies on locked-down devices.
	`ALTER TABLE devices ADD COLUMN ignore_traffic_log INTEGER NOT NULL DEFAULT 0;`,

	// v12: traffic-monitor search index. The monitor's substring search
	// was a 4x leading-wildcard LIKE over query_log — unindexable, so a
	// full table scan (~3.6s on a 100k+ row table). An FTS5 virtual table
	// with the trigram tokenizer makes substring MATCH sub-100ms at any
	// table size. content='query_log' keeps it external (index only, no
	// data copy); triggers keep it in sync. query_log rows are only ever
	// inserted or deleted (never updated), so no AFTER UPDATE trigger.
	// The final INSERT...SELECT backfills the existing rows.
	`CREATE INDEX IF NOT EXISTS idx_query_log_action ON query_log(action);

	CREATE VIRTUAL TABLE IF NOT EXISTS query_log_fts USING fts5(
		domain, dst_ip, client_ip, dst_port,
		content='query_log', content_rowid='id', tokenize='trigram'
	);

	CREATE TRIGGER IF NOT EXISTS query_log_fts_ai AFTER INSERT ON query_log BEGIN
		INSERT INTO query_log_fts(rowid, domain, dst_ip, client_ip, dst_port)
		VALUES (new.id, new.domain, new.dst_ip, new.client_ip, new.dst_port);
	END;

	CREATE TRIGGER IF NOT EXISTS query_log_fts_ad AFTER DELETE ON query_log BEGIN
		INSERT INTO query_log_fts(query_log_fts, rowid, domain, dst_ip, client_ip, dst_port)
		VALUES ('delete', old.id, old.domain, old.dst_ip, old.client_ip, old.dst_port);
	END;

	INSERT INTO query_log_fts(rowid, domain, dst_ip, client_ip, dst_port)
	SELECT id, domain, dst_ip, client_ip, dst_port FROM query_log;`,

	// v13: muted domains — patterns whose traffic events are dropped at
	// ingest (never written to query_log), to keep the monitor readable
	// when a device spams repetitive lookups. Distinct from blocked_domains
	// (firewall/DNS deny): muting only suppresses logging, it changes no
	// network behaviour. Same exact/suffix match shape as blocked_domains.
	`CREATE TABLE IF NOT EXISTS muted_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pattern TEXT NOT NULL UNIQUE,
		match_type TEXT NOT NULL DEFAULT 'suffix' CHECK(match_type IN ('exact','suffix')),
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,

	// v14: drop the explicit block-list. V3 makes the SNI proxy the sole
	// :443 gate with a default-deny posture — anything not on a policy's
	// allow list is dropped, so an enumerated block-list is redundant.
	// DNS is reconfigured (in code, not schema) to a default-deny
	// allow-list as the extra-defense layer. The per-policy IP-set
	// machinery and the DoH/DoT chokepoint are removed in the same
	// release. dns_blocklist (the separate Pi-hole-style ad-block list)
	// is untouched.
	`DROP TABLE IF EXISTS blocked_domains;`,

	// v15: presets-per-device model. The V2 "policy" abstraction was a
	// V1 hangover for per-policy nftables chains/sets that V3 doesn't
	// have — in V3 a policy was just a named bag of domains, which is
	// the worse half of a preset. Replace with composable curated
	// preset bundles attached to devices by MAC.
	//
	// Device classification collapses to a single `status` field:
	//   unknown  — new or unclassified; forward chain drops everything.
	//   filtered — SNI-gated by the UNION of enabled presets on the device.
	//   trusted  — bypasses the SNI gate entirely (V3's old "Open" mode).
	//   blocked  — explicit user-set block; forward chain hard-drops.
	//
	// The protected-deny floor still applies on every preset_domain insert.
	// dns_blocklist (Pi-hole-style ad-block) is dropped — it was vestigial
	// under V3's default-deny DNS.
	//
	// Tesla AP/Nav seed contains ONLY the four cert-audited safe domains:
	// no auth.tesla.com (shares the Akamai *.tesla.com cert with toolbox/
	// epc), no bare go.tesla.services (suffix re-admits eng nav), no
	// managed-charging. Nav only.
	`CREATE TABLE IF NOT EXISTS presets (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL UNIQUE,
		description TEXT DEFAULT '',
		is_system   INTEGER NOT NULL DEFAULT 0,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS preset_domains (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		preset_id         INTEGER NOT NULL REFERENCES presets(id) ON DELETE CASCADE,
		domain            TEXT NOT NULL,
		description       TEXT DEFAULT '',
		enabled           INTEGER NOT NULL DEFAULT 0,
		resolved_ips      TEXT DEFAULT '',
		last_resolved_at  DATETIME,
		hit_count         INTEGER DEFAULT 0,
		created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(preset_id, domain)
	);

	CREATE INDEX IF NOT EXISTS idx_preset_domains_preset ON preset_domains(preset_id);

	CREATE TABLE IF NOT EXISTS device_presets (
		device_mac  TEXT NOT NULL,
		preset_id   INTEGER NOT NULL REFERENCES presets(id) ON DELETE CASCADE,
		assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (device_mac, preset_id)
	);

	CREATE INDEX IF NOT EXISTS idx_device_presets_mac ON device_presets(device_mac);

	ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'unknown';

	-- Migrate existing classifications BEFORE dropping the old tables.
	-- Open-mode policy → trusted. Other policy → filtered.
	-- is_blocked=1 wins over either.
	UPDATE devices SET status='trusted'
	WHERE LOWER(mac_address) IN (
		SELECT LOWER(dp.device_mac)
		FROM device_policies dp JOIN policies p ON p.id = dp.policy_id
		WHERE p.mode = 'open'
	);

	UPDATE devices SET status='filtered'
	WHERE LOWER(mac_address) IN (
		SELECT LOWER(dp.device_mac)
		FROM device_policies dp JOIN policies p ON p.id = dp.policy_id
		WHERE p.mode != 'open'
	);

	UPDATE devices SET status='blocked' WHERE is_blocked = 1;

	-- Seed the four system presets.
	INSERT INTO presets (name, description, is_system) VALUES
		('Tesla AP/Nav', 'Tesla navigation + autopilot map data. Audited safe: every entry has a tightly-scoped cert (single-name or 4-SAN no-wildcard) with no overlap onto protected endpoints.', 1),
		('YouTube',      'YouTube web app, video CDN (googlevideo), thumbnails (ytimg), channel avatars (ggpht), short URLs (youtu.be).', 1),
		('Netflix',      'Netflix web/app + video and image CDNs (nflxvideo, nflximg, nflxext, nflxso).', 1),
		('Disney+',      'Disney+ streaming via BAMTech / Disney Streaming Services (disneyplus, disney-plus, dssott, bamgrid).', 1);

	-- Tesla AP/Nav: ONLY the audited safe four. Nav only.
	INSERT INTO preset_domains (preset_id, domain, description, enabled)
	SELECT id, 'daws.tesla.services',           'Tesla nav data — single-name cert on CloudFront, audited safe',                       1 FROM presets WHERE name='Tesla AP/Nav'
	UNION ALL SELECT id, 'apmv3.go.tesla.services',       'Tesla Autopilot map data v3 — single-name cert on Akamai, audited safe',     1 FROM presets WHERE name='Tesla AP/Nav'
	UNION ALL SELECT id, 'maps-eu-prd.go.tesla.services', 'Tesla EU maps backend — mTLS, 4-SAN cert (regional map servers, no wildcard)',1 FROM presets WHERE name='Tesla AP/Nav'
	UNION ALL SELECT id, 'maps.googleapis.com',           'Google maps / geocoding fallback — wildcard, but no Tesla overlap',          1 FROM presets WHERE name='Tesla AP/Nav';

	-- YouTube preset.
	INSERT INTO preset_domains (preset_id, domain, description, enabled)
	SELECT id, 'youtube.com',     'YouTube web app + API',        1 FROM presets WHERE name='YouTube'
	UNION ALL SELECT id, 'googlevideo.com', 'YouTube video CDN (segments)', 1 FROM presets WHERE name='YouTube'
	UNION ALL SELECT id, 'ytimg.com',       'YouTube thumbnails',           1 FROM presets WHERE name='YouTube'
	UNION ALL SELECT id, 'ggpht.com',       'YouTube channel avatars',      1 FROM presets WHERE name='YouTube'
	UNION ALL SELECT id, 'youtu.be',        'YouTube short-URL redirects',  1 FROM presets WHERE name='YouTube';

	-- Netflix preset.
	INSERT INTO preset_domains (preset_id, domain, description, enabled)
	SELECT id, 'netflix.com',   'Netflix web/app + API',     1 FROM presets WHERE name='Netflix'
	UNION ALL SELECT id, 'nflxvideo.net', 'Netflix video CDN',         1 FROM presets WHERE name='Netflix'
	UNION ALL SELECT id, 'nflximg.com',   'Netflix images / box-art',  1 FROM presets WHERE name='Netflix'
	UNION ALL SELECT id, 'nflxext.com',   'Netflix external assets',   1 FROM presets WHERE name='Netflix'
	UNION ALL SELECT id, 'nflxso.net',    'Netflix static origin',     1 FROM presets WHERE name='Netflix';

	-- Disney+ preset.
	INSERT INTO preset_domains (preset_id, domain, description, enabled)
	SELECT id, 'disneyplus.com',  'Disney+ web/app',                                 1 FROM presets WHERE name='Disney+'
	UNION ALL SELECT id, 'disney-plus.net', 'Disney+ related origin',                         1 FROM presets WHERE name='Disney+'
	UNION ALL SELECT id, 'dssott.com',      'Disney Streaming Services origin / token API',   1 FROM presets WHERE name='Disney+'
	UNION ALL SELECT id, 'bamgrid.com',     'BAMTech / Disney Streaming Services CDN',        1 FROM presets WHERE name='Disney+';

	-- Attach Tesla AP/Nav to every device that was previously on the old
	-- Tesla policy. Those devices are now status='filtered' (set above)
	-- and get the curated safe nav-only allow list via this preset.
	INSERT OR IGNORE INTO device_presets (device_mac, preset_id)
	SELECT LOWER(dp.device_mac), pr.id
	FROM device_policies dp
	JOIN policies p ON p.id = dp.policy_id
	JOIN presets pr ON pr.name = 'Tesla AP/Nav'
	WHERE p.name = 'Tesla';

	-- Drop the old policy/IP-set model.
	DROP TABLE IF EXISTS device_policies;
	DROP TABLE IF EXISTS policy_allowed_domains;
	DROP TABLE IF EXISTS policies;

	-- Drop the vestigial Pi-hole-style ad-block list.
	DROP TABLE IF EXISTS dns_blocklist;`,

	// v16: filter model — rename "presets" to "filters" and make them
	// GLOBAL toggles instead of per-device attachments.
	//
	// V3 (v15) shipped presets attached individually to each device via
	// device_presets. Operator feedback: it's needless ceremony — in
	// practice the operator wants to flip "YouTube" on or off for the
	// whole network, not per-MAC. The model collapses to:
	//
	//   - filters (renamed from presets) carry a new `enabled` column.
	//     When enabled=1, every domain inside applies to ALL filtered
	//     devices.
	//   - device_presets disappears entirely.
	//   - The "Status" / "Traffic" classification simplifies to three
	//     values: blocked (default for new devices), filtered, open.
	//     The old "unknown" rolls into blocked; "trusted" → "open".
	//
	// Description on filter_domains becomes effectively required at the
	// service layer (CreateDomain rejects an empty description); the
	// column itself stays nullable for migration safety.
	`-- Map old statuses onto the new three-value scheme.
	UPDATE devices SET status='blocked' WHERE status='unknown';
	UPDATE devices SET status='open'    WHERE status='trusted';

	-- Add the new `+"`enabled`"+` toggle to presets. A preset that was
	-- attached to at least one device (under v15's per-device model) is
	-- assumed live and gets enabled=1; anything else stays off so the
	-- operator can opt it in explicitly. Default 0 keeps fresh installs
	-- conservative.
	ALTER TABLE presets ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0;
	UPDATE presets SET enabled=1
	WHERE id IN (SELECT DISTINCT preset_id FROM device_presets);

	-- Drop the per-device attachment table. Filters are global from here on.
	DROP TABLE IF EXISTS device_presets;

	-- Rename presets → filters and preset_domains → filter_domains. The
	-- foreign-key REFERENCES inside filter_domains still resolves to the
	-- renamed table (SQLite tracks references by name, but ALTER RENAME
	-- updates them) — verified by the v16 migration test.
	ALTER TABLE presets RENAME TO filters;
	ALTER TABLE preset_domains RENAME TO filter_domains;
	-- The internal FK column keeps the legacy name `+"`preset_id`"+`. Renaming
	-- it would force a full table rebuild for a cosmetic gain; the service
	-- layer reads it through a constant. The index name is also legacy.

	-- For migrated installs that already had Tesla AP/Nav attached to a
	-- device (i.e. enabled=1 above), make sure its domains are enabled
	-- too — they were enabled at v15 seed time, but a defensive UPDATE
	-- keeps the post-migration state self-consistent.
	UPDATE filter_domains SET enabled=1
	WHERE preset_id IN (SELECT id FROM filters WHERE name='Tesla AP/Nav' AND enabled=1)
	  AND enabled=0;`,

	// v17: clean up phantom ARP records.
	//
	// /proc/net/arp records 00:00:00:00:00:00 against an IP whose ARP
	// resolution is still in progress. Older versions of parseARP wrote
	// those into the devices table, where they later collided with the
	// real device's IP in the Traffic page's client-name lookup — the
	// ghost row clobbered the legitimate row in the IP-to-name map,
	// making aliased/hosted devices show up as bare IPs.
	//
	// parseARP now filters these at write-time. This migration removes
	// any that previous installs left behind. Cascades through
	// device_presets via the existing FK.
	`DELETE FROM devices WHERE mac_address = '00:00:00:00:00:00';`,

	// v18: refine system filters per operator review.
	//
	// 1. YouTube: expand from the original 5-domain set to the 13 domains the
	//    Tesla actually needs for in-car playback — the Google account login
	//    chain (accounts.google.com, gds), the BG region account branch, the
	//    font CDNs, the Google static + main pages YouTube depends on, plus
	//    the Tesla-specific UI path (youtube-ui.l.google.com). New rows are
	//    enabled=1 because they are operator-curated seed contents (the
	//    review-then-enable safety pattern only applies to UI-added rows).
	//
	// 2. Tesla AP/Nav: drop maps.googleapis.com. It migrates to the new Maps
	//    & Time filter so the operator can decouple "vehicle is on" from
	//    "vehicle has map data."
	//
	// 3. New filter Maps & Time: map tiles + geocoding + NTP. Enabled=1 by
	//    default — without it the Tesla loses nav, so the safer migration
	//    target is "nav still works as before, just under a different name."
	//    Operator can disable on /filters if they want a stricter posture.
	`INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'accounts.google.bg',           'BG branch of accounts.google.com', 1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'accounts.google.com',     'login',                            1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'fonts.googleapis.com',    'fonts',                            1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'fonts.gstatic.com',       'fonts',                            1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'gds.google.com',          'OAuth2 login',                     1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'www.google.com',          'needed for youtube to play videos',1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'www.gstatic.com',         'static content',                   1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'youtube-ui.l.google.com', 'used by Tesla',                    1 FROM filters f WHERE f.name='YouTube';

	DELETE FROM filter_domains
	WHERE domain='maps.googleapis.com'
	  AND preset_id IN (SELECT id FROM filters WHERE name='Tesla AP/Nav');

	INSERT OR IGNORE INTO filters (name, description, is_system, enabled) VALUES
		('Maps & Time', 'Map tiles + geocoding + NTP time-sync. Required for in-car nav and time accuracy on the Tesla.', 1, 1);

	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'mt.l.google.com',       'Map Tiles',      1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'tile.googleapis.com',   'Map Tiles',      1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'maps.googleapis.com',   'Maps',           1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'places.googleapis.com', 'Search in Maps', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'pool.ntp.org',          'Time Sync',      1 FROM filters f WHERE f.name='Maps & Time';`,

	// v19: refresh system filters from a live production audit on the Tesla.
	//
	// 1. Maps & Time picks up Google's internal map-tile pool (mt0..mt3)
	//    and the Terrain Maps endpoint (www.googleapis.com). mt.l.google.com
	//    serves part of the load but the car rotates across mt0..mt3 as
	//    well, and intermittent gaps in nav tiles trace back to those
	//    being sinkholed.
	//
	// 2. YouTube picks up two domains the operator surfaced from the
	//    SNI-DROP log during use:
	//      - lh3.googleusercontent.com: the avatar/preview chip CDN
	//        (enabled — purely image content from Google's user CDN).
	//      - oauth2.googleapis.com: the OAuth 2.0 token endpoint used by
	//        YT Music sign-in. SEEDED DISABLED — toggle it on only during
	//        sign-in, off after. (This is plain HTTPS through the SNI
	//        proxy, NOT a port-hole; no firewall changes needed.)
	//
	// 3. Twitch: brand-new system filter. CDN host set curated from a
	//    live in-car streaming session.
	//
	// 4. Disney+: dropped. Unused in practice; removes one source of
	//    confusion in the UI. The filter_domains cascade clears its
	//    domain rows; the filters row itself is then deleted.
	`-- Maps & Time additions (idempotent — IGNORE if a row exists)
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'mt0.google.com',     'internal Map Tile service', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'mt1.google.com',     'internal Map Tile Service', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'mt2.google.com',     'internal Map Tile Service', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'mt3.google.com',     'internal Map Tile Service', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'www.googleapis.com', 'Terrain Maps',              1 FROM filters f WHERE f.name='Maps & Time';

	-- YouTube additions. oauth2.googleapis.com seeded DISABLED so it's a
	-- deliberate flip-on-during-pairing toggle, not an always-on hole.
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'lh3.googleusercontent.com', 'google cdn',    1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'oauth2.googleapis.com',     'YT Music auth', 0 FROM filters f WHERE f.name='YouTube';

	-- Twitch: new system filter + curated CDN domain set.
	--
	-- INSERT OR IGNORE is a no-op on installs where the operator already
	-- created a 'Twitch' filter manually in the UI (it would be is_system=0
	-- in that case). The UPDATE below promotes it to is_system=1 and
	-- replaces the description with the curated one, so both fresh
	-- installs and pre-existing user-created Twitch filters converge.
	INSERT OR IGNORE INTO filters (name, description, is_system, enabled) VALUES
		('Twitch', 'Twitch live-streaming via the in-car browser. CDN host set curated from a live session — twitch.tv plus the live-video/ttvnw/jtvnw CDNs and Fastly edge.', 1, 1);
	UPDATE filters SET
		is_system = 1,
		description = 'Twitch live-streaming via the in-car browser. CDN host set curated from a live session — twitch.tv plus the live-video/ttvnw/jtvnw CDNs and Fastly edge.'
	WHERE name = 'Twitch';

	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'ext-twitch.tv',         'interactive twitch extensions isolated from main site', 1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'jtvw.net',              'cdn',                     1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'live-video.net',        'cdn',                     1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'static-cdn.jtvnw.net',  'cdn',                     1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'ttvnw.net',             'twitch per user service', 1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'ttvw.net',              'cdn',                     1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'twitch.map.fastly.net', 'twitch service',          1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'twitch.tv',             'main twitch endpoint',    1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'twitchcdn.net',         'cdn',                     1 FROM filters f WHERE f.name='Twitch';

	-- Drop Disney+. filter_domains first (FK), then the filter row itself.
	DELETE FROM filter_domains WHERE preset_id IN (SELECT id FROM filters WHERE name='Disney+');
	DELETE FROM filters WHERE name='Disney+';`,
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
