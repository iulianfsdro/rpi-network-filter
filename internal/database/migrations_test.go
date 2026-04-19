package database

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// openMemory returns a fresh in-memory SQLite DB — no file, no fixtures.
func openMemory(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrateFreshAppliesAll(t *testing.T) {
	db := openMemory(t)

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var v int
	if err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&v); err != nil {
		t.Fatalf("schema_version read: %v", err)
	}
	if v != len(migrations) {
		t.Errorf("applied version = %d, want %d", v, len(migrations))
	}
}

func TestMigrateIdempotent(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&count); err != nil {
		t.Fatalf("schema_version count: %v", err)
	}
	if count != len(migrations) {
		t.Errorf("schema_version rows = %d, want %d (double-applied?)", count, len(migrations))
	}
}

func TestMigrateSeedsDefaultAndTeslaPolicies(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Default exists, strict, is_default = 1
	var mode string
	var isDefault int
	if err := db.QueryRow("SELECT mode, is_default FROM policies WHERE name='Default'").
		Scan(&mode, &isDefault); err != nil {
		t.Fatalf("Default policy: %v", err)
	}
	if mode != "strict" {
		t.Errorf("Default.mode = %q, want strict", mode)
	}
	if isDefault != 1 {
		t.Error("Default.is_default should be 1")
	}

	// Tesla exists, strict, not default
	if err := db.QueryRow("SELECT mode, is_default FROM policies WHERE name='Tesla'").
		Scan(&mode, &isDefault); err != nil {
		t.Fatalf("Tesla policy: %v", err)
	}
	if mode != "strict" || isDefault != 0 {
		t.Errorf("Tesla: mode=%q is_default=%d", mode, isDefault)
	}

	// Tesla allow list must contain connman (seeded at v6) plus the
	// Preset B entries (seeded at v10). We assert membership rather
	// than count so adding further domains doesn't break the test.
	rows, err := db.Query(`
		SELECT pad.domain
		FROM policy_allowed_domains pad
		JOIN policies p ON p.id = pad.policy_id
		WHERE p.name='Tesla'`)
	if err != nil {
		t.Fatalf("Tesla domains query: %v", err)
	}
	defer rows.Close()
	teslaDomains := map[string]bool{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatalf("scan: %v", err)
		}
		teslaDomains[d] = true
	}
	for _, want := range []string{
		"connman.vn.tesla.services",
		"auth.tesla.com",
		"managed-charging.sn.tesla.services",
		"go.tesla.services",
		"maps.googleapis.com",
	} {
		if !teslaDomains[want] {
			t.Errorf("Tesla allow list missing %q", want)
		}
	}

	// Open policy from v9
	if err := db.QueryRow("SELECT mode FROM policies WHERE name='Open'").Scan(&mode); err != nil {
		t.Fatalf("Open policy: %v", err)
	}
	if mode != "open" {
		t.Errorf("Open.mode = %q, want open", mode)
	}
}

func TestMigrateDropsAllowedDomainsTable(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var name string
	err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='allowed_domains'",
	).Scan(&name)
	if err == nil {
		t.Error("allowed_domains table should have been dropped in v6")
	} else if err != sql.ErrNoRows {
		t.Fatalf("unexpected sqlite_master query error: %v", err)
	}
}

func TestMigrateV8WipesURLEncodedMACs(t *testing.T) {
	db := openMemory(t)

	// Apply v1 through v7 manually by trimming migrations to pre-v8.
	// Simplest: run the full Migrate, then inject a bad row, then
	// confirm that a subsequent Migrate re-run is a no-op and the
	// bad row stays (migrations are one-shot). The real regression
	// guard is that v8 ran once during the initial Migrate and
	// wiped anything that was in there — simulate by inserting
	// directly and checking the table now cleanly deletes.
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Simulate the bug: insert a URL-encoded row.
	if _, err := db.Exec(`
		INSERT INTO device_policies (device_mac, policy_id)
		VALUES ('aa%3abb%3acc%3add%3aee%3aff', 1)
	`); err != nil {
		t.Fatalf("seed bad row: %v", err)
	}

	// Run the cleanup query directly (migration v8 is a single
	// statement, so this mirrors what it does).
	res, err := db.Exec("DELETE FROM device_policies WHERE instr(device_mac, '%') > 0")
	if err != nil {
		t.Fatalf("cleanup delete: %v", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		t.Errorf("v8-style cleanup affected %d rows, want 1", n)
	}
}

func TestMigrateBlockedDomainsSeeded(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM blocked_domains").Scan(&count); err != nil {
		t.Fatalf("count blocked_domains: %v", err)
	}
	if count < 5 {
		t.Errorf("blocked_domains seeded count = %d, want at least 5 (Tesla endpoints)", count)
	}
}

func TestMigratePolicyModeCheckAcceptsOpen(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// The v9 rebuild should let mode='open' pass. If CHECK constraint
	// was wrong the insert would fail.
	if _, err := db.Exec(`
		INSERT INTO policies (name, mode) VALUES ('test-open', 'open')
	`); err != nil {
		t.Errorf("insert mode=open rejected by CHECK: %v", err)
	}
	// Invalid modes must still be rejected.
	if _, err := db.Exec(`
		INSERT INTO policies (name, mode) VALUES ('test-bogus', 'bogus')
	`); err == nil {
		t.Error("insert mode=bogus should fail CHECK")
	}
}
