package services

import (
	"database/sql"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/database"
	_ "modernc.org/sqlite"
)

// memDB returns a migrated in-memory SQLite DB pinned to a single
// connection (so the :memory: database persists across pool checkouts).
func memDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// filterID looks up a (system) filter's id by name.
func filterID(t *testing.T, db *sql.DB, name string) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRow("SELECT id FROM filters WHERE name = ?", name).Scan(&id); err != nil {
		t.Fatalf("filter %q id: %v", name, err)
	}
	return id
}

// freshFilter creates a brand-new (non-system) filter with an empty domain
// list and returns its id. The filter is created with enabled=1 so the
// AllEnabledDomains queries see its contents — flip it off in the test
// when the un-applied case is what's being asserted.
func freshFilter(t *testing.T, db *sql.DB, name string) int64 {
	t.Helper()
	res, err := db.Exec(
		"INSERT INTO filters (name, description, is_system, enabled) VALUES (?, '', 0, 1)", name,
	)
	if err != nil {
		t.Fatalf("create filter %q: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("filter %q id: %v", name, err)
	}
	return id
}

// mustExec runs a statement, failing the test on error.
func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}
