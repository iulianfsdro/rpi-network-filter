package services

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/iulianfsdro/rpi-network-filter/internal/database"
)

// migratedDB returns a fresh in-memory SQLite DB with all migrations
// applied — exercises the v12 FTS5/trigram + v13 muted_domains schema.
func migratedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestQueryPaginatedFTSSearch(t *testing.T) {
	svc := NewTrafficLogService(migratedDB(t))

	for _, d := range []string{
		"www.youtube.com",
		"hermes-prd.ap.tesla.services",
		"auth.tesla.com",
	} {
		svc.insertEntry(TrafficEntry{Domain: d, Action: "query", Source: "dns"})
	}

	// Substring match on a single domain.
	if r := svc.QueryPaginated(TrafficFilter{Query: "youtube"}); r.Total != 1 ||
		len(r.Entries) != 1 || r.Entries[0].Domain != "www.youtube.com" {
		t.Fatalf("search 'youtube': total=%d entries=%d", r.Total, len(r.Entries))
	}

	// Mid-string substring spanning two rows (the FTS5 trigram win).
	if r := svc.QueryPaginated(TrafficFilter{Query: "tesla"}); r.Total != 2 {
		t.Fatalf("search 'tesla': total=%d, want 2", r.Total)
	}

	// Sub-3-char query takes the LIKE fallback (trigram needs 3-grams).
	if r := svc.QueryPaginated(TrafficFilter{Query: "yo"}); r.Total != 1 {
		t.Fatalf("search 'yo' (LIKE fallback): total=%d, want 1", r.Total)
	}
}

func TestMuteDropsAtIngest(t *testing.T) {
	svc := NewTrafficLogService(migratedDB(t))

	if _, err := svc.AddMuted("tesla.services"); err != nil {
		t.Fatalf("AddMuted: %v", err)
	}
	if !svc.isMuted("hermes-prd.ap.tesla.services") {
		t.Fatal("isMuted should match a deeper subdomain of a suffix pattern")
	}

	svc.insertEntry(TrafficEntry{Domain: "hermes-prd.ap.tesla.services", Action: "query", Source: "dns"})
	svc.insertEntry(TrafficEntry{Domain: "www.youtube.com", Action: "query", Source: "dns"})

	// The muted domain's event was dropped; the other was kept.
	if r := svc.QueryPaginated(TrafficFilter{Query: "tesla"}); r.Total != 0 {
		t.Fatalf("muted domain should not be logged: total=%d", r.Total)
	}
	if r := svc.QueryPaginated(TrafficFilter{Query: "youtube"}); r.Total != 1 {
		t.Fatalf("unmuted domain should be logged: total=%d", r.Total)
	}

	// Unmuting resumes logging.
	var id int64
	if err := svc.db.QueryRow("SELECT id FROM muted_domains LIMIT 1").Scan(&id); err != nil {
		t.Fatalf("read mute id: %v", err)
	}
	if err := svc.RemoveMuted(id); err != nil {
		t.Fatalf("RemoveMuted: %v", err)
	}
	svc.insertEntry(TrafficEntry{Domain: "hermes-prd.ap.tesla.services", Action: "query", Source: "dns"})
	if r := svc.QueryPaginated(TrafficFilter{Query: "tesla"}); r.Total != 1 {
		t.Fatalf("after unmute the event should be logged: total=%d", r.Total)
	}
}
