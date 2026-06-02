package services

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

func domainEnabled(t *testing.T, db *sql.DB, id int64) bool {
	t.Helper()
	var e int
	if err := db.QueryRow("SELECT enabled FROM filter_domains WHERE id = ?", id).Scan(&e); err != nil {
		t.Fatalf("read enabled for domain %d: %v", id, err)
	}
	return e == 1
}

// TestCreateDomain_DisabledAndProtectedAndDescription verifies the four
// filter-domain safety behaviours: new domains are created disabled
// (review-then-enable), protected Tesla endpoints (and broad parents)
// are rejected outright, and an empty description is rejected — every
// allow-list entry needs a justification.
func TestCreateDomain_DisabledAndProtectedAndDescription(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	// A fresh filter — the seeded Tesla AP/Nav filter already ships
	// auth.tesla.com (we'd conflict if we used it).
	fID := freshFilter(t, db, "FilterTest")

	// 1. A new domain is created DISABLED, even if the request says enabled.
	id, err := fs.CreateDomain(fID, models.FilterDomain{
		Domain: "auth.tesla.com", Description: "test OAuth", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateDomain(auth.tesla.com): %v", err)
	}
	if domainEnabled(t, db, id) {
		t.Errorf("a newly added domain was enabled — it must default to disabled")
	}

	// 2. Re-adding an already-enabled domain must NOT flip it back off.
	mustExec(t, db, "UPDATE filter_domains SET enabled = 1 WHERE id = ?", id)
	if _, err := fs.CreateDomain(fID, models.FilterDomain{
		Domain: "auth.tesla.com", Description: "second take",
	}); err != nil {
		t.Fatalf("re-add CreateDomain: %v", err)
	}
	if !domainEnabled(t, db, id) {
		t.Errorf("re-adding a domain disabled a live entry — enabled must be left untouched")
	}

	// 3. Protected Tesla endpoints are rejected — a misclick never lands.
	for _, bad := range []string{
		"hermes-prd.ap.tesla.services",
		"hermes-api.prd.eu.vn.cloud.tesla.com", // EU variant
		"tesla.services",                       // catastrophically broad
	} {
		if _, err := fs.CreateDomain(fID, models.FilterDomain{
			Domain: bad, Description: "should never land",
		}); err == nil {
			t.Errorf("CreateDomain accepted a protected/dangerous domain %q — must reject", bad)
		}
	}

	// 4. Empty / whitespace-only description is rejected.
	for _, desc := range []string{"", "   ", "\t\n"} {
		if _, err := fs.CreateDomain(fID, models.FilterDomain{
			Domain: "spotify.com", Description: desc,
		}); !errors.Is(err, ErrDescRequired) {
			t.Errorf("CreateDomain with description=%q returned %v, want ErrDescRequired", desc, err)
		}
	}
}

// TestSystemFilterCannotBeDeleted — the seeded Tesla AP/Nav (and the
// other system filters) must not be removable via the API. They can
// still be edited or extended.
func TestSystemFilterCannotBeDeleted(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	id := filterID(t, db, "Tesla AP/Nav")
	if err := fs.Delete(id); !errors.Is(err, ErrSystemFilter) {
		t.Errorf("Delete(Tesla AP/Nav) = %v, want ErrSystemFilter", err)
	}
}

// TestFilterEnabledToggleAffectsAllowedDomains — flipping a filter's
// enabled flag changes what the global allow-list returns, even though
// the underlying domain rows didn't change. This is the property the
// whole UX rework relies on.
func TestFilterEnabledToggleAffectsAllowedDomains(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	fID := freshFilter(t, db, "Streaming")

	// Add one domain and enable it.
	id, err := fs.CreateDomain(fID, models.FilterDomain{
		Domain: "stream.example.com", Description: "test",
	})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	mustExec(t, db, "UPDATE filter_domains SET enabled = 1 WHERE id = ?", id)

	// Filter off → domain is NOT in the global allow list.
	if err := fs.SetEnabled(fID, false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	got, _ := fs.AllEnabledDomains()
	for _, d := range got {
		if d == "stream.example.com" {
			t.Errorf("domain leaked into allow-list while filter is OFF: %v", got)
		}
	}

	// Filter on → domain IS in the global allow list.
	if err := fs.SetEnabled(fID, true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	got, _ = fs.AllEnabledDomains()
	found := false
	for _, d := range got {
		if d == "stream.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("enabled filter's domain missing from allow-list: %v", got)
	}
}
