package services

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

var (
	ErrFilterNotFound = errors.New("filter not found")
	ErrSystemFilter   = errors.New("system filters cannot be deleted")
	ErrDescRequired   = errors.New("description is required — justify every allow-list entry")
)

// FilterService owns CRUD over the filter model: filters (the curated
// bundles), per-filter domain allow-lists, and the per-filter enable
// toggle. A filter with enabled=1 applies to EVERY device with
// status='filtered' — there are no per-device attachments. The SNI proxy
// reads from this service to build its global allow-list cache; the
// firewall service reads device status (via NetworkService) to classify
// forward traffic.
type FilterService struct {
	db *sql.DB
}

func NewFilterService(db *sql.DB) *FilterService {
	return &FilterService{db: db}
}

// ── Filters ────────────────────────────────────────────────────

func (s *FilterService) List() ([]models.Filter, error) {
	rows, err := s.db.Query(`
		SELECT id, name, description, is_system, enabled, created_at
		FROM filters ORDER BY is_system DESC, name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list filters: %w", err)
	}
	defer rows.Close()

	var out []models.Filter
	for rows.Next() {
		var f models.Filter
		var sys, en int
		if err := rows.Scan(&f.ID, &f.Name, &f.Description, &sys, &en, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan filter: %w", err)
		}
		f.IsSystem = sys == 1
		f.Enabled = en == 1
		out = append(out, f)
	}
	return out, nil
}

func (s *FilterService) Get(id int64) (models.Filter, error) {
	var f models.Filter
	var sys, en int
	err := s.db.QueryRow(`
		SELECT id, name, description, is_system, enabled, created_at
		FROM filters WHERE id = ?
	`, id).Scan(&f.ID, &f.Name, &f.Description, &sys, &en, &f.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrFilterNotFound
	}
	if err != nil {
		return f, fmt.Errorf("get filter %d: %w", id, err)
	}
	f.IsSystem = sys == 1
	f.Enabled = en == 1
	return f, nil
}

func (s *FilterService) Create(f models.Filter) (int64, error) {
	f.Name = strings.TrimSpace(f.Name)
	if !ValidPresetName(f.Name) {
		return 0, fmt.Errorf("invalid filter name: must be 1-64 chars, letters/digits/space/_/-/+/'/' only (start alphanumeric)")
	}
	// User-created filters are never system filters and start disabled
	// (the operator opts in by flipping the enable toggle).
	res, err := s.db.Exec(`
		INSERT INTO filters (name, description, is_system, enabled) VALUES (?, ?, 0, 0)
	`, f.Name, f.Description)
	if err != nil {
		return 0, fmt.Errorf("insert filter: %w", err)
	}
	return res.LastInsertId()
}

// Update edits the name and description. The Enabled flag has its own
// dedicated setter so a UI bug can't accidentally clear a live filter.
func (s *FilterService) Update(id int64, f models.Filter) error {
	f.Name = strings.TrimSpace(f.Name)
	if !ValidPresetName(f.Name) {
		return fmt.Errorf("invalid filter name")
	}
	_, err := s.db.Exec(`UPDATE filters SET name=?, description=? WHERE id=?`, f.Name, f.Description, id)
	if err != nil {
		return fmt.Errorf("update filter %d: %w", id, err)
	}
	return nil
}

// SetEnabled flips the global enable flag — when true, every domain in
// this filter applies to all filtered devices.
func (s *FilterService) SetEnabled(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	res, err := s.db.Exec(`UPDATE filters SET enabled=? WHERE id=?`, v, id)
	if err != nil {
		return fmt.Errorf("set enabled on filter %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrFilterNotFound
	}
	return nil
}

func (s *FilterService) Delete(id int64) error {
	// Guard system filters — removing seeded Tesla AP/Nav by accident
	// would silently break the curated set. System filters can be edited
	// or extended but not deleted.
	var sys int
	if err := s.db.QueryRow("SELECT is_system FROM filters WHERE id = ?", id).Scan(&sys); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFilterNotFound
		}
		return err
	}
	if sys == 1 {
		return ErrSystemFilter
	}
	_, err := s.db.Exec("DELETE FROM filters WHERE id = ?", id)
	return err
}

// ── Per-filter domain list ─────────────────────────────────────

func (s *FilterService) ListDomains(filterID int64) ([]models.FilterDomain, error) {
	rows, err := s.db.Query(`
		SELECT id, preset_id, domain, description, enabled,
		       resolved_ips, last_resolved_at, hit_count, created_at
		FROM filter_domains
		WHERE preset_id = ?
		ORDER BY domain ASC
	`, filterID)
	if err != nil {
		return nil, fmt.Errorf("list filter domains: %w", err)
	}
	defer rows.Close()

	var out []models.FilterDomain
	for rows.Next() {
		var d models.FilterDomain
		var enabled int
		if err := rows.Scan(&d.ID, &d.FilterID, &d.Domain, &d.Description, &enabled,
			&d.ResolvedIPs, &d.LastResolvedAt, &d.HitCount, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan filter domain: %w", err)
		}
		d.Enabled = enabled == 1
		out = append(out, d)
	}
	return out, nil
}

// CreateDomain inserts a domain into a filter. Every entry is required
// to carry a non-empty description — the operator must justify every
// allow-list addition. New rows are inserted DISABLED (review-then-
// enable). The protected-deny floor rejects known-bad Tesla endpoints
// and broad parents that would re-admit one. An upsert onto an existing
// row overwrites the description but leaves the enabled flag alone.
func (s *FilterService) CreateDomain(filterID int64, d models.FilterDomain) (int64, error) {
	domain := NormalizeDomain(d.Domain)
	if domain == "" {
		return 0, fmt.Errorf("domain is required")
	}
	desc := strings.TrimSpace(d.Description)
	if desc == "" {
		return 0, ErrDescRequired
	}
	if isProtectedDenied(domain) {
		return 0, fmt.Errorf("%q is a protected Tesla endpoint and cannot be allow-listed", domain)
	}
	if isProtectedAncestor(domain) {
		return 0, fmt.Errorf("%q is too broad — it would admit a protected Tesla endpoint; allow the specific sub-domain instead", domain)
	}
	var id int64
	err := s.db.QueryRow(`
		INSERT INTO filter_domains (preset_id, domain, description, enabled)
		VALUES (?, ?, ?, 0)
		ON CONFLICT(preset_id, domain) DO UPDATE SET
			description = excluded.description
		RETURNING id
	`, filterID, domain, desc).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upsert filter domain: %w", err)
	}
	return id, nil
}

func (s *FilterService) UpdateDomain(id int64, d models.FilterDomain) error {
	if strings.TrimSpace(d.Description) == "" {
		return ErrDescRequired
	}
	enabled := 0
	if d.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(`
		UPDATE filter_domains
		SET description = ?, enabled = ?
		WHERE id = ?
	`, strings.TrimSpace(d.Description), enabled, id)
	return err
}

// SetDomainEnabled toggles a single domain on/off without forcing the
// caller to supply a description (used by the toggle in the UI).
func (s *FilterService) SetDomainEnabled(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE filter_domains SET enabled=? WHERE id=?`, v, id)
	return err
}

func (s *FilterService) DeleteDomain(id int64) error {
	_, err := s.db.Exec("DELETE FROM filter_domains WHERE id = ?", id)
	return err
}

// AllEnabledDomains returns the union of every enabled filter_domain
// across every filter whose own enabled flag is on. This is the global
// allow-list — every filtered device sees the same suffixes. The SNI
// proxy uses it for its cache; the DNS layer uses it to decide which
// hostnames get a server= line.
func (s *FilterService) AllEnabledDomains() ([]string, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT fd.domain
		FROM filter_domains fd
		JOIN filters f ON f.id = fd.preset_id
		WHERE fd.enabled = 1 AND f.enabled = 1
		ORDER BY fd.domain ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query enabled domains: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" && ValidDomain(d) {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}
