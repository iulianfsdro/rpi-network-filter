package services

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

// BlockedService manages the denylist of domains that must never be
// reachable — even via the allow-list. It is used as a guard before
// inserting into allowed_domains and as a DNS sinkhole source.
type BlockedService struct {
	db *sql.DB
}

func NewBlockedService(db *sql.DB) *BlockedService {
	return &BlockedService{db: db}
}

// NormalizeDomain lowercases, trims whitespace, and strips a leading "*."
// wildcard — "*.tesla.com" becomes "tesla.com". Matching is suffix-based
// by default so the root form matches subdomains too.
func NormalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	return d
}

// ErrDomainBlocked is returned by the allow-list create path when the
// requested domain collides with a blocked_domains entry.
var ErrDomainBlocked = errors.New("domain is on the block list")

// BlockMatch is a matched block rule returned by IsBlocked.
type BlockMatch struct {
	Domain    string
	MatchType string
	Reason    string
}

func (s *BlockedService) List() ([]models.BlockedDomain, error) {
	rows, err := s.db.Query(`
		SELECT id, domain, match_type, reason, enabled, created_at
		FROM blocked_domains ORDER BY domain ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query blocked domains: %w", err)
	}
	defer rows.Close()

	var out []models.BlockedDomain
	for rows.Next() {
		var d models.BlockedDomain
		var enabled int
		if err := rows.Scan(&d.ID, &d.Domain, &d.MatchType, &d.Reason, &enabled, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan blocked domain: %w", err)
		}
		d.Enabled = enabled == 1
		out = append(out, d)
	}
	return out, nil
}

func (s *BlockedService) Create(d models.BlockedDomain) (int64, error) {
	domain := NormalizeDomain(d.Domain)
	if domain == "" {
		return 0, errors.New("domain is required")
	}
	matchType := d.MatchType
	if matchType == "" {
		matchType = "suffix"
	}
	if matchType != "exact" && matchType != "suffix" {
		return 0, errors.New("match_type must be 'exact' or 'suffix'")
	}
	enabled := 1
	if !d.Enabled {
		enabled = 0
	}

	res, err := s.db.Exec(
		"INSERT INTO blocked_domains (domain, match_type, reason, enabled) VALUES (?, ?, ?, ?)",
		domain, matchType, d.Reason, enabled,
	)
	if err != nil {
		return 0, fmt.Errorf("insert blocked domain: %w", err)
	}
	return res.LastInsertId()
}

func (s *BlockedService) Update(id int64, d models.BlockedDomain) error {
	matchType := d.MatchType
	if matchType != "exact" && matchType != "suffix" {
		matchType = "suffix"
	}
	enabled := 1
	if !d.Enabled {
		enabled = 0
	}
	_, err := s.db.Exec(
		"UPDATE blocked_domains SET match_type=?, reason=?, enabled=? WHERE id=?",
		matchType, d.Reason, enabled, id,
	)
	if err != nil {
		return fmt.Errorf("update blocked domain %d: %w", id, err)
	}
	return nil
}

func (s *BlockedService) Delete(id int64) error {
	_, err := s.db.Exec("DELETE FROM blocked_domains WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete blocked domain %d: %w", id, err)
	}
	return nil
}

// IsBlocked reports whether the given domain is on the block list. For
// match_type='suffix' entries, it matches the exact domain and any deeper
// subdomain ("tesla-cdn.com" matches "cdn1.tesla-cdn.com"). For 'exact',
// only the exact string matches.
func (s *BlockedService) IsBlocked(domain string) (*BlockMatch, error) {
	candidate := NormalizeDomain(domain)
	if candidate == "" {
		return nil, nil
	}

	rows, err := s.db.Query(
		"SELECT domain, match_type, reason FROM blocked_domains WHERE enabled = 1",
	)
	if err != nil {
		return nil, fmt.Errorf("query block list: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var m BlockMatch
		if err := rows.Scan(&m.Domain, &m.MatchType, &m.Reason); err != nil {
			return nil, fmt.Errorf("scan block match: %w", err)
		}
		blocked := NormalizeDomain(m.Domain)
		if blocked == "" {
			continue
		}
		switch m.MatchType {
		case "exact":
			if candidate == blocked {
				return &m, nil
			}
		default: // suffix
			if candidate == blocked || strings.HasSuffix(candidate, "."+blocked) {
				return &m, nil
			}
		}
	}
	return nil, nil
}

// EnabledDomains returns every enabled block entry's normalized domain
// along with its match_type. Used by the DNS service to emit dnsmasq
// address=/.../0.0.0.0 directives so resolution fails entirely.
func (s *BlockedService) EnabledDomains() ([]models.BlockedDomain, error) {
	rows, err := s.db.Query(`
		SELECT id, domain, match_type, reason, enabled, created_at
		FROM blocked_domains WHERE enabled = 1 ORDER BY domain ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query enabled blocked domains: %w", err)
	}
	defer rows.Close()

	var out []models.BlockedDomain
	for rows.Next() {
		var d models.BlockedDomain
		var enabled int
		if err := rows.Scan(&d.ID, &d.Domain, &d.MatchType, &d.Reason, &enabled, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan enabled blocked domain: %w", err)
		}
		d.Enabled = enabled == 1
		out = append(out, d)
	}
	return out, nil
}
