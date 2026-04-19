package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

var (
	ErrPolicyNotFound    = errors.New("policy not found")
	ErrDefaultPolicyLock = errors.New("the default policy cannot be deleted or have its is_default flag cleared")
)

func validMode(m string) bool {
	return m == "permissive" || m == "strict" || m == "open"
}

// PolicyService owns CRUD over policies, per-policy allow lists, and
// device→policy assignments. The FirewallService reads from this service
// when generating nftables rules; it does not write back.
type PolicyService struct {
	db      *sql.DB
	blocked *BlockedService
}

func NewPolicyService(db *sql.DB, blocked *BlockedService) *PolicyService {
	return &PolicyService{db: db, blocked: blocked}
}

// ── Policies ───────────────────────────────────────────────────

func (s *PolicyService) List() ([]models.Policy, error) {
	rows, err := s.db.Query(`
		SELECT id, name, mode, description, is_default, created_at
		FROM policies ORDER BY is_default DESC, name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var out []models.Policy
	for rows.Next() {
		var p models.Policy
		var def int
		if err := rows.Scan(&p.ID, &p.Name, &p.Mode, &p.Description, &def, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		p.IsDefault = def == 1
		out = append(out, p)
	}
	return out, nil
}

func (s *PolicyService) Get(id int64) (models.Policy, error) {
	var p models.Policy
	var def int
	err := s.db.QueryRow(`
		SELECT id, name, mode, description, is_default, created_at
		FROM policies WHERE id = ?
	`, id).Scan(&p.ID, &p.Name, &p.Mode, &p.Description, &def, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrPolicyNotFound
	}
	if err != nil {
		return p, fmt.Errorf("get policy %d: %w", id, err)
	}
	p.IsDefault = def == 1
	return p, nil
}

// Default returns the policy currently marked as default.
func (s *PolicyService) Default() (models.Policy, error) {
	var p models.Policy
	var def int
	err := s.db.QueryRow(`
		SELECT id, name, mode, description, is_default, created_at
		FROM policies WHERE is_default = 1 LIMIT 1
	`).Scan(&p.ID, &p.Name, &p.Mode, &p.Description, &def, &p.CreatedAt)
	if err != nil {
		return p, fmt.Errorf("default policy: %w", err)
	}
	p.IsDefault = def == 1
	return p, nil
}

func (s *PolicyService) Create(p models.Policy) (int64, error) {
	p.Name = strings.TrimSpace(p.Name)
	if !ValidPolicyName(p.Name) {
		return 0, fmt.Errorf("invalid policy name: must be 1-64 chars, letters/digits/space/_/- only (start alphanumeric)")
	}
	if !validMode(p.Mode) {
		p.Mode = "permissive"
	}
	// New policies never assume the default flag — transfer happens via SetDefault.
	res, err := s.db.Exec(`
		INSERT INTO policies (name, mode, description, is_default)
		VALUES (?, ?, ?, 0)
	`, p.Name, p.Mode, p.Description)
	if err != nil {
		return 0, fmt.Errorf("insert policy: %w", err)
	}
	return res.LastInsertId()
}

func (s *PolicyService) Update(id int64, p models.Policy) error {
	p.Name = strings.TrimSpace(p.Name)
	if !ValidPolicyName(p.Name) {
		return fmt.Errorf("invalid policy name: must be 1-64 chars, letters/digits/space/_/- only (start alphanumeric)")
	}
	if !validMode(p.Mode) {
		return fmt.Errorf("invalid mode %q", p.Mode)
	}
	_, err := s.db.Exec(`
		UPDATE policies SET name=?, mode=?, description=? WHERE id=?
	`, p.Name, p.Mode, p.Description, id)
	if err != nil {
		return fmt.Errorf("update policy %d: %w", id, err)
	}
	return nil
}

func (s *PolicyService) Delete(id int64) error {
	// Guard the default policy — losing it would orphan unassigned devices.
	var def int
	if err := s.db.QueryRow("SELECT is_default FROM policies WHERE id = ?", id).Scan(&def); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPolicyNotFound
		}
		return err
	}
	if def == 1 {
		return ErrDefaultPolicyLock
	}
	_, err := s.db.Exec("DELETE FROM policies WHERE id = ?", id)
	return err
}

// ── Per-policy allow list ──────────────────────────────────────

func (s *PolicyService) ListDomains(policyID int64) ([]models.PolicyDomain, error) {
	rows, err := s.db.Query(`
		SELECT id, policy_id, domain, description, enabled,
		       resolved_ips, last_resolved_at, hit_count, created_at
		FROM policy_allowed_domains
		WHERE policy_id = ?
		ORDER BY domain ASC
	`, policyID)
	if err != nil {
		return nil, fmt.Errorf("list policy domains: %w", err)
	}
	defer rows.Close()

	var out []models.PolicyDomain
	for rows.Next() {
		var d models.PolicyDomain
		var enabled int
		if err := rows.Scan(&d.ID, &d.PolicyID, &d.Domain, &d.Description, &enabled,
			&d.ResolvedIPs, &d.LastResolvedAt, &d.HitCount, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan policy domain: %w", err)
		}
		d.Enabled = enabled == 1
		out = append(out, d)
	}
	return out, nil
}

func (s *PolicyService) CreateDomain(policyID int64, d models.PolicyDomain) (int64, error) {
	domain := NormalizeDomain(d.Domain)
	if domain == "" {
		return 0, fmt.Errorf("domain is required")
	}
	if s.blocked != nil {
		match, err := s.blocked.IsBlocked(domain)
		if err != nil {
			return 0, fmt.Errorf("check block list: %w", err)
		}
		if match != nil {
			return 0, fmt.Errorf("%w: %q matches rule %q (%s)",
				ErrDomainBlocked, domain, match.Domain, match.Reason)
		}
	}
	enabled := 0
	if d.Enabled {
		enabled = 1
	}
	var id int64
	err := s.db.QueryRow(`
		INSERT INTO policy_allowed_domains (policy_id, domain, description, enabled)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(policy_id, domain) DO UPDATE SET
			description = CASE WHEN excluded.description != '' THEN excluded.description ELSE policy_allowed_domains.description END,
			enabled     = excluded.enabled
		RETURNING id
	`, policyID, domain, d.Description, enabled).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upsert policy domain: %w", err)
	}
	return id, nil
}

func (s *PolicyService) UpdateDomain(id int64, d models.PolicyDomain) error {
	enabled := 0
	if d.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(`
		UPDATE policy_allowed_domains
		SET description = ?, enabled = ?
		WHERE id = ?
	`, d.Description, enabled, id)
	return err
}

func (s *PolicyService) DeleteDomain(id int64) error {
	_, err := s.db.Exec("DELETE FROM policy_allowed_domains WHERE id = ?", id)
	return err
}

// ResolveDomain queries the local dnsmasq (via /etc/resolv.conf) for `domain`
// so that dnsmasq's nftset= directive populates the matching nft set before
// the first client tries to connect. Addresses v1's "allowed but still
// blocked" race where the set was empty until a client's own DNS query
// fired. Should be called AFTER FirewallService.Apply has reloaded dnsmasq
// with the new nftset= line for this domain. Safe to call in a goroutine.
//
// Also writes the resolved IPs + timestamp back to the row so the UI can
// show "last resolved X.X.X.X at <time>".
func (s *PolicyService) ResolveDomain(domain string) {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{PreferGo: true}
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		log.Printf("[POLICY] proactive resolve %s: %v", domain, err)
		return
	}
	log.Printf("[POLICY] proactive resolve %s -> %v", domain, ips)

	payload, _ := json.Marshal(ips)
	if _, err := s.db.Exec(`
		UPDATE policy_allowed_domains
		SET resolved_ips = ?, last_resolved_at = CURRENT_TIMESTAMP
		WHERE domain = ?
	`, string(payload), domain); err != nil {
		log.Printf("[POLICY] write resolved_ips for %s: %v", domain, err)
	}
}

// RefreshAll iterates every enabled (policy × domain) row and issues a DNS
// query through the local dnsmasq so the per-policy nft sets stay populated
// between natural client queries. Called by the periodic re-resolve cron.
func (s *PolicyService) RefreshAll() {
	rows, err := s.db.Query(`
		SELECT DISTINCT domain FROM policy_allowed_domains WHERE enabled = 1
	`)
	if err != nil {
		log.Printf("[POLICY] refresh: list domains: %v", err)
		return
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			log.Printf("[POLICY] refresh scan: %v", err)
			continue
		}
		domains = append(domains, d)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[POLICY] refresh iterate: %v", err)
	}
	log.Printf("[POLICY] refresh: re-resolving %d domains", len(domains))
	for _, d := range domains {
		s.ResolveDomain(d)
	}
}

// StartRefreshLoop kicks off a background goroutine that calls RefreshAll
// every `interval`. The returned cancel function stops the loop; callers
// pass it to the process shutdown hook.
func (s *PolicyService) StartRefreshLoop(interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// First refresh happens 30s after boot so dnsmasq has finished starting.
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				s.RefreshAll()
				timer.Reset(interval)
			}
		}
	}()
	return cancel
}

// ── Device assignments ─────────────────────────────────────────

func (s *PolicyService) AssignDevice(mac string, policyID int64) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" {
		return fmt.Errorf("mac is required")
	}
	_, err := s.db.Exec(`
		INSERT INTO device_policies (device_mac, policy_id)
		VALUES (?, ?)
		ON CONFLICT(device_mac) DO UPDATE SET policy_id = excluded.policy_id
	`, mac, policyID)
	return err
}

func (s *PolicyService) UnassignDevice(mac string) error {
	_, err := s.db.Exec("DELETE FROM device_policies WHERE device_mac = ?", strings.ToLower(mac))
	return err
}

func (s *PolicyService) ListAssignments() ([]models.DevicePolicy, error) {
	rows, err := s.db.Query(`
		SELECT dp.device_mac, dp.policy_id, p.name, dp.assigned_at
		FROM device_policies dp
		JOIN policies p ON p.id = dp.policy_id
		ORDER BY dp.device_mac ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list device-policy assignments: %w", err)
	}
	defer rows.Close()

	var out []models.DevicePolicy
	for rows.Next() {
		var a models.DevicePolicy
		if err := rows.Scan(&a.DeviceMAC, &a.PolicyID, &a.PolicyName, &a.AssignedAt); err != nil {
			return nil, fmt.Errorf("scan assignment: %w", err)
		}
		out = append(out, a)
	}
	return out, nil
}

// DevicePolicy returns the effective policy for a MAC. A MAC with no row in
// device_policies resolves to the default policy.
func (s *PolicyService) DevicePolicy(mac string) (models.Policy, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	var p models.Policy
	var def int
	err := s.db.QueryRow(`
		SELECT p.id, p.name, p.mode, p.description, p.is_default, p.created_at
		FROM device_policies dp
		JOIN policies p ON p.id = dp.policy_id
		WHERE dp.device_mac = ?
	`, mac).Scan(&p.ID, &p.Name, &p.Mode, &p.Description, &def, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return s.Default()
	}
	if err != nil {
		return p, fmt.Errorf("device policy lookup: %w", err)
	}
	p.IsDefault = def == 1
	return p, nil
}
