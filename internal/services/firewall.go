package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

type FirewallService struct {
	db      *sql.DB
	exec    *executor.Executor
	cfg     config.Config
	blocked *BlockedService
	policy  *PolicyService
	mu      sync.Mutex
}

func NewFirewallService(db *sql.DB, exec *executor.Executor, cfg config.Config, blocked *BlockedService, policy *PolicyService) *FirewallService {
	return &FirewallService{db: db, exec: exec, cfg: cfg, blocked: blocked, policy: policy}
}

func (s *FirewallService) ListRules() ([]models.FirewallRule, error) {
	rows, err := s.db.Query(`
		SELECT id, description, direction, protocol, source_ip, dest_ip, dest_port,
			action, device_mac, enabled, priority, created_at
		FROM firewall_rules ORDER BY priority ASC, id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query firewall rules: %w", err)
	}
	defer rows.Close()

	var rules []models.FirewallRule
	for rows.Next() {
		var r models.FirewallRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Description, &r.Direction, &r.Protocol,
			&r.SourceIP, &r.DestIP, &r.DestPort, &r.Action, &r.DeviceMAC,
			&enabled, &r.Priority, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan firewall rule: %w", err)
		}
		r.Enabled = enabled == 1
		rules = append(rules, r)
	}
	return rules, nil
}

func (s *FirewallService) CreateRule(r models.FirewallRule) (int64, error) {
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	result, err := s.db.Exec(`
		INSERT INTO firewall_rules (description, direction, protocol, source_ip, dest_ip, dest_port, action, device_mac, enabled, priority)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, r.Description, r.Direction, r.Protocol, r.SourceIP, r.DestIP, r.DestPort, r.Action, r.DeviceMAC, enabled, r.Priority)
	if err != nil {
		return 0, fmt.Errorf("insert firewall rule: %w", err)
	}
	return result.LastInsertId()
}

func (s *FirewallService) UpdateRule(id int64, r models.FirewallRule) error {
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(`
		UPDATE firewall_rules SET description=?, direction=?, protocol=?, source_ip=?, dest_ip=?,
			dest_port=?, action=?, device_mac=?, enabled=?, priority=?
		WHERE id=?
	`, r.Description, r.Direction, r.Protocol, r.SourceIP, r.DestIP, r.DestPort, r.Action, r.DeviceMAC, enabled, r.Priority, id)
	if err != nil {
		return fmt.Errorf("update firewall rule %d: %w", id, err)
	}
	return nil
}

func (s *FirewallService) DeleteRule(id int64) error {
	_, err := s.db.Exec("DELETE FROM firewall_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete firewall rule %d: %w", id, err)
	}
	return nil
}

// ── Allowed Domains CRUD ───────────────────────────────────────
//
// v2: entries live in policy_allowed_domains, one row per (policy, domain).
// The legacy handlers (ListAllowedDomains / CreateAllowedDomain / …) operate
// on the `Default` policy so existing API clients keep working unchanged.
// The per-policy variants (ListPolicyDomains, etc.) are used by the new
// Policies page.

// defaultPolicyID returns the id of the built-in `Default` (permissive) policy.
func (s *FirewallService) defaultPolicyID() (int64, error) {
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM policies WHERE is_default = 1 LIMIT 1`).Scan(&id); err != nil {
		return 0, fmt.Errorf("lookup default policy: %w", err)
	}
	return id, nil
}

func (s *FirewallService) ListAllowedDomains() ([]models.AllowedDomain, error) {
	rows, err := s.db.Query(`
		SELECT pad.id, pad.domain, pad.description, pad.enabled, pad.created_at
		FROM policy_allowed_domains pad
		JOIN policies p ON p.id = pad.policy_id
		WHERE p.is_default = 1
		ORDER BY pad.domain ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query allowed domains: %w", err)
	}
	defer rows.Close()

	var domains []models.AllowedDomain
	for rows.Next() {
		var d models.AllowedDomain
		var enabled int
		if err := rows.Scan(&d.ID, &d.Domain, &d.Description, &enabled, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan allowed domain: %w", err)
		}
		d.Enabled = enabled == 1
		domains = append(domains, d)
	}
	return domains, nil
}

// CreateAllowedDomain inserts a new allow-list entry into the Default policy,
// or if the domain already exists there, re-enables it and returns the
// existing ID. Idempotent so the quick-allow button in the traffic monitor
// is safe to click twice.
func (s *FirewallService) CreateAllowedDomain(d models.AllowedDomain) (int64, error) {
	enabled := 0
	if d.Enabled {
		enabled = 1
	}
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

	policyID, err := s.defaultPolicyID()
	if err != nil {
		return 0, err
	}

	var id int64
	err = s.db.QueryRow(`
		INSERT INTO policy_allowed_domains (policy_id, domain, description, enabled)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(policy_id, domain) DO UPDATE SET
			description = CASE WHEN excluded.description != '' THEN excluded.description ELSE policy_allowed_domains.description END,
			enabled     = excluded.enabled
		RETURNING id
	`, policyID, domain, d.Description, enabled).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upsert allowed domain: %w", err)
	}
	return id, nil
}

func (s *FirewallService) UpdateAllowedDomain(id int64, d models.AllowedDomain) error {
	enabled := 0
	if d.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(
		"UPDATE policy_allowed_domains SET description=?, enabled=? WHERE id=?",
		d.Description, enabled, id,
	)
	return err
}

func (s *FirewallService) DeleteAllowedDomain(id int64) error {
	_, err := s.db.Exec("DELETE FROM policy_allowed_domains WHERE id = ?", id)
	return err
}

// ListActiveSetIPs returns the current IPs in a policy's nftables IP set.
// With no policy id it falls back to the Default policy for v1-style callers.
func (s *FirewallService) ListActiveSetIPs(policyID ...int64) []string {
	var id int64
	if len(policyID) > 0 && policyID[0] != 0 {
		id = policyID[0]
	} else {
		def, err := s.policy.Default()
		if err != nil {
			return nil
		}
		id = def.ID
	}
	result, err := s.exec.Run("nft", "-a", "list", "set", "inet", "filter", policySetName(id))
	if err != nil {
		return nil
	}

	// Parse output — looking for "elements = { 1.2.3.4, 5.6.7.8 }" or multiline format
	var ips []string
	lines := strings.Split(result.Stdout, "\n")
	inElements := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "elements = {") {
			inElements = true
			line = strings.TrimPrefix(line, "elements = {")
		}
		if inElements {
			line = strings.TrimSuffix(line, "}")
			parts := strings.Split(line, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				// IPs may have "expires Xs" suffix; take only the IP
				if idx := strings.Index(p, " "); idx > 0 {
					p = p[:idx]
				}
				if p != "" && strings.Contains(p, ".") {
					ips = append(ips, p)
				}
			}
			if strings.Contains(line, "}") {
				break
			}
		}
	}
	return ips
}

// policySnapshot bundles everything Apply needs to generate per-policy
// nftables chains in one atomic read of the DB state.
type policySnapshot struct {
	policies    []models.Policy
	domainsByID map[int64][]models.PolicyDomain
	assignments []models.DevicePolicy
	defaultID   int64
}

func (s *FirewallService) loadPolicySnapshot() (policySnapshot, error) {
	var snap policySnapshot
	policies, err := s.policy.List()
	if err != nil {
		return snap, fmt.Errorf("list policies: %w", err)
	}
	snap.policies = policies

	snap.domainsByID = make(map[int64][]models.PolicyDomain, len(policies))
	for _, p := range policies {
		if p.IsDefault {
			snap.defaultID = p.ID
		}
		ds, err := s.policy.ListDomains(p.ID)
		if err != nil {
			return snap, fmt.Errorf("list domains for policy %d: %w", p.ID, err)
		}
		snap.domainsByID[p.ID] = ds
	}

	assignments, err := s.policy.ListAssignments()
	if err != nil {
		return snap, fmt.Errorf("list device-policy assignments: %w", err)
	}
	snap.assignments = assignments
	return snap, nil
}

func (s *FirewallService) Apply() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rules, err := s.ListRules()
	if err != nil {
		return fmt.Errorf("list rules for apply: %w", err)
	}

	// Blocked devices (hard drop, regardless of policy)
	var blockedMACs []string
	rows, err := s.db.Query("SELECT mac_address FROM devices WHERE is_blocked = 1")
	if err != nil {
		return fmt.Errorf("query blocked devices: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var mac string
		rows.Scan(&mac)
		blockedMACs = append(blockedMACs, mac)
	}

	snap, err := s.loadPolicySnapshot()
	if err != nil {
		return err
	}

	conf := s.generateConfig(rules, blockedMACs, snap)

	if err := os.WriteFile("/etc/nftables.conf", []byte(conf), 0644); err != nil {
		if !s.exec.DryRun {
			return fmt.Errorf("write nftables.conf: %w", err)
		}
		log.Printf("[DRY-RUN] Would write /etc/nftables.conf (%d bytes)", len(conf))
	}

	if _, err := s.exec.Run("nft", "-f", "/etc/nftables.conf"); err != nil {
		return fmt.Errorf("reload nftables: %w", err)
	}

	// Write dnsmasq nftset config (one line per domain × policy)
	var totalDomains int
	for _, ds := range snap.domainsByID {
		totalDomains += len(ds)
	}
	if err := s.writeDnsmasqNftsets(snap); err != nil {
		log.Printf("[WARN] Failed to write dnsmasq nftsets: %v", err)
	} else {
		if _, err := s.exec.Run("systemctl", "reload", "dnsmasq"); err != nil {
			log.Printf("[WARN] Failed to reload dnsmasq: %v", err)
		}
	}

	log.Printf("[FIREWALL] Applied %d global rules, %d blocked devices, %d policies, %d domain-policy mappings, %d device assignments",
		len(rules), len(blockedMACs), len(snap.policies), totalDomains, len(snap.assignments))
	return nil
}

// writeDnsmasqNftsets generates /etc/dnsmasq.d/netfilter-nftsets.conf with
// one nftset= line per (enabled domain × policy). dnsmasq auto-adds resolved
// IPs to the correct policy-scoped nft set when clients query the domain.
// The same domain can belong to multiple policies; each mapping produces its
// own nftset= directive and both sets are populated on the same lookup.
func (s *FirewallService) writeDnsmasqNftsets(snap policySnapshot) error {
	var b strings.Builder
	b.WriteString("# Generated by netfilterd — do not edit\n")
	b.WriteString("# Maps DNS queries to per-policy nftables sets for dynamic allow-listing\n\n")

	count := 0
	for _, p := range snap.policies {
		for _, d := range snap.domainsByID[p.ID] {
			if !d.Enabled {
				continue
			}
			domain := strings.ToLower(strings.TrimSpace(d.Domain))
			if domain == "" {
				continue
			}
			fmt.Fprintf(&b, "nftset=/%s/inet#filter#%s\n", domain, policySetName(p.ID))
			count++
		}
	}

	path := "/etc/dnsmasq.d/netfilter-nftsets.conf"
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		if !s.exec.DryRun {
			return fmt.Errorf("write %s: %w", path, err)
		}
		log.Printf("[DRY-RUN] Would write %s (%d entries)", path, count)
	}
	return nil
}

func policySetName(policyID int64) string   { return fmt.Sprintf("pol_%d_ips", policyID) }
func policyChainName(policyID int64) string { return fmt.Sprintf("pol_%d_chain", policyID) }

func (s *FirewallService) generateConfig(rules []models.FirewallRule, blockedMACs []string, snap policySnapshot) string {
	var b strings.Builder

	b.WriteString("#!/usr/sbin/nft -f\n\n")
	b.WriteString("flush ruleset\n\n")

	// NAT table
	b.WriteString("table ip nat {\n")
	b.WriteString("    chain postrouting {\n")
	b.WriteString("        type nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&b, "        oifname \"%s\" masquerade\n", s.cfg.WANInterface)
	b.WriteString("    }\n")
	b.WriteString("}\n\n")

	// Filter table
	b.WriteString("table inet filter {\n")

	// One IP set per policy. 30-day timeout; a re-resolve cron refreshes
	// entries before they age out so long-idle connections don't break.
	// Sets are pre-populated from policy_allowed_domains.resolved_ips so
	// that `flush ruleset` + reload doesn't transiently empty every set
	// and strand long-lived TLS connections — also means deleting a
	// domain immediately removes its IPs (sync-flush-on-delete).
	for _, p := range snap.policies {
		fmt.Fprintf(&b, "    set %s {\n", policySetName(p.ID))
		b.WriteString("        type ipv4_addr\n")
		b.WriteString("        flags timeout\n")
		b.WriteString("        timeout 30d\n")

		var ips []string
		seen := make(map[string]struct{})
		for _, d := range snap.domainsByID[p.ID] {
			if !d.Enabled || d.ResolvedIPs == "" {
				continue
			}
			var rs []string
			if err := json.Unmarshal([]byte(d.ResolvedIPs), &rs); err != nil {
				continue
			}
			for _, ip := range rs {
				ip = strings.TrimSpace(ip)
				if ip == "" || strings.Contains(ip, ":") {
					continue // skip IPv6; nft set is ipv4_addr
				}
				if _, dup := seen[ip]; dup {
					continue
				}
				seen[ip] = struct{}{}
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			b.WriteString("        elements = {\n")
			for i, ip := range ips {
				comma := ","
				if i == len(ips)-1 {
					comma = ""
				}
				fmt.Fprintf(&b, "            %s%s\n", ip, comma)
			}
			b.WriteString("        }\n")
		}
		b.WriteString("    }\n\n")
	}

	// Well-known DoH/DoT resolver IPs. Permanent (no timeout) because the
	// list is static and small. Dropping these forces clients back onto
	// our dnsmasq — without this chokepoint, Firefox/iOS/Chrome silently
	// bypass every per-policy allow rule via encrypted DNS.
	b.WriteString("    set doh_resolvers {\n")
	b.WriteString("        type ipv4_addr\n")
	b.WriteString("        elements = {\n")
	for i, ip := range dohResolverIPs {
		comma := ","
		if i == len(dohResolverIPs)-1 {
			comma = ""
		}
		fmt.Fprintf(&b, "            %s%s\n", ip, comma)
	}
	b.WriteString("        }\n")
	b.WriteString("    }\n\n")

	// Input chain (unchanged)
	b.WriteString("    chain input {\n")
	b.WriteString("        type filter hook input priority filter; policy drop;\n")
	b.WriteString("        ct state established,related accept\n")
	b.WriteString("        iif lo accept\n")
	fmt.Fprintf(&b, "        iifname \"%s\" udp dport 53 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" udp dport 67 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" tcp dport 22 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" tcp dport 80 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" tcp dport 8443 accept\n", s.cfg.LANInterface)
	b.WriteString("        iifname \"lo\" accept\n")
	b.WriteString("    }\n\n")

	// One chain per policy. Each chain:
	//   - accepts on IP-set hit (with a per-policy log prefix for traffic mon)
	//   - on miss:
	//       strict policy:     drops with a [NETFILTER-DROP pol=Name] log
	//       permissive policy: jumps to the default policy's chain
	//   - the default policy's chain is always terminal (final drop log).
	// Global user-defined forward rules live inside the default chain so
	// strict policies can't be bypassed by a broad global "accept tcp 443"
	// rule.
	for _, p := range snap.policies {
		fmt.Fprintf(&b, "    chain %s {\n", policyChainName(p.ID))
		fmt.Fprintf(&b, "        ip daddr @%s log prefix \"[NETFILTER-ACCEPT pol=%s] \" accept\n",
			policySetName(p.ID), p.Name)

		if p.IsDefault {
			// Global user-defined forward rules — only run for devices routed
			// to the default policy (unassigned + explicitly default-assigned).
			for _, r := range rules {
				if !r.Enabled || r.Direction != "forward" {
					continue
				}
				for _, line := range s.buildRuleLines(r) {
					fmt.Fprintf(&b, "        %s\n", line)
				}
			}
			fmt.Fprintf(&b, "        ct state new log prefix \"[NETFILTER-DROP pol=%s] \"\n", p.Name)
		} else if p.Mode == "strict" {
			fmt.Fprintf(&b, "        ct state new log prefix \"[NETFILTER-DROP pol=%s] \"\n", p.Name)
		} else {
			// permissive non-default — fall through to default chain
			fmt.Fprintf(&b, "        jump %s\n", policyChainName(snap.defaultID))
		}
		b.WriteString("    }\n\n")
	}

	// Top-level forward chain: conntrack fast-path, hard drops for blocked
	// devices, DoH/DoT chokepoint, per-MAC policy dispatch via vmap
	// (goto — no return), then fallback jump into the default chain for
	// unassigned devices.
	b.WriteString("    chain forward {\n")
	b.WriteString("        type filter hook forward priority filter; policy drop;\n")
	b.WriteString("        ct state established,related accept\n")
	for _, mac := range blockedMACs {
		fmt.Fprintf(&b, "        ether saddr %s drop\n", strings.ToLower(mac))
	}
	// DoH / DoT chokepoint — applies to every device, regardless of policy,
	// before the per-MAC dispatch. Logged so the traffic monitor can show
	// which devices are trying to bypass our DNS.
	b.WriteString("        ip daddr @doh_resolvers tcp dport 443 log prefix \"[NETFILTER-DROP-DOH] \" drop\n")
	b.WriteString("        ip daddr @doh_resolvers udp dport 853 log prefix \"[NETFILTER-DROP-DOT] \" drop\n")
	if len(snap.assignments) > 0 {
		b.WriteString("        ether saddr vmap {\n")
		for i, a := range snap.assignments {
			comma := ","
			if i == len(snap.assignments)-1 {
				comma = ""
			}
			fmt.Fprintf(&b, "            %s : goto %s%s\n",
				strings.ToLower(a.DeviceMAC), policyChainName(a.PolicyID), comma)
		}
		b.WriteString("        }\n")
	}
	fmt.Fprintf(&b, "        jump %s\n", policyChainName(snap.defaultID))
	b.WriteString("    }\n\n")

	// Output chain (unchanged)
	b.WriteString("    chain output {\n")
	b.WriteString("        type filter hook output priority filter; policy accept;\n")
	for _, r := range rules {
		if !r.Enabled || r.Direction != "outbound" {
			continue
		}
		for _, line := range s.buildRuleLines(r) {
			fmt.Fprintf(&b, "        %s\n", line)
		}
	}
	b.WriteString("    }\n")

	b.WriteString("}\n")

	return b.String()
}

// buildRuleLines returns one or more nftables rule lines for a single rule.
// If dest_ip is a hostname, it resolves to all IPs and emits one rule per IP.
// If resolution fails, the rule is skipped with a warning.
func (s *FirewallService) buildRuleLines(r models.FirewallRule) []string {
	destIPs := []string{""}

	if r.DestIP != "" {
		resolved := resolveHostOrIP(r.DestIP)
		if len(resolved) == 0 {
			log.Printf("[FIREWALL] Skipping rule %d: could not resolve dest_ip %q", r.ID, r.DestIP)
			return nil
		}
		destIPs = resolved
	}

	var lines []string
	for _, destIP := range destIPs {
		var parts []string

		if r.DeviceMAC != "" {
			parts = append(parts, fmt.Sprintf("ether saddr %s", strings.ToLower(r.DeviceMAC)))
		}
		if r.Protocol != "" && r.Protocol != "all" {
			if r.Protocol == "icmp" {
				parts = append(parts, "meta l4proto icmp")
			} else {
				parts = append(parts, r.Protocol)
			}
		}
		if r.SourceIP != "" {
			parts = append(parts, fmt.Sprintf("ip saddr %s", r.SourceIP))
		}
		if destIP != "" {
			parts = append(parts, fmt.Sprintf("ip daddr %s", destIP))
		}
		if r.DestPort != "" && r.Protocol != "icmp" && r.Protocol != "all" {
			parts = append(parts, fmt.Sprintf("dport %s", r.DestPort))
		}

		if r.Action == "accept" {
			parts = append(parts, "log prefix \"[NETFILTER-ACCEPT] \"")
		}

		parts = append(parts, r.Action)

		if r.Description != "" {
			comment := r.Description
			if r.DestIP != "" && r.DestIP != destIP {
				comment = fmt.Sprintf("%s (%s)", r.Description, r.DestIP)
			}
			parts = append(parts, fmt.Sprintf("comment \"%s\"", strings.ReplaceAll(comment, "\"", "'")))
		}

		lines = append(lines, strings.Join(parts, " "))
	}

	return lines
}

// resolveHostOrIP returns a slice of IPs for the given input.
// If input is already an IP or CIDR, returns it as-is.
// If it's a hostname, resolves it via DNS.
func resolveHostOrIP(input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	// Check if it's already an IP or CIDR
	if strings.Contains(input, "/") {
		// CIDR notation
		if _, _, err := net.ParseCIDR(input); err == nil {
			return []string{input}
		}
	}
	if ip := net.ParseIP(input); ip != nil {
		return []string{input}
	}

	// Treat as hostname — resolve via DNS
	ips, err := net.LookupIP(input)
	if err != nil {
		return nil
	}

	var result []string
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			result = append(result, ip4.String())
		}
	}
	return result
}
