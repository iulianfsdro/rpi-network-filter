package services

import (
	"database/sql"
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
	db   *sql.DB
	exec *executor.Executor
	cfg  config.Config
	mu   sync.Mutex
}

func NewFirewallService(db *sql.DB, exec *executor.Executor, cfg config.Config) *FirewallService {
	return &FirewallService{db: db, exec: exec, cfg: cfg}
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

func (s *FirewallService) ListAllowedDomains() ([]models.AllowedDomain, error) {
	rows, err := s.db.Query(`
		SELECT id, domain, description, enabled, created_at
		FROM allowed_domains ORDER BY domain ASC
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

func (s *FirewallService) CreateAllowedDomain(d models.AllowedDomain) (int64, error) {
	enabled := 0
	if d.Enabled {
		enabled = 1
	}
	domain := strings.ToLower(strings.TrimSpace(d.Domain))
	result, err := s.db.Exec(
		"INSERT INTO allowed_domains (domain, description, enabled) VALUES (?, ?, ?)",
		domain, d.Description, enabled,
	)
	if err != nil {
		return 0, fmt.Errorf("insert allowed domain: %w", err)
	}
	return result.LastInsertId()
}

func (s *FirewallService) UpdateAllowedDomain(id int64, d models.AllowedDomain) error {
	enabled := 0
	if d.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(
		"UPDATE allowed_domains SET description=?, enabled=? WHERE id=?",
		d.Description, enabled, id,
	)
	return err
}

func (s *FirewallService) DeleteAllowedDomain(id int64) error {
	_, err := s.db.Exec("DELETE FROM allowed_domains WHERE id = ?", id)
	return err
}

// ListActiveSetIPs returns the current IPs in the nftables allowed_domains set
func (s *FirewallService) ListActiveSetIPs() []string {
	result, err := s.exec.Run("nft", "-a", "list", "set", "inet", "filter", "allowed_domains")
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

func (s *FirewallService) Apply() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rules, err := s.ListRules()
	if err != nil {
		return fmt.Errorf("list rules for apply: %w", err)
	}

	// Get blocked devices
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

	// Fetch allowed domains for nftset config
	allowedDomains, err := s.ListAllowedDomains()
	if err != nil {
		log.Printf("[WARN] Failed to list allowed domains: %v", err)
	}

	conf := s.generateConfig(rules, blockedMACs)

	if err := os.WriteFile("/etc/nftables.conf", []byte(conf), 0644); err != nil {
		if !s.exec.DryRun {
			return fmt.Errorf("write nftables.conf: %w", err)
		}
		log.Printf("[DRY-RUN] Would write /etc/nftables.conf (%d bytes)", len(conf))
	}

	if _, err := s.exec.Run("nft", "-f", "/etc/nftables.conf"); err != nil {
		return fmt.Errorf("reload nftables: %w", err)
	}

	// Write dnsmasq nftset config so DNS queries auto-populate the set
	if err := s.writeDnsmasqNftsets(allowedDomains); err != nil {
		log.Printf("[WARN] Failed to write dnsmasq nftsets: %v", err)
	} else if len(allowedDomains) > 0 {
		// Only reload dnsmasq if the config was actually written
		if _, err := s.exec.Run("systemctl", "reload", "dnsmasq"); err != nil {
			log.Printf("[WARN] Failed to reload dnsmasq: %v", err)
		}
	}

	log.Printf("[FIREWALL] Applied %d rules, %d blocked, %d allowed domains",
		len(rules), len(blockedMACs), len(allowedDomains))
	return nil
}

// writeDnsmasqNftsets generates /etc/dnsmasq.d/netfilter-nftsets.conf with
// one nftset= line per enabled allowed domain. dnsmasq will automatically add
// resolved IPs to the nftables set when clients query these domains.
func (s *FirewallService) writeDnsmasqNftsets(domains []models.AllowedDomain) error {
	var b strings.Builder
	b.WriteString("# Generated by netfilterd — do not edit\n")
	b.WriteString("# Maps DNS queries to the nftables 'allowed_domains' set for dynamic allow-listing\n\n")

	count := 0
	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(d.Domain))
		if domain == "" {
			continue
		}
		fmt.Fprintf(&b, "nftset=/%s/inet#filter#allowed_domains\n", domain)
		count++
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

func (s *FirewallService) generateConfig(rules []models.FirewallRule, blockedMACs []string) string {
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

	// Dynamic set for allow-listed domains (populated by dnsmasq via nftset=)
	// Timeout: entries expire 1 hour after last addition (re-added on next query)
	b.WriteString("    set allowed_domains {\n")
	b.WriteString("        type ipv4_addr\n")
	b.WriteString("        flags timeout\n")
	b.WriteString("        timeout 1h\n")
	b.WriteString("    }\n\n")

	// Input chain
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

	// Forward chain — DEFAULT DENY: all client traffic is dropped unless explicitly allowed
	b.WriteString("    chain forward {\n")
	b.WriteString("        type filter hook forward priority filter; policy drop;\n")
	b.WriteString("        ct state established,related accept\n")

	// Blocked devices — explicit drop before any accept rules
	for _, mac := range blockedMACs {
		fmt.Fprintf(&b, "        ether saddr %s drop\n", strings.ToLower(mac))
	}

	// Accept traffic to dynamically allow-listed domains
	// (IPs are auto-added by dnsmasq when clients resolve allowed domains)
	b.WriteString("        ip daddr @allowed_domains log prefix \"[NETFILTER-ACCEPT] \" accept\n")

	// User-defined rules (accept rules allow specific traffic through)
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if r.Direction != "forward" {
			continue
		}
		for _, line := range s.buildRuleLines(r) {
			fmt.Fprintf(&b, "        %s\n", line)
		}
	}

	// Log all new connection attempts that reach default drop (for traffic monitor)
	b.WriteString("        ct state new log prefix \"[NETFILTER-DROP] \"\n")

	b.WriteString("    }\n\n")

	// Output chain
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
