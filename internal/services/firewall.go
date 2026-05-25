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

// deviceSnapshot is the per-device classification generateConfig needs:
// the MAC of every filtered, open, and blocked device. A device without
// a status row, or any value not in this set, falls through to the
// forward chain's policy drop — blocked-by-default.
type deviceSnapshot struct {
	filtered []string
	open     []string
	blocked  []string
}

func (s *FirewallService) loadDeviceSnapshot() (deviceSnapshot, error) {
	var snap deviceSnapshot
	rows, err := s.db.Query(`SELECT mac_address, status FROM devices WHERE status IN ('filtered','open','blocked')`)
	if err != nil {
		return snap, fmt.Errorf("query device status: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var mac, status string
		if err := rows.Scan(&mac, &status); err != nil {
			return snap, fmt.Errorf("scan device status: %w", err)
		}
		if !ValidMAC(strings.ToLower(mac)) {
			log.Printf("[FIREWALL] skip invalid MAC %q in DB", mac)
			continue
		}
		mac = strings.ToLower(mac)
		switch status {
		case "filtered":
			snap.filtered = append(snap.filtered, mac)
		case "open":
			snap.open = append(snap.open, mac)
		case "blocked":
			snap.blocked = append(snap.blocked, mac)
		}
	}
	return snap, rows.Err()
}

func (s *FirewallService) Apply() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rules, err := s.ListRules()
	if err != nil {
		return fmt.Errorf("list rules for apply: %w", err)
	}

	snap, err := s.loadDeviceSnapshot()
	if err != nil {
		return err
	}

	conf := s.generateConfig(rules, snap)

	if err := os.WriteFile("/etc/nftables.conf", []byte(conf), 0644); err != nil {
		if !s.exec.DryRun {
			return fmt.Errorf("write nftables.conf: %w", err)
		}
		log.Printf("[DRY-RUN] Would write /etc/nftables.conf (%d bytes)", len(conf))
	}

	if _, err := s.exec.Run("nft", "-f", "/etc/nftables.conf"); err != nil {
		return fmt.Errorf("reload nftables: %w", err)
	}

	log.Printf("[FIREWALL] applied: %d rules, %d filtered, %d open, %d blocked",
		len(rules), len(snap.filtered), len(snap.open), len(snap.blocked))
	return nil
}

func (s *FirewallService) generateConfig(rules []models.FirewallRule, snap deviceSnapshot) string {
	var b strings.Builder

	b.WriteString("#!/usr/sbin/nft -f\n\n")
	b.WriteString("flush ruleset\n\n")

	// NAT table.
	//
	//  Filtered device: tcp/80 → connman spoof (DNAT to the Pi), tcp/443 →
	//  the local SNI proxy (REDIRECT). Intercepted in prerouting, before the
	//  forward chain — the forward chain never sees a filtered device's web.
	//
	//  Open device: UDP/TCP 53 → DNAT'd straight to the configured upstream
	//  so the device bypasses the Pi's default-deny dnsmasq regardless of
	//  what DNS its DHCP lease was issued with. Critical for the case where
	//  the device was filtered when it joined (lease cached DNS = the Pi)
	//  and the operator later flips it to Open — DHCP option changes only
	//  land on the next lease, which can be hours away; this DNAT makes
	//  Open take effect immediately on every status flip.
	upstream := splitUpstreams(s.cfg.DNSUpstream)[0]
	b.WriteString("table ip nat {\n")
	b.WriteString("    chain prerouting {\n")
	b.WriteString("        type nat hook prerouting priority dstnat; policy accept;\n")
	for _, mac := range snap.filtered {
		fmt.Fprintf(&b, "        iifname \"%s\" ether saddr %s tcp dport 80 dnat to %s\n",
			s.cfg.LANInterface, mac, s.cfg.LANGateway)
		fmt.Fprintf(&b, "        iifname \"%s\" ether saddr %s tcp dport 443 redirect to :%d\n",
			s.cfg.LANInterface, mac, s.cfg.SNIProxyPort)
	}
	for _, mac := range snap.open {
		fmt.Fprintf(&b, "        iifname \"%s\" ether saddr %s udp dport 53 dnat to %s:53\n",
			s.cfg.LANInterface, mac, upstream)
		fmt.Fprintf(&b, "        iifname \"%s\" ether saddr %s tcp dport 53 dnat to %s:53\n",
			s.cfg.LANInterface, mac, upstream)
	}
	b.WriteString("    }\n")
	b.WriteString("    chain postrouting {\n")
	b.WriteString("        type nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&b, "        oifname \"%s\" masquerade\n", s.cfg.WANInterface)
	b.WriteString("    }\n")
	b.WriteString("}\n\n")

	// Filter table.
	b.WriteString("table inet filter {\n")

	// Input chain — traffic terminating on the Pi: DNS, DHCP, SSH, the
	// connman spoof (:80/:443), the admin UI (:8443), and the SNI proxy.
	b.WriteString("    chain input {\n")
	b.WriteString("        type filter hook input priority filter; policy drop;\n")
	b.WriteString("        ct state established,related accept\n")
	b.WriteString("        iif lo accept\n")
	fmt.Fprintf(&b, "        iifname \"%s\" udp dport 53 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" udp dport 67 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" tcp dport 22 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" tcp dport 80 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" tcp dport 443 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" tcp dport 8443 accept\n", s.cfg.LANInterface)
	fmt.Fprintf(&b, "        iifname \"%s\" tcp dport %d accept\n", s.cfg.LANInterface, s.cfg.SNIProxyPort)
	b.WriteString("    }\n\n")

	// Forward chain. A filtered device's :80/:443 was already intercepted
	// in prerouting; all its other traffic falls through to the drop.
	// Open devices get full passthrough. Blocked devices are dropped up
	// front. Devices with no row, or any other status, are caught by the
	// default policy drop — i.e. blocked-by-default.
	b.WriteString("    chain forward {\n")
	b.WriteString("        type filter hook forward priority filter; policy drop;\n")
	b.WriteString("        ct state established,related accept\n")
	for _, mac := range snap.blocked {
		fmt.Fprintf(&b, "        ether saddr %s drop\n", mac)
	}
	for _, mac := range snap.open {
		fmt.Fprintf(&b, "        ether saddr %s accept\n", mac)
	}
	// Global user-defined forward rules (the /firewall page).
	for _, r := range rules {
		if !r.Enabled || r.Direction != "forward" {
			continue
		}
		for _, line := range s.buildRuleLines(r) {
			fmt.Fprintf(&b, "        %s\n", line)
		}
	}
	b.WriteString("        ct state new log prefix \"[NETFILTER-DROP] \" drop\n")
	b.WriteString("        drop\n")
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
//
// Validates every field before emitting — the output is pasted into the
// nft config file, so any unvalidated string with `\n`, `;`, or `{` would
// inject arbitrary rules.
func (s *FirewallService) buildRuleLines(r models.FirewallRule) []string {
	if !ValidProtocol(r.Protocol) {
		log.Printf("[FIREWALL] skip rule %d: invalid protocol %q", r.ID, r.Protocol)
		return nil
	}
	if r.SourceIP != "" && !ValidIPOrCIDR(r.SourceIP) {
		log.Printf("[FIREWALL] skip rule %d: invalid source_ip %q", r.ID, r.SourceIP)
		return nil
	}
	if !ValidPortSpec(r.DestPort) {
		log.Printf("[FIREWALL] skip rule %d: invalid dest_port %q", r.ID, r.DestPort)
		return nil
	}
	if r.DeviceMAC != "" && !ValidMAC(r.DeviceMAC) {
		log.Printf("[FIREWALL] skip rule %d: invalid device_mac %q", r.ID, r.DeviceMAC)
		return nil
	}

	destIPs := []string{""}

	if r.DestIP != "" {
		resolved := resolveHostOrIP(r.DestIP)
		if len(resolved) == 0 {
			log.Printf("[FIREWALL] Skipping rule %d: could not resolve dest_ip %q", r.ID, r.DestIP)
			return nil
		}
		// Validate every resolved IP — LookupIP should never return
		// malformed strings, but defensive validation keeps the nft
		// config uninjectable even if resolution is poisoned.
		var filtered []string
		for _, ip := range resolved {
			if ValidIPOrCIDR(ip) {
				filtered = append(filtered, ip)
			}
		}
		if len(filtered) == 0 {
			return nil
		}
		destIPs = filtered
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
