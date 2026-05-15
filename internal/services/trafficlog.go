package services

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

type TrafficEntry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	DstPort   string `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Action    string `json:"action"`
	SrcMAC    string `json:"src_mac"`
	Domain    string `json:"domain"`
	Source    string `json:"source"` // "dns" | "forward"
	Policy    string `json:"policy"` // name of the policy that produced the verdict (forward only)
}

type TrafficLogService struct {
	db       *sql.DB
	dnsCache map[string]string
	dnsMu    sync.RWMutex

	// Per-device log-suppression cache. Holds the lowercased MAC and
	// last-known IP of every device with devices.ignore_traffic_log = 1.
	// Checked in the hot ingest path so chatty devices (e.g. owner laptop
	// burning hundreds of DNS queries per second) don't fill query_log.
	// Refreshed periodically by RefreshIgnoreCache and on demand from the
	// device-update handler.
	ignoreMu   sync.RWMutex
	ignoredMACs map[string]struct{}
	ignoredIPs  map[string]struct{}
}

func NewTrafficLogService(db *sql.DB) *TrafficLogService {
	return &TrafficLogService{
		db:          db,
		dnsCache:    make(map[string]string),
		ignoredMACs: make(map[string]struct{}),
		ignoredIPs:  make(map[string]struct{}),
	}
}

var nflogRe = regexp.MustCompile(
	`\[NETFILTER.*?\].*SRC=(\S+)\s.*DST=(\S+)\s.*PROTO=(\S+)`,
)
var nflogPortRe = regexp.MustCompile(`DPT=(\d+)`)
var nflogMacRe = regexp.MustCompile(`MAC=([0-9a-f:]+)`)
// Captures the policy name from log prefixes like "[NETFILTER-ACCEPT pol=Tesla]".
var nflogPolicyRe = regexp.MustCompile(`\[NETFILTER-(?:ACCEPT|DROP)(?:-[A-Z]+)?\s+pol=([^\s\]]+)\]`)

var dnsQueryRe = regexp.MustCompile(
	`query\[(\S+)\] (\S+) from (\S+)`,
)
var dnsReplyRe = regexp.MustCompile(
	`reply (\S+) is (\d+\.\d+\.\d+\.\d+)`,
)

// journald JSON entry (subset of fields we care about)
type journalEntry struct {
	Cursor           string `json:"__CURSOR"`
	Message          string `json:"MESSAGE"`
	RealtimeTS       string `json:"__REALTIME_TIMESTAMP"`
	SyslogIdentifier string `json:"SYSLOG_IDENTIFIER"`
}

func (s *TrafficLogService) StartTailing() {
	// Prime the ignore cache before any tail starts ingesting so the
	// first event from an ignored device isn't accidentally logged.
	s.RefreshIgnoreCache()
	go s.tailJournal("kernel", "kernel-cursor", []string{"-k"})
	go s.tailDnsmasqLogFile()
	go s.cleanOldEntries()
	go s.refreshIgnoreCacheLoop()
}

// RefreshIgnoreCache rebuilds the in-memory set of MACs/IPs whose traffic
// events should be skipped at INSERT time. Call after any change to a
// device's ignore_traffic_log column, or rely on the periodic refresh.
func (s *TrafficLogService) RefreshIgnoreCache() {
	rows, err := s.db.Query("SELECT mac_address, ip_address FROM devices WHERE ignore_traffic_log = 1")
	if err != nil {
		log.Printf("[TRAFFIC] refresh ignore cache: %v", err)
		return
	}
	defer rows.Close()

	macs := make(map[string]struct{})
	ips := make(map[string]struct{})
	for rows.Next() {
		var mac, ip string
		if err := rows.Scan(&mac, &ip); err != nil {
			continue
		}
		if mac != "" {
			macs[strings.ToLower(strings.TrimSpace(mac))] = struct{}{}
		}
		if ip != "" {
			ips[strings.TrimSpace(ip)] = struct{}{}
		}
	}

	s.ignoreMu.Lock()
	s.ignoredMACs = macs
	s.ignoredIPs = ips
	s.ignoreMu.Unlock()
}

func (s *TrafficLogService) refreshIgnoreCacheLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.RefreshIgnoreCache()
	}
}

// isIgnored returns true if a traffic event from this MAC or IP should be
// dropped at INSERT time. Either match wins — DNS events have no MAC, so
// the IP cache catches them; forward events always carry a MAC.
func (s *TrafficLogService) isIgnored(mac, ip string) bool {
	if mac == "" && ip == "" {
		return false
	}
	s.ignoreMu.RLock()
	defer s.ignoreMu.RUnlock()
	if mac != "" {
		if _, ok := s.ignoredMACs[strings.ToLower(strings.TrimSpace(mac))]; ok {
			return true
		}
	}
	if ip != "" {
		if _, ok := s.ignoredIPs[strings.TrimSpace(ip)]; ok {
			return true
		}
	}
	return false
}

// WipeForDevice deletes every query_log row attributable to this device.
// MAC matches forward (nflog) events; IP matches DNS events (which carry
// no MAC). Pass the device's last-known IP from the devices row — old IPs
// from a prior DHCP lease will still leak through, which is acceptable.
func (s *TrafficLogService) WipeForDevice(mac, ip string) (int64, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	ip = strings.TrimSpace(ip)
	if mac == "" && ip == "" {
		return 0, nil
	}
	res, err := s.db.Exec(
		"DELETE FROM query_log WHERE LOWER(client_mac) = ? OR client_ip = ?",
		mac, ip,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// tailDnsmasqLogFile tails /var/log/dnsmasq.log (the default on Raspberry Pi OS
// when log-facility= is configured) via `tail -F` for real-time updates.
// Falls back to journalctl if the file doesn't exist.
func (s *TrafficLogService) tailDnsmasqLogFile() {
	const dnsmasqLog = "/var/log/dnsmasq.log"

	for {
		if _, err := os.Stat(dnsmasqLog); err != nil {
			// File doesn't exist — use journalctl instead
			s.tailJournal("dnsmasq", "dnsmasq-cursor", []string{"-u", "dnsmasq"})
			time.Sleep(5 * time.Second)
			continue
		}

		// tail -F follows the file even across rotations; -n 0 skips existing content on startup
		cmd := exec.Command("tail", "-F", "-n", "0", dnsmasqLog)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("[TRAFFIC] dnsmasq tail pipe failed: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if err := cmd.Start(); err != nil {
			log.Printf("[TRAFFIC] dnsmasq tail start failed: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			s.parseDnsLine(scanner.Text(), "")
		}

		cmd.Wait()
		log.Printf("[TRAFFIC] dnsmasq tail exited, restarting...")
		time.Sleep(2 * time.Second)
	}
}

func (s *TrafficLogService) tailJournal(name, cursorKey string, baseArgs []string) {
	for {
		cursor := s.getCursor(cursorKey)

		args := append([]string{}, baseArgs...)
		args = append(args, "-o", "json", "--no-pager", "--follow")

		if cursor != "" {
			args = append(args, "--after-cursor="+cursor)
		} else {
			// First run — get last 24h
			args = append(args, "--since=1 day ago")
		}

		cmd := exec.Command("journalctl", args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("[TRAFFIC] %s: pipe failed: %v", name, err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := cmd.Start(); err != nil {
			log.Printf("[TRAFFIC] %s: start failed: %v", name, err)
			time.Sleep(5 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

		lastCursorSave := time.Now()
		var lastCursor string

		for scanner.Scan() {
			var entry journalEntry
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				continue
			}

			lastCursor = entry.Cursor

			if name == "kernel" {
				if strings.Contains(entry.Message, "NETFILTER") {
					s.parseNfLine(entry.Message, entry.RealtimeTS)
				}
			} else if name == "dnsmasq" {
				s.parseDnsLine(entry.Message, entry.RealtimeTS)
			}

			// Save cursor every 5 seconds to reduce DB writes
			if time.Since(lastCursorSave) > 5*time.Second && lastCursor != "" {
				s.setCursor(cursorKey, lastCursor)
				lastCursorSave = time.Now()
			}
		}

		// Save final cursor before restart
		if lastCursor != "" {
			s.setCursor(cursorKey, lastCursor)
		}

		cmd.Wait()
		log.Printf("[TRAFFIC] %s journal stream ended, restarting...", name)
		time.Sleep(2 * time.Second)
	}
}

func (s *TrafficLogService) getCursor(key string) string {
	var cursor string
	err := s.db.QueryRow("SELECT value FROM kv_store WHERE key = ?", key).Scan(&cursor)
	if err != nil && err != sql.ErrNoRows {
		// Real DB error (locked, missing table, schema drift). Without
		// this log the tail loop silently re-ingests 24h of kernel
		// log on every iteration.
		log.Printf("[TRAFFIC] read cursor %q: %v", key, err)
	}
	return cursor
}

func (s *TrafficLogService) setCursor(key, value string) {
	if _, err := s.db.Exec(`
		INSERT INTO kv_store (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
	`, key, value); err != nil {
		log.Printf("[TRAFFIC] write cursor %q: %v", key, err)
	}
}

func (s *TrafficLogService) cleanOldEntries() {
	// Wait 1 hour before first cleanup (so startup isn't destructive)
	time.Sleep(1 * time.Hour)

	for {
		var retentionDays string
		if err := s.db.QueryRow("SELECT value FROM settings WHERE key = 'log_retention_days'").Scan(&retentionDays); err != nil && err != sql.ErrNoRows {
			log.Printf("[TRAFFIC] read log_retention_days: %v", err)
		}
		if retentionDays == "" {
			retentionDays = "30"
		}

		if _, err := s.db.Exec(
			"DELETE FROM query_log WHERE timestamp < datetime('now', '-' || ? || ' days')",
			retentionDays,
		); err != nil {
			log.Printf("[TRAFFIC] prune old entries: %v", err)
		}
		time.Sleep(6 * time.Hour)
	}
}

func (s *TrafficLogService) parseNfLine(message, realtimeTS string) {
	m := nflogRe.FindStringSubmatch(message)
	if m == nil {
		return
	}

	entry := TrafficEntry{
		Timestamp: realtimeTS,
		SrcIP:     m[1],
		DstIP:     m[2],
		Protocol:  m[3],
		Source:    "forward",
	}

	if pm := nflogPortRe.FindStringSubmatch(message); pm != nil {
		entry.DstPort = pm[1]
	}
	if mm := nflogMacRe.FindStringSubmatch(message); mm != nil {
		entry.SrcMAC = mm[1]
	}

	switch {
	case strings.Contains(message, "[NETFILTER-DROP-DOH]"):
		entry.Action = "blocked"
		entry.Policy = "DoH chokepoint"
	case strings.Contains(message, "[NETFILTER-DROP-DOT]"):
		entry.Action = "blocked"
		entry.Policy = "DoT chokepoint"
	case strings.Contains(message, "[NETFILTER-DROP"):
		entry.Action = "blocked"
	case strings.Contains(message, "[NETFILTER-ACCEPT"):
		entry.Action = "allowed"
	default:
		entry.Action = "logged"
	}

	if entry.Policy == "" {
		if pm := nflogPolicyRe.FindStringSubmatch(message); pm != nil {
			entry.Policy = pm[1]
		}
	}

	s.dnsMu.RLock()
	if domain, ok := s.dnsCache[entry.DstIP]; ok {
		entry.Domain = domain
	}
	s.dnsMu.RUnlock()

	s.insertEntry(entry)
}

func (s *TrafficLogService) parseDnsLine(message, realtimeTS string) {
	// DNS query
	if m := dnsQueryRe.FindStringSubmatch(message); m != nil {
		domain := m[2]
		clientIP := m[3]

		if domain == "localhost" || strings.HasSuffix(domain, ".local") {
			return
		}

		s.insertEntry(TrafficEntry{
			Timestamp: realtimeTS,
			Protocol:  "DNS",
			DstPort:   "53",
			SrcIP:     clientIP,
			Domain:    domain,
			Action:    "query",
			Source:    "dns",
		})
		return
	}

	// DNS reply — cache for reverse lookup
	if m := dnsReplyRe.FindStringSubmatch(message); m != nil {
		s.dnsMu.Lock()
		s.dnsCache[m[2]] = m[1]
		if len(s.dnsCache) > 10000 {
			s.dnsCache = make(map[string]string)
		}
		s.dnsMu.Unlock()
	}
}

func (s *TrafficLogService) insertEntry(e TrafficEntry) {
	if e.Source == "" {
		e.Source = "forward"
	}
	if s.isIgnored(e.SrcMAC, e.SrcIP) {
		return
	}
	_, err := s.db.Exec(`
		INSERT INTO query_log (timestamp, client_ip, domain, dst_ip, dst_port, protocol, action, client_mac, source, policy)
		VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, e.SrcIP, e.Domain, e.DstIP, e.DstPort, e.Protocol, e.Action, e.SrcMAC, e.Source, e.Policy)
	if err != nil {
		log.Printf("[WARN] Failed to insert query log: %v", err)
	}
}

func (s *TrafficLogService) RecentEntries(limit int) []TrafficEntry {
	if limit <= 0 {
		limit = 200
	}

	rows, err := s.db.Query(`
		SELECT id, timestamp, client_ip, domain, dst_ip, dst_port, protocol, action, client_mac,
		       COALESCE(source,'forward'), COALESCE(policy,'')
		FROM query_log ORDER BY id DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []TrafficEntry
	for rows.Next() {
		var e TrafficEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SrcIP, &e.Domain, &e.DstIP, &e.DstPort,
			&e.Protocol, &e.Action, &e.SrcMAC, &e.Source, &e.Policy); err != nil {
			log.Printf("[WARN] RecentEntries scan: %v", err)
			continue
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[WARN] RecentEntries iterate: %v", err)
	}
	return entries
}

// PagedResult is a paginated query response with total count.
type PagedResult struct {
	Entries []TrafficEntry `json:"entries"`
	Total   int            `json:"total"`
	Page    int            `json:"page"`
	Pages   int            `json:"pages"`
	PerPage int            `json:"per_page"`
}

// TrafficFilter holds pagination + filter options
type TrafficFilter struct {
	Page    int
	PerPage int
	Action  string
	Query   string
	From    string // ISO datetime
	To      string // ISO datetime
	Source  string // "dns" | "forward" | "" (any)
}

// QueryPaginated returns a page of query_log entries matching the filter.
func (s *TrafficLogService) QueryPaginated(f TrafficFilter) PagedResult {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PerPage <= 0 || f.PerPage > 500 {
		f.PerPage = 50
	}

	var where []string
	var args []any

	if f.Action != "" && f.Action != "all" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}

	if f.Source != "" && f.Source != "all" {
		where = append(where, "COALESCE(source,'forward') = ?")
		args = append(args, f.Source)
	}

	if f.Query != "" {
		pattern := "%" + f.Query + "%"
		where = append(where, "(domain LIKE ? OR client_ip LIKE ? OR dst_ip LIKE ? OR dst_port LIKE ?)")
		args = append(args, pattern, pattern, pattern, pattern)
	}

	if f.From != "" {
		where = append(where, "timestamp >= ?")
		args = append(args, f.From)
	}
	if f.To != "" {
		where = append(where, "timestamp <= ?")
		args = append(args, f.To)
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	// Total count (for pagination)
	var total int
	countQuery := "SELECT COUNT(*) FROM query_log" + whereSQL
	s.db.QueryRow(countQuery, args...).Scan(&total)

	// Pages calculation
	pages := (total + f.PerPage - 1) / f.PerPage
	if pages < 1 {
		pages = 1
	}
	if f.Page > pages {
		f.Page = pages
	}

	offset := (f.Page - 1) * f.PerPage

	query := `
		SELECT id, timestamp, client_ip, domain, dst_ip, dst_port, protocol, action, client_mac,
		       COALESCE(source,'forward'), COALESCE(policy,'')
		FROM query_log` + whereSQL + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	pageArgs := append(args, f.PerPage, offset)

	rows, err := s.db.Query(query, pageArgs...)
	if err != nil {
		log.Printf("[WARN] QueryPaginated failed: %v", err)
		return PagedResult{Entries: []TrafficEntry{}, Total: total, Page: f.Page, Pages: pages, PerPage: f.PerPage}
	}
	defer rows.Close()

	entries := make([]TrafficEntry, 0, f.PerPage)
	for rows.Next() {
		var e TrafficEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SrcIP, &e.Domain, &e.DstIP, &e.DstPort,
			&e.Protocol, &e.Action, &e.SrcMAC, &e.Source, &e.Policy); err != nil {
			log.Printf("[WARN] QueryPaginated scan: %v", err)
			continue
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[WARN] QueryPaginated iterate: %v", err)
	}

	return PagedResult{
		Entries: entries,
		Total:   total,
		Page:    f.Page,
		Pages:   pages,
		PerPage: f.PerPage,
	}
}

// Clear wipes all query_log entries and resets cursors so tail restarts from current position.
func (s *TrafficLogService) Clear() error {
	if _, err := s.db.Exec("DELETE FROM query_log"); err != nil {
		return err
	}
	if _, err := s.db.Exec("DELETE FROM sqlite_sequence WHERE name = 'query_log'"); err != nil {
		return err
	}
	log.Printf("[TRAFFIC] query_log cleared")
	return nil
}

func (s *TrafficLogService) Search(query string, limit int) []TrafficEntry {
	if limit <= 0 {
		limit = 100
	}
	pattern := "%" + query + "%"

	rows, err := s.db.Query(`
		SELECT id, timestamp, client_ip, domain, dst_ip, dst_port, protocol, action, client_mac
		FROM query_log
		WHERE domain LIKE ? OR client_ip LIKE ? OR dst_ip LIKE ? OR dst_port LIKE ?
		ORDER BY id DESC LIMIT ?
	`, pattern, pattern, pattern, pattern, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []TrafficEntry
	for rows.Next() {
		var e TrafficEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SrcIP, &e.Domain, &e.DstIP, &e.DstPort, &e.Protocol, &e.Action, &e.SrcMAC); err != nil {
			log.Printf("[WARN] Search scan: %v", err)
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

// Summary stats for the statistics page
type StatsSummary struct {
	Total         int `json:"total"`
	Queries       int `json:"queries"`
	Allowed       int `json:"allowed"`
	Blocked       int `json:"blocked"`
	UniqueDomains int `json:"unique_domains"`
	UniqueClients int `json:"unique_clients"`
}

type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

type ClientCount struct {
	Client string `json:"client"`
	Count  int    `json:"count"`
}

type TimePoint struct {
	Time    string `json:"time"`
	Queries int    `json:"queries"`
	Allowed int    `json:"allowed"`
	Blocked int    `json:"blocked"`
}

func (s *TrafficLogService) timeWhereClause(rangeStr string) string {
	switch rangeStr {
	case "1h":
		return "timestamp >= datetime('now', '-1 hour')"
	case "24h":
		return "timestamp >= datetime('now', '-1 day')"
	case "7d":
		return "timestamp >= datetime('now', '-7 days')"
	case "30d":
		return "timestamp >= datetime('now', '-30 days')"
	case "all":
		return "1=1"
	default:
		return "timestamp >= datetime('now', '-1 day')"
	}
}

func (s *TrafficLogService) Summary(rangeStr string) StatsSummary {
	where := s.timeWhereClause(rangeStr)
	var stats StatsSummary

	// Single atomic query so counts are consistent
	if err := s.db.QueryRow(`
		SELECT
			COUNT(*),
			SUM(CASE WHEN action = 'query'   THEN 1 ELSE 0 END),
			SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END),
			SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END),
			COUNT(DISTINCT CASE WHEN domain != '' THEN domain END),
			COUNT(DISTINCT CASE WHEN client_ip != '' THEN client_ip END)
		FROM query_log WHERE `+where).Scan(
		&stats.Total, &stats.Queries, &stats.Allowed, &stats.Blocked,
		&stats.UniqueDomains, &stats.UniqueClients,
	); err != nil {
		log.Printf("[WARN] Summary scan: %v", err)
	}

	return stats
}

func (s *TrafficLogService) TopDomains(action, rangeStr, q string, limit int) []DomainCount {
	if limit <= 0 {
		limit = 50
	}
	where := s.timeWhereClause(rangeStr)

	// Use domain if present, else fall back to dst_ip.
	// This way blocked IPs without known domains still show up.
	query := `
		SELECT COALESCE(NULLIF(domain, ''), dst_ip) as dest, COUNT(*) as cnt
		FROM query_log
		WHERE (domain != '' OR dst_ip != '') AND ` + where
	args := []any{}
	if action != "" && action != "all" {
		query += " AND action = ?"
		args = append(args, action)
	}
	if q != "" {
		// Filter against both columns so a search hits whether the row
		// has a resolved domain (DNS events) or just an IP (some forward
		// events). Mirrors the LIKE pattern used in QueryPaginated.
		pattern := "%" + q + "%"
		query += " AND (domain LIKE ? OR dst_ip LIKE ?)"
		args = append(args, pattern, pattern)
	}
	query += " GROUP BY dest ORDER BY cnt DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []DomainCount
	for rows.Next() {
		var d DomainCount
		if err := rows.Scan(&d.Domain, &d.Count); err != nil {
			log.Printf("[WARN] TopDomains scan: %v", err)
			continue
		}
		result = append(result, d)
	}
	return result
}

func (s *TrafficLogService) TopClients(rangeStr string, limit int) []ClientCount {
	if limit <= 0 {
		limit = 10
	}
	where := s.timeWhereClause(rangeStr)
	rows, err := s.db.Query(`
		SELECT client_ip, COUNT(*) as cnt FROM query_log
		WHERE client_ip != '' AND `+where+`
		GROUP BY client_ip ORDER BY cnt DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []ClientCount
	for rows.Next() {
		var c ClientCount
		if err := rows.Scan(&c.Client, &c.Count); err != nil {
			log.Printf("[WARN] TopClients scan: %v", err)
			continue
		}
		result = append(result, c)
	}
	return result
}

func (s *TrafficLogService) TimeSeries(rangeStr string) []TimePoint {
	var bucket string
	var where string
	switch rangeStr {
	case "1h":
		bucket = "strftime('%Y-%m-%d %H:%M', timestamp, '-' || (strftime('%M', timestamp) % 5) || ' minutes')"
		where = "timestamp >= datetime('now', '-1 hour')"
	case "7d":
		bucket = "strftime('%Y-%m-%d %H:00', timestamp)"
		where = "timestamp >= datetime('now', '-7 days')"
	case "30d":
		bucket = "strftime('%Y-%m-%d', timestamp)"
		where = "timestamp >= datetime('now', '-30 days')"
	default: // 24h
		bucket = "strftime('%Y-%m-%d %H:00', timestamp)"
		where = "timestamp >= datetime('now', '-1 day')"
	}

	query := `
		SELECT ` + bucket + ` as bucket,
			SUM(CASE WHEN action = 'query' THEN 1 ELSE 0 END) as queries,
			SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) as allowed,
			SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked
		FROM query_log WHERE ` + where + `
		GROUP BY bucket ORDER BY bucket ASC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []TimePoint
	for rows.Next() {
		var p TimePoint
		if err := rows.Scan(&p.Time, &p.Queries, &p.Allowed, &p.Blocked); err != nil {
			log.Printf("[WARN] TimeSeries scan: %v", err)
			continue
		}
		result = append(result, p)
	}
	return result
}
