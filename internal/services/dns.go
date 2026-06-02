package services

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

// DNSService configures dnsmasq. V3 runs dnsmasq in a default-deny posture:
// only domains enabled in a preset attached to at least one filtered device
// resolve; everything else is sinkholed. This is the extra-defense DNS
// layer behind the SNI proxy (the primary :443 gate).
type DNSService struct {
	db   *sql.DB
	exec *executor.Executor
	cfg  config.Config
	mu   sync.Mutex
}

func NewDNSService(db *sql.DB, exec *executor.Executor, cfg config.Config) *DNSService {
	return &DNSService{db: db, exec: exec, cfg: cfg}
}

// EnsureDefaultDenyConfig auto-heals existing installs that were set up
// before the default-deny posture was tightened. Two leaks are fixed:
//
//  1. /etc/dnsmasq.conf used to carry global `server=<upstream>` directives
//     (no domain prefix). Those make dnsmasq forward every otherwise-
//     unmatched query to a public resolver, so `address=/#/` in our
//     netfilter-dns.conf NEVER fires (per dnsmasq's "otherwise unanswered"
//     semantics for the wildcard). Strip them and add `no-resolv` so
//     dnsmasq has no global upstream at all.
//
//  2. /etc/resolv.conf used to list `nameserver 127.0.0.1` first, meaning
//     the Pi's OWN processes (apt, curl, etc.) routed their DNS through
//     dnsmasq — which will now NXDOMAIN them. Remove the loopback entry
//     so the Pi resolves directly via the public upstreams listed after.
//
// Idempotent. Restarts dnsmasq if anything changed.
func (s *DNSService) EnsureDefaultDenyConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dnsmasqChanged, err := stripGlobalUpstreamsAndAddNoResolv("/etc/dnsmasq.conf")
	if err != nil {
		return fmt.Errorf("heal /etc/dnsmasq.conf: %w", err)
	}
	resolvChanged, err := stripLoopbackFromResolv("/etc/resolv.conf")
	if err != nil {
		log.Printf("[DNS] could not heal /etc/resolv.conf (continuing): %v", err)
	}
	if dnsmasqChanged || resolvChanged {
		log.Printf("[DNS] auto-healed legacy DNS config (dnsmasq=%v resolv=%v); restarting dnsmasq", dnsmasqChanged, resolvChanged)
		if _, err := s.exec.Run("systemctl", "restart", "dnsmasq"); err != nil {
			return fmt.Errorf("restart dnsmasq: %w", err)
		}
	}
	return nil
}

// stripGlobalUpstreamsAndAddNoResolv rewrites /etc/dnsmasq.conf to remove
// any `server=<ip>` line that has no domain prefix (the global-forwarder
// form), deduplicate any pre-existing `no-resolv` lines down to one, and
// ensure that one `no-resolv` line is present. Returns true if the file
// was actually changed.
//
// Earlier versions of this function only recognised a bare `no-resolv`
// line — they didn't see their OWN appended form `no-resolv  # added by
// netfilterd …` as already-present, so every dns.Apply() tacked on
// another copy. The directive-level detection below (via strings.Fields)
// recognises the directive regardless of trailing comment / whitespace
// and additionally drops any duplicates left behind by older builds.
func stripGlobalUpstreamsAndAddNoResolv(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var lines []string
	seenNoResolv := false
	changed := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// A global upstream forwarder has the form `server=<ip>` or
		// `server=<ip>#<port>`. The allow-list form `server=/<domain>/<ip>`
		// has a literal `/` after `server=` — keep those.
		if strings.HasPrefix(trimmed, "server=") && !strings.HasPrefix(trimmed, "server=/") {
			lines = append(lines, "# stripped by netfilterd (global upstream defeats default-deny): "+trimmed)
			changed = true
			continue
		}

		// Recognise the `no-resolv` directive as the first whitespace-
		// separated token; this matches the bare form AND the
		// "no-resolv  # comment" form this function writes. Dedupe to one.
		fields := strings.Fields(trimmed)
		if len(fields) >= 1 && fields[0] == "no-resolv" {
			if seenNoResolv {
				changed = true // drop the duplicate
				continue
			}
			seenNoResolv = true
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	if !seenNoResolv {
		lines = append(lines, "no-resolv  # added by netfilterd — no fallback to /etc/resolv.conf")
		changed = true
	}
	if !changed {
		return false, nil
	}
	out := strings.Join(lines, "\n") + "\n"
	return true, os.WriteFile(path, []byte(out), 0644)
}

// stripLoopbackFromResolv removes `nameserver 127.0.0.1` (and IPv6
// loopback) from /etc/resolv.conf so the Pi's own processes don't route
// through the local default-deny dnsmasq. Returns true if the file
// changed.
func stripLoopbackFromResolv(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var lines []string
	changed := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		t := strings.Fields(strings.TrimSpace(line))
		if len(t) == 2 && t[0] == "nameserver" && (t[1] == "127.0.0.1" || t[1] == "::1") {
			changed = true
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// buildDNSConfig renders the default-deny dnsmasq config: `address=/#/0.0.0.0`
// sinkholes every name to 0.0.0.0; a `server=/` line per allow-listed
// domain lets only those resolve. A domain on the protected-deny floor
// is dropped even if it appears in a filter — it stays sinkholed.
// connman always resolves (the :80 captive-check spoof depends on it).
// Open devices are handed a public DNS via a per-tag DHCP option so the
// default-deny does not restrict them. Pure — no I/O — so it is
// unit-testable.
//
// 0.0.0.0 over NXDOMAIN — the empirical reason: Tier-4 (Tesla connected)
// showed NXDOMAIN-on-everything makes the Tesla cycle "online/captive"
// every few seconds. connman keeps checking and any negative for the
// captive host destabilises the whole "online" state. Sinkholing to
// 0.0.0.0 instead returns *a* record (just an unrouteable one), the
// connman spoof at :80 still answers 200 OK on its own captive name, and
// the car settles. The `server=/<specific>/` overrides correctly beat
// the `#` wildcard in this dnsmasq version regardless of the rdata.
func buildDNSConfig(upstreams, allowedDomains, openMACs []string) string {
	var b strings.Builder
	b.WriteString("# Generated by netfilterd — do not edit\n")
	b.WriteString("# Default-deny DNS: only filter-enabled domains resolve; everything\n")
	b.WriteString("# else is sinkholed to 0.0.0.0. Extra-defense layer behind the SNI proxy.\n\n")
	b.WriteString("address=/#/0.0.0.0\n\n")

	b.WriteString("# connman captive-check — must resolve for the spoof to work\n")
	for _, up := range upstreams {
		fmt.Fprintf(&b, "server=/%s/%s\n", spoofConnManHost, up)
	}

	b.WriteString("\n# Filter allow-list — resolve via upstream\n")
	for _, d := range allowedDomains {
		if isProtectedDenied(d) {
			// A protected endpoint never gets a server= line — it stays
			// sinkholed by address=/#/ even if it slipped into a filter.
			continue
		}
		for _, up := range upstreams {
			fmt.Fprintf(&b, "server=/%s/%s\n", d, up)
		}
	}

	if len(openMACs) > 0 {
		b.WriteString("\n# Open devices — handed public DNS, bypass the default-deny resolver\n")
		for _, mac := range openMACs {
			fmt.Fprintf(&b, "dhcp-host=%s,set:open\n", mac)
		}
		fmt.Fprintf(&b, "dhcp-option=tag:open,6,%s\n", strings.Join(upstreams, ","))
	}
	return b.String()
}

// Apply writes /etc/dnsmasq.d/netfilter-dns.conf from buildDNSConfig and
// restarts dnsmasq (restart, not reload — SIGHUP does not re-read
// /etc/dnsmasq.d/*.conf).
func (s *DNSService) Apply() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	domains, err := s.allowedDomains()
	if err != nil {
		return fmt.Errorf("query allow-list domains: %w", err)
	}
	openMACs, err := s.openDeviceMACs()
	if err != nil {
		return fmt.Errorf("query open devices: %w", err)
	}
	conf := buildDNSConfig(splitUpstreams(s.cfg.DNSUpstream), domains, openMACs)

	const confPath = "/etc/dnsmasq.d/netfilter-dns.conf"
	os.Remove("/etc/dnsmasq.d/blocklist.conf") // legacy V2 file
	if err := os.WriteFile(confPath, []byte(conf), 0644); err != nil {
		if !s.exec.DryRun {
			return fmt.Errorf("write %s: %w", confPath, err)
		}
		log.Printf("[DRY-RUN] Would write %s", confPath)
	}
	if _, err := s.exec.Run("systemctl", "restart", "dnsmasq"); err != nil {
		return fmt.Errorf("restart dnsmasq: %w", err)
	}

	log.Printf("[DNS] default-deny config applied: %d allow-listed domains, %d open devices", len(domains), len(openMACs))
	return nil
}

// allowedDomains is the GLOBAL union of every enabled filter_domain
// across every filter whose own enabled flag is on. Filters are no
// longer per-device — when a filter is on, every filtered device sees
// every enabled domain inside it.
func (s *DNSService) allowedDomains() ([]string, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT fd.domain
		FROM filter_domains fd
		JOIN filters f ON f.id = fd.preset_id
		WHERE fd.enabled = 1 AND f.enabled = 1
		ORDER BY fd.domain ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" && ValidDomain(d) {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

// openDeviceMACs returns the MACs of devices with status='open' — they
// get a public DNS upstream via DHCP option, bypassing the default-deny
// resolver entirely.
func (s *DNSService) openDeviceMACs() ([]string, error) {
	rows, err := s.db.Query(`SELECT mac_address FROM devices WHERE status = 'open'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		if m = strings.ToLower(strings.TrimSpace(m)); ValidMAC(m) {
			out = append(out, m)
		}
	}
	return out, rows.Err()
}

func splitUpstreams(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = []string{"1.1.1.1"}
	}
	return out
}
