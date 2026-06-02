package services

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

type NetworkService struct {
	db  *sql.DB
	cfg config.Config
}

func NewNetworkService(db *sql.DB, cfg config.Config) *NetworkService {
	return &NetworkService{db: db, cfg: cfg}
}

func (s *NetworkService) StartScanner() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Run once immediately
	s.scan()

	for range ticker.C {
		s.scan()
	}
}

func (s *NetworkService) scan() {
	devices := make(map[string]*models.Device)

	// Parse DHCP leases
	s.parseDHCPLeases(devices)

	// Parse ARP table
	s.parseARP(devices)

	// Upsert to database
	for _, dev := range devices {
		s.upsertDevice(dev)
	}

	// Mark devices not seen in 5 minutes as offline (handled at query time via last_seen)
}

func (s *NetworkService) parseDHCPLeases(devices map[string]*models.Device) {
	f, err := os.Open("/var/lib/misc/dnsmasq.leases")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// Format: expiry MAC IP hostname *
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		mac := strings.ToUpper(fields[1])
		ip := fields[2]
		hostname := fields[3]
		if hostname == "*" {
			hostname = ""
		}

		devices[mac] = &models.Device{
			MACAddress: mac,
			IPAddress:  ip,
			Hostname:   hostname,
		}
	}
}

func (s *NetworkService) parseARP(devices map[string]*models.Device) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return
	}
	defer f.Close()
	mergeARP(devices, f, s.cfg.LANInterface)
}

// mergeARP reads /proc/net/arp content from r and merges live ARP entries
// into devices, restricted to lanIface. Split from parseARP so the merge
// rules (live ARP overrides stale leases-file IP; skip Flags=0x0
// incomplete; reject null/invalid MAC) are unit-testable without faking
// the filesystem.
func mergeARP(devices map[string]*models.Device, r io.Reader, lanIface string) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // skip header

	for scanner.Scan() {
		// Format: IP HWtype Flags HWaddress Mask Device
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		if fields[5] != lanIface {
			continue
		}
		// Flags=0x0 means "incomplete" — the kernel has an IP slot but
		// no resolved MAC yet. The HWaddress column on those rows is
		// 00:00:00:00:00:00, and they'd otherwise look like a real
		// device with a null MAC. Drop them up front.
		if fields[2] == "0x0" {
			continue
		}
		mac := strings.ToUpper(fields[3])
		ip := fields[0]

		// Defensive: also reject explicit 00:00... in case Flags != 0x0
		// but the MAC slot is somehow still null (kernel oddity on some
		// drivers). Migration v17 cleans up any that are already in the
		// DB from the pre-fix era.
		if mac == "" || mac == "00:00:00:00:00:00" || !ValidMAC(strings.ToLower(mac)) {
			continue
		}

		if existing, ok := devices[mac]; ok {
			// Live ARP wins the IP race over the dnsmasq leases file:
			// /proc/net/arp reflects actual current packets to/from the
			// MAC right now, while the leases file can hold a stale IP
			// across a reconnect (the row stays until the lease expires
			// or is explicitly evicted). Without this override, deleting
			// a device row and watching it reappear would resurrect the
			// OLD IP from the leases file every scan tick, even though
			// the kernel is forwarding packets to the new IP. Keep the
			// hostname we got from DHCP though — ARP has no hostname.
			existing.IPAddress = ip
		} else {
			devices[mac] = &models.Device{
				MACAddress: mac,
				IPAddress:  ip,
			}
		}
	}
}

func (s *NetworkService) upsertDevice(dev *models.Device) {
	// New devices land as 'blocked' — the forward chain hard-drops their
	// traffic until the operator explicitly classifies them as Filtered
	// or Open in the UI. The ON CONFLICT clause leaves the status of
	// an existing row alone, so a deliberately-classified device keeps
	// its status across DHCP renewals or ARP refreshes.
	_, err := s.db.Exec(`
		INSERT INTO devices (mac_address, ip_address, hostname, status, last_seen)
		VALUES (?, ?, ?, 'blocked', CURRENT_TIMESTAMP)
		ON CONFLICT(mac_address) DO UPDATE SET
			ip_address = excluded.ip_address,
			hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
			last_seen = CURRENT_TIMESTAMP
	`, dev.MACAddress, dev.IPAddress, dev.Hostname)
	if err != nil {
		log.Printf("[WARN] Failed to upsert device %s: %v", dev.MACAddress, err)
	}
}

func (s *NetworkService) ListDevices() ([]models.Device, error) {
	rows, err := s.db.Query(`
		SELECT id, mac_address, ip_address, hostname, alias, first_seen, last_seen,
			status, is_blocked, ignore_traffic_log,
			CASE WHEN last_seen > datetime('now', '-5 minutes') THEN 1 ELSE 0 END as online
		FROM devices ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query devices: %w", err)
	}
	defer rows.Close()

	var devices []models.Device
	for rows.Next() {
		var d models.Device
		var blocked, ignoreLog, online int
		if err := rows.Scan(&d.ID, &d.MACAddress, &d.IPAddress, &d.Hostname, &d.Alias,
			&d.FirstSeen, &d.LastSeen, &d.Status, &blocked, &ignoreLog, &online); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		d.IsBlocked = blocked == 1
		d.IgnoreTrafficLog = ignoreLog == 1
		d.Online = online == 1
		devices = append(devices, d)
	}
	return devices, nil
}

// SetStatus updates a device's classification. Must be one of the
// models.DeviceStatus* constants (blocked, filtered, open). Anything else
// is rejected.
func (s *NetworkService) SetStatus(mac, status string) error {
	mac = strings.ToUpper(strings.TrimSpace(mac))
	if !ValidMAC(strings.ToLower(mac)) {
		return fmt.Errorf("invalid mac %q", mac)
	}
	switch status {
	case models.DeviceStatusBlocked, models.DeviceStatusFiltered, models.DeviceStatusOpen:
	default:
		return fmt.Errorf("invalid status %q (must be blocked, filtered, or open)", status)
	}
	// Keep the legacy is_blocked column in lockstep so anything still
	// reading it sees a consistent view.
	blocked := 0
	if status == models.DeviceStatusBlocked {
		blocked = 1
	}
	_, err := s.db.Exec(
		"UPDATE devices SET status = ?, is_blocked = ? WHERE mac_address = ?",
		status, blocked, mac,
	)
	if err != nil {
		return fmt.Errorf("set status on %s: %w", mac, err)
	}
	return nil
}

// Delete hard-removes a device row by MAC. After deletion, the device is
// indistinguishable from one that has never been seen — if it reconnects,
// the network scanner re-inserts it with the schema default status
// ('blocked'), so it gets dropped by the forward chain until the operator
// explicitly reclassifies it.
func (s *NetworkService) Delete(mac string) error {
	mac = strings.ToUpper(strings.TrimSpace(mac))
	if !ValidMAC(strings.ToLower(mac)) {
		return fmt.Errorf("invalid mac %q", mac)
	}
	res, err := s.db.Exec("DELETE FROM devices WHERE mac_address = ?", mac)
	if err != nil {
		return fmt.Errorf("delete device %s: %w", mac, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("device %s not found", mac)
	}
	return nil
}

// DeviceIPByMAC returns the device's last-known IP, or "" if no row exists.
// Used by the traffic-log wipe to also delete DNS rows tagged by client_ip
// (DNS events don't carry a MAC).
func (s *NetworkService) DeviceIPByMAC(mac string) string {
	var ip string
	if err := s.db.QueryRow("SELECT ip_address FROM devices WHERE mac_address = ?", mac).Scan(&ip); err != nil {
		return ""
	}
	return ip
}

// UpdateDevice updates per-device metadata that isn't part of the status
// classification: alias and the traffic-log mute flag. To change a device's
// status use SetStatus.
func (s *NetworkService) UpdateDevice(mac, alias string, ignoreTrafficLog bool) error {
	ignoreInt := 0
	if ignoreTrafficLog {
		ignoreInt = 1
	}
	_, err := s.db.Exec(
		"UPDATE devices SET alias = ?, ignore_traffic_log = ? WHERE mac_address = ?",
		alias, ignoreInt, mac,
	)
	if err != nil {
		return fmt.Errorf("update device %s: %w", mac, err)
	}
	return nil
}

func (s *NetworkService) GetDeviceCount() (online, total int, err error) {
	err = s.db.QueryRow(`
		SELECT
			COUNT(*) as total,
			SUM(CASE WHEN last_seen > datetime('now', '-5 minutes') THEN 1 ELSE 0 END) as online
		FROM devices
	`).Scan(&total, &online)
	return
}
