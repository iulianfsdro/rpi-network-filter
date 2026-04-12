package services

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

type BandwidthService struct {
	db   *sql.DB
	exec *executor.Executor
	cfg  config.Config
	mu   sync.Mutex
}

func NewBandwidthService(db *sql.DB, exec *executor.Executor, cfg config.Config) *BandwidthService {
	return &BandwidthService{db: db, exec: exec, cfg: cfg}
}

func (s *BandwidthService) ListLimits() ([]models.BandwidthLimit, error) {
	rows, err := s.db.Query("SELECT id, device_mac, download_kbps, upload_kbps, enabled FROM bandwidth_limits")
	if err != nil {
		return nil, fmt.Errorf("query bandwidth limits: %w", err)
	}
	defer rows.Close()

	var limits []models.BandwidthLimit
	for rows.Next() {
		var l models.BandwidthLimit
		var enabled int
		if err := rows.Scan(&l.ID, &l.DeviceMAC, &l.DownloadKbps, &l.UploadKbps, &enabled); err != nil {
			return nil, fmt.Errorf("scan bandwidth limit: %w", err)
		}
		l.Enabled = enabled == 1
		limits = append(limits, l)
	}
	return limits, nil
}

func (s *BandwidthService) CreateLimit(l models.BandwidthLimit) (int64, error) {
	enabled := 0
	if l.Enabled {
		enabled = 1
	}
	result, err := s.db.Exec(`
		INSERT INTO bandwidth_limits (device_mac, download_kbps, upload_kbps, enabled)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(device_mac) DO UPDATE SET
			download_kbps = excluded.download_kbps,
			upload_kbps = excluded.upload_kbps,
			enabled = excluded.enabled
	`, l.DeviceMAC, l.DownloadKbps, l.UploadKbps, enabled)
	if err != nil {
		return 0, fmt.Errorf("insert bandwidth limit: %w", err)
	}
	return result.LastInsertId()
}

func (s *BandwidthService) UpdateLimit(id int64, l models.BandwidthLimit) error {
	enabled := 0
	if l.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(
		"UPDATE bandwidth_limits SET download_kbps=?, upload_kbps=?, enabled=? WHERE id=?",
		l.DownloadKbps, l.UploadKbps, enabled, id,
	)
	if err != nil {
		return fmt.Errorf("update bandwidth limit %d: %w", id, err)
	}
	return nil
}

func (s *BandwidthService) DeleteLimit(id int64) error {
	_, err := s.db.Exec("DELETE FROM bandwidth_limits WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete bandwidth limit %d: %w", id, err)
	}
	return nil
}

func (s *BandwidthService) Apply() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	iface := s.cfg.LANInterface

	// Clear existing qdiscs
	s.exec.Run("tc", "qdisc", "del", "dev", iface, "root")
	s.exec.Run("tc", "qdisc", "del", "dev", iface, "ingress")

	limits, err := s.ListLimits()
	if err != nil {
		return fmt.Errorf("list limits for apply: %w", err)
	}

	// Filter to enabled limits only
	var active []models.BandwidthLimit
	for _, l := range limits {
		if l.Enabled {
			active = append(active, l)
		}
	}

	if len(active) == 0 {
		log.Printf("[BANDWIDTH] No active limits, cleared qdiscs")
		return nil
	}

	// Setup root HTB qdisc for download (egress on wlan0 = download to clients)
	if _, err := s.exec.Run("tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "999"); err != nil {
		return fmt.Errorf("add root qdisc: %w", err)
	}

	// Default class (unlimited)
	if _, err := s.exec.Run("tc", "class", "add", "dev", iface, "parent", "1:", "classid", "1:999", "htb", "rate", "100mbit"); err != nil {
		return fmt.Errorf("add default class: %w", err)
	}

	// Per-device download classes
	for i, l := range active {
		classID := fmt.Sprintf("1:%d", i+1)
		rate := fmt.Sprintf("%dkbit", l.DownloadKbps)

		ip := s.getDeviceIP(l.DeviceMAC)
		if ip == "" {
			continue
		}

		if _, err := s.exec.Run("tc", "class", "add", "dev", iface, "parent", "1:", "classid", classID, "htb", "rate", rate, "ceil", rate); err != nil {
			log.Printf("[WARN] Failed to add class for %s: %v", l.DeviceMAC, err)
			continue
		}

		if _, err := s.exec.Run("tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1",
			"u32", "match", "ip", "dst", ip, "flowid", classID); err != nil {
			log.Printf("[WARN] Failed to add filter for %s: %v", l.DeviceMAC, err)
		}
	}

	// Upload limiting via IFB
	s.applyUploadLimits(iface, active)

	log.Printf("[BANDWIDTH] Applied %d bandwidth limits", len(active))
	return nil
}

func (s *BandwidthService) applyUploadLimits(iface string, limits []models.BandwidthLimit) {
	// Setup IFB device for ingress shaping
	s.exec.Run("ip", "link", "add", "ifb0", "type", "ifb")
	s.exec.Run("ip", "link", "set", "ifb0", "up")

	// Redirect ingress to IFB
	s.exec.Run("tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress")
	s.exec.Run("tc", "filter", "add", "dev", iface, "parent", "ffff:", "protocol", "ip",
		"u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", "ifb0")

	// HTB on IFB
	s.exec.Run("tc", "qdisc", "add", "dev", "ifb0", "root", "handle", "1:", "htb", "default", "999")
	s.exec.Run("tc", "class", "add", "dev", "ifb0", "parent", "1:", "classid", "1:999", "htb", "rate", "100mbit")

	for i, l := range limits {
		if l.UploadKbps <= 0 {
			continue
		}

		classID := fmt.Sprintf("1:%d", i+1)
		rate := fmt.Sprintf("%dkbit", l.UploadKbps)

		ip := s.getDeviceIP(l.DeviceMAC)
		if ip == "" {
			continue
		}

		s.exec.Run("tc", "class", "add", "dev", "ifb0", "parent", "1:", "classid", classID, "htb", "rate", rate, "ceil", rate)
		s.exec.Run("tc", "filter", "add", "dev", "ifb0", "parent", "1:", "protocol", "ip", "prio", "1",
			"u32", "match", "ip", "src", ip, "flowid", classID)
	}
}

func (s *BandwidthService) getDeviceIP(mac string) string {
	var ip string
	s.db.QueryRow("SELECT ip_address FROM devices WHERE mac_address = ?", strings.ToUpper(mac)).Scan(&ip)
	return ip
}
