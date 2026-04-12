package services

import (
	"bufio"
	"database/sql"
	"fmt"
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

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		// Format: IP HWtype Flags HWaddress Mask Device
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		if fields[5] != s.cfg.LANInterface {
			continue
		}
		mac := strings.ToUpper(fields[3])
		ip := fields[0]

		if _, exists := devices[mac]; !exists {
			devices[mac] = &models.Device{
				MACAddress: mac,
				IPAddress:  ip,
			}
		}
	}
}

func (s *NetworkService) upsertDevice(dev *models.Device) {
	_, err := s.db.Exec(`
		INSERT INTO devices (mac_address, ip_address, hostname, last_seen)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
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
		SELECT id, mac_address, ip_address, hostname, alias, first_seen, last_seen, is_blocked,
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
		var blocked, online int
		if err := rows.Scan(&d.ID, &d.MACAddress, &d.IPAddress, &d.Hostname, &d.Alias,
			&d.FirstSeen, &d.LastSeen, &blocked, &online); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		d.IsBlocked = blocked == 1
		d.Online = online == 1
		devices = append(devices, d)
	}
	return devices, nil
}

func (s *NetworkService) UpdateDevice(mac, alias string, blocked bool) error {
	blockedInt := 0
	if blocked {
		blockedInt = 1
	}
	_, err := s.db.Exec(
		"UPDATE devices SET alias = ?, is_blocked = ? WHERE mac_address = ?",
		alias, blockedInt, mac,
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
