package services

import (
	"database/sql"
	"log"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

type Services struct {
	Auth       *AuthService
	Network    *NetworkService
	Firewall   *FirewallService
	DNS        *DNSService
	Blocked    *BlockedService
	Bandwidth  *BandwidthService
	Hotspot    *HotspotService
	System     *SystemService
	Audit      *AuditService
	TrafficLog *TrafficLogService
	Policy     *PolicyService
}

func New(db *sql.DB, exec *executor.Executor, cfg config.Config) *Services {
	audit := NewAuditService(db)
	trafficLog := NewTrafficLogService(db)
	blocked := NewBlockedService(db)
	policy := NewPolicyService(db, blocked)
	return &Services{
		Auth:       NewAuthService(db),
		Network:    NewNetworkService(db, cfg),
		Firewall:   NewFirewallService(db, exec, cfg, blocked, policy),
		DNS:        NewDNSService(db, exec, blocked),
		Blocked:    blocked,
		Bandwidth:  NewBandwidthService(db, exec, cfg),
		Hotspot:    NewHotspotService(db, exec),
		System:     NewSystemService(exec, cfg),
		Audit:      audit,
		TrafficLog: trafficLog,
		Policy:     policy,
	}
}

func (s *Services) ApplyAll() {
	if err := s.Firewall.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply firewall rules: %v", err)
	}
	if err := s.DNS.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply DNS blocklist: %v", err)
	}
	if err := s.Bandwidth.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply bandwidth limits: %v", err)
	}
	if err := s.Hotspot.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply hotspot config: %v", err)
	}
}
