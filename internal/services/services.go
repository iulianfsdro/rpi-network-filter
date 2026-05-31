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
	Bandwidth  *BandwidthService
	Hotspot    *HotspotService
	System     *SystemService
	Audit      *AuditService
	TrafficLog *TrafficLogService
	Filter     *FilterService
	Spoof      *SpoofService
	SNIProxy   *SNIProxyService
	Tesla       *TeslaService
	TeslaToken  *TeslaTokenService
	BLESession  *BLESessionService
	Remote      *RemoteService
}

func New(db *sql.DB, exec *executor.Executor, cfg config.Config) *Services {
	audit := NewAuditService(db)
	trafficLog := NewTrafficLogService(db)
	filter := NewFilterService(db)
	network := NewNetworkService(db, cfg)
	tesla := NewTeslaService(db, audit)
	return &Services{
		Auth:       NewAuthService(db),
		Network:    network,
		Firewall:   NewFirewallService(db, exec, cfg),
		DNS:        NewDNSService(db, exec, cfg),
		Bandwidth:  NewBandwidthService(db, exec, cfg),
		Hotspot:    NewHotspotService(db, exec),
		System:     NewSystemService(exec, cfg),
		Audit:      audit,
		TrafficLog: trafficLog,
		Filter:     filter,
		Spoof:      NewSpoofService(cfg, exec),
		SNIProxy:   NewSNIProxyService(cfg, db, trafficLog),
		Tesla:      tesla,
		TeslaToken: NewTeslaTokenService(db),
		BLESession: NewBLESessionService(tesla),
		Remote:     NewRemoteService(),
	}
}

func (s *Services) ApplyAll() {
	if err := s.Firewall.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply firewall rules: %v", err)
	}
	if err := s.DNS.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply DNS config: %v", err)
	}
	if err := s.Bandwidth.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply bandwidth limits: %v", err)
	}
	if err := s.Hotspot.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply hotspot config: %v", err)
	}
}
