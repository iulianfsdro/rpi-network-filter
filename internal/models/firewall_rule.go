package models

import "time"

type FirewallRule struct {
	ID          int64     `json:"id"`
	Description string    `json:"description"`
	Direction   string    `json:"direction"`
	Protocol    string    `json:"protocol"`
	SourceIP    string    `json:"source_ip"`
	DestIP      string    `json:"dest_ip"`
	DestPort    string    `json:"dest_port"`
	Action      string    `json:"action"`
	DeviceMAC   string    `json:"device_mac"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	CreatedAt   time.Time `json:"created_at"`
}
