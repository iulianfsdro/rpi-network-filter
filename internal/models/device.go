package models

import "time"

// DeviceStatus enumerates how the firewall treats a device's forwarded
// traffic. Surfaced in the UI as the "Traffic" column. There are exactly
// three values; new devices appear as Blocked by default — anything
// without explicit operator approval gets nothing.
const (
	DeviceStatusBlocked  = "blocked"  // forward chain hard-drops everything
	DeviceStatusFiltered = "filtered" // SNI-gated by the union of enabled filters
	DeviceStatusOpen     = "open"     // bypass — forward accept + DNS DNAT to upstream
)

type Device struct {
	ID               int64     `json:"id"`
	MACAddress       string    `json:"mac_address"`
	IPAddress        string    `json:"ip_address"`
	Hostname         string    `json:"hostname"`
	Alias            string    `json:"alias"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	Status           string    `json:"status"` // unknown | filtered | trusted | blocked
	IsBlocked        bool      `json:"is_blocked"`
	Online           bool      `json:"online"`
	IgnoreTrafficLog bool      `json:"ignore_traffic_log"`
}
