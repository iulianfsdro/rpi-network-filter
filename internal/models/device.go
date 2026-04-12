package models

import "time"

type Device struct {
	ID         int64     `json:"id"`
	MACAddress string    `json:"mac_address"`
	IPAddress  string    `json:"ip_address"`
	Hostname   string    `json:"hostname"`
	Alias      string    `json:"alias"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	IsBlocked  bool      `json:"is_blocked"`
	Online     bool      `json:"online"`
}
