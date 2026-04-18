package models

import "time"

// Policy represents a named allow-list policy that devices can be assigned to.
// Mode controls what happens to traffic destined for an IP not in the policy's
// allow set: "permissive" falls through to the default policy's set;
// "strict" drops outright. Devices unassigned to any policy inherit the
// policy marked IsDefault.
type Policy struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Mode        string    `json:"mode"` // "permissive" | "strict"
	Description string    `json:"description"`
	IsDefault   bool      `json:"is_default"`
	CreatedAt   time.Time `json:"created_at"`
}

// PolicyDomain is an allow-list entry scoped to a single policy. Resolved IPs
// and hit-count metadata are maintained by the re-resolve cron so the UI can
// show "is this rule actually working?" without guessing.
type PolicyDomain struct {
	ID             int64     `json:"id"`
	PolicyID       int64     `json:"policy_id"`
	Domain         string    `json:"domain"`
	Description    string    `json:"description"`
	Enabled        bool      `json:"enabled"`
	ResolvedIPs    string    `json:"resolved_ips"` // JSON-encoded []string
	LastResolvedAt *time.Time `json:"last_resolved_at,omitempty"`
	HitCount       int64     `json:"hit_count"`
	CreatedAt      time.Time `json:"created_at"`
}

// DevicePolicy pins a single MAC to a single policy. Devices without a row
// here fall back to the default policy.
type DevicePolicy struct {
	DeviceMAC  string    `json:"device_mac"`
	PolicyID   int64     `json:"policy_id"`
	PolicyName string    `json:"policy_name,omitempty"`
	AssignedAt time.Time `json:"assigned_at"`
}
