package models

import "time"

// Filter is a named bundle of allow-listed domains. A filter is GLOBAL:
// when its Enabled flag is true, every domain it contains (whose own
// per-domain enabled flag is also true) applies to every device with
// status='filtered'. There is no per-device attachment — the operator
// toggles a filter on or off for the whole network.
//
// System filters (IsSystem=true) ship with the binary and represent
// curated, audited bundles for common services — Tesla AP/Nav, YouTube,
// Netflix, Disney+. They can still be edited or extended by the operator.
// User filters (IsSystem=false) are created in the UI.
type Filter struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// FilterDomain is one allow-list entry inside a filter. New rows are
// inserted disabled by default (review-then-enable). The protected-deny
// floor rejects inserts whose hostname matches a known-bad Tesla endpoint,
// and ancestor rejects refuse a broad parent whose suffix would re-admit
// one. The description column is enforced at the service layer to be
// non-empty — every entry needs a justification.
//
// The PresetID JSON field keeps its legacy name in the wire format and
// in the underlying preset_id column (renaming would force a full table
// rebuild for a cosmetic gain). It refers to filters.id.
type FilterDomain struct {
	ID             int64      `json:"id"`
	FilterID       int64      `json:"preset_id"` // legacy column name; UI calls it filter_id
	Domain         string     `json:"domain"`
	Description    string     `json:"description"`
	Enabled        bool       `json:"enabled"`
	ResolvedIPs    string     `json:"resolved_ips"`
	LastResolvedAt *time.Time `json:"last_resolved_at,omitempty"`
	HitCount       int64      `json:"hit_count"`
	CreatedAt      time.Time  `json:"created_at"`
}
