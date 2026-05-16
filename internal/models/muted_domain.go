package models

import "time"

// MutedDomain is a pattern whose traffic events are dropped at ingest so
// they never reach query_log or the traffic monitor. Logging-only — it
// changes no network behaviour (unlike BlockedDomain).
type MutedDomain struct {
	ID        int64     `json:"id"`
	Pattern   string    `json:"pattern"`
	MatchType string    `json:"match_type"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}
