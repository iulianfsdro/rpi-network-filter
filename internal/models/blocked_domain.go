package models

import "time"

type BlockedDomain struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	MatchType string    `json:"match_type"`
	Reason    string    `json:"reason"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}
