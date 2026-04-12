package models

import "time"

type DNSBlockEntry struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	Category  string    `json:"category"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}
