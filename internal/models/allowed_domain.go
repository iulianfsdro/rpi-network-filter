package models

import "time"

type AllowedDomain struct {
	ID          int64     `json:"id"`
	Domain      string    `json:"domain"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}
