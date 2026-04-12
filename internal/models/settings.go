package models

import "time"

type Setting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type AuditLog struct {
	ID        int64     `json:"id"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}
