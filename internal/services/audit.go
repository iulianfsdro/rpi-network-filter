package services

import (
	"database/sql"
	"fmt"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

type AuditService struct {
	db *sql.DB
}

func NewAuditService(db *sql.DB) *AuditService {
	return &AuditService{db: db}
}

func (s *AuditService) Log(action, details string) {
	s.db.Exec("INSERT INTO audit_log (action, details) VALUES (?, ?)", action, details)
}

func (s *AuditService) Recent(limit int) ([]models.AuditLog, error) {
	rows, err := s.db.Query(
		"SELECT id, action, details, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?", limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var entry models.AuditLog
		if err := rows.Scan(&entry.ID, &entry.Action, &entry.Details, &entry.Timestamp); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		logs = append(logs, entry)
	}
	return logs, nil
}
