package services

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	db *sql.DB
}

func NewAuthService(db *sql.DB) *AuthService {
	return &AuthService{db: db}
}

func (s *AuthService) CreateUser(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	_, err = s.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hash))
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

func (s *AuthService) ResetPassword(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	result, err := s.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", string(hash), username)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user '%s' not found", username)
	}

	return nil
}

func (s *AuthService) Login(username, password string) (string, error) {
	var user models.User
	err := s.db.QueryRow(
		"SELECT id, username, password_hash FROM users WHERE username = ?", username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("invalid credentials")
	}
	if err != nil {
		return "", fmt.Errorf("query user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", fmt.Errorf("invalid credentials")
	}

	token, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = s.db.Exec(
		"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		token, user.ID, expiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}

	return token, nil
}

func (s *AuthService) ValidateSession(token string) (*models.User, error) {
	var user models.User
	var expiresAt time.Time

	err := s.db.QueryRow(`
		SELECT u.id, u.username, s.expires_at
		FROM sessions s JOIN users u ON s.user_id = u.id
		WHERE s.token = ?
	`, token).Scan(&user.ID, &user.Username, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid session")
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}

	if time.Now().After(expiresAt) {
		s.db.Exec("DELETE FROM sessions WHERE token = ?", token)
		return nil, fmt.Errorf("session expired")
	}

	return &user, nil
}

func (s *AuthService) Logout(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

func (s *AuthService) CleanExpiredSessions() {
	s.db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
