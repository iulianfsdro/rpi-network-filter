// tesla_token.go — bearer-token management for /api/ble/*.
//
// V4.4 Phase 1. The byte-forwarder API is reachable over Tailscale
// Funnel (eventually) and so cannot rely on session cookies. Each
// enrolled client device gets a single high-entropy bearer; the
// plaintext is shown exactly once at issue time and stored only as a
// SHA-256 hash. Audit columns (created_at, last_used_at, revoked_at)
// let an operator triage a leak without losing history.
package services

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// teslaTokenBytes is the size of the underlying random seed for a
// bearer. 32 bytes = 256 bits of entropy; base64-url encodes to 43
// characters. Brute-forcing this online against a rate-limited public
// endpoint is computationally infeasible.
const teslaTokenBytes = 32

// TeslaClientToken is the public-facing description of a single bearer.
// The raw token text is NEVER stored in this struct after issuance — it
// only exists in the issue response.
type TeslaClientToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// TeslaTokenIssue is what IssueToken returns. Plaintext is shown to the
// operator once and not persisted.
type TeslaTokenIssue struct {
	Token TeslaClientToken `json:"token"`
	Plain string           `json:"plain"`
}

// TeslaTokenService is the CRUD + validation surface. Held by
// services.Services; the BLE bearer middleware uses Validate, the
// admin handlers use the rest.
type TeslaTokenService struct {
	db *sql.DB
}

// NewTeslaTokenService wires the service.
func NewTeslaTokenService(db *sql.DB) *TeslaTokenService {
	return &TeslaTokenService{db: db}
}

// Issue creates a new bearer with the given operator-supplied label.
// Returns the row metadata plus the plaintext token. Caller is
// responsible for delivering plain to the operator over a confidential
// channel (the issuing session itself, ideally — never logged, never
// echoed back to the API).
//
// The label is trimmed, length-bounded, and required. Two tokens may
// share a label — there's no UNIQUE constraint on name.
func (s *TeslaTokenService) Issue(name string) (*TeslaTokenIssue, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("token name cannot be empty")
	}
	if len(name) > 80 {
		return nil, errors.New("token name too long (max 80 chars)")
	}

	seed := make([]byte, teslaTokenBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("seed bearer: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(seed)
	hash := hashTeslaToken(plain)

	res, err := s.db.Exec(
		"INSERT INTO tesla_client_tokens (name, token_hash) VALUES (?, ?)",
		name, hash,
	)
	if err != nil {
		return nil, fmt.Errorf("insert token: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("token id: %w", err)
	}

	row, err := s.get(id)
	if err != nil {
		return nil, err
	}
	return &TeslaTokenIssue{Token: *row, Plain: plain}, nil
}

// List returns every token (active + revoked). The operator UI uses it
// to display the active set + revoke individual entries.
func (s *TeslaTokenService) List() ([]TeslaClientToken, error) {
	rows, err := s.db.Query(`
		SELECT id, name, created_at, last_used_at, revoked_at
		FROM tesla_client_tokens
		ORDER BY revoked_at IS NULL DESC, created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()

	var out []TeslaClientToken
	for rows.Next() {
		var t TeslaClientToken
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke flips revoked_at to now() for the given token id. Idempotent —
// revoking an already-revoked token is a no-op (revoked_at stays at
// its original timestamp). Returns ErrTokenNotFound if no such id.
func (s *TeslaTokenService) Revoke(id int64) error {
	res, err := s.db.Exec(
		"UPDATE tesla_client_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL",
		id,
	)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Could be "doesn't exist" or "already revoked" — distinguish.
		var exists int
		_ = s.db.QueryRow("SELECT COUNT(*) FROM tesla_client_tokens WHERE id = ?", id).Scan(&exists)
		if exists == 0 {
			return ErrTeslaTokenNotFound
		}
	}
	return nil
}

// Validate looks up a plaintext bearer by its hash. Returns the token
// row on success (active, not revoked) and bumps last_used_at. The
// returned name is what the bearer middleware stuffs into request
// context for audit-log attribution.
//
// Returns ErrTeslaTokenInvalid if no match OR the token is revoked.
// Distinguishing those two cases would leak which tokens exist, so we
// don't.
func (s *TeslaTokenService) Validate(plain string) (*TeslaClientToken, error) {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return nil, ErrTeslaTokenInvalid
	}
	hash := hashTeslaToken(plain)

	var t TeslaClientToken
	err := s.db.QueryRow(`
		SELECT id, name, created_at, last_used_at, revoked_at
		FROM tesla_client_tokens
		WHERE token_hash = ? AND revoked_at IS NULL`,
		hash,
	).Scan(&t.ID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt)
	if err == sql.ErrNoRows {
		return nil, ErrTeslaTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("validate token: %w", err)
	}

	// Best-effort touch — failure here doesn't deny access (the bearer
	// was still valid this instant), it just means the next "last used"
	// timestamp is slightly stale. The op-ux value of this column
	// (telling an operator which tokens are idle and safe to revoke) is
	// not worth coupling the auth fast-path to write availability.
	_, _ = s.db.Exec(
		"UPDATE tesla_client_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
		t.ID,
	)

	return &t, nil
}

func (s *TeslaTokenService) get(id int64) (*TeslaClientToken, error) {
	var t TeslaClientToken
	err := s.db.QueryRow(`
		SELECT id, name, created_at, last_used_at, revoked_at
		FROM tesla_client_tokens WHERE id = ?`,
		id,
	).Scan(&t.ID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt)
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	return &t, nil
}

// hashTeslaToken is the one-way function used to derive token_hash. We
// use plain SHA-256 (not bcrypt/argon) because the input is already a
// uniformly-random 256-bit secret — a slow KDF would buy nothing
// against an offline guess attempt, but would cost real latency on
// every API call. Hash is hex-encoded so the DB column stays
// human-readable.
func hashTeslaToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// Sentinel errors so handlers can map to HTTP codes precisely.
var (
	ErrTeslaTokenNotFound = errors.New("tesla client token not found")
	ErrTeslaTokenInvalid  = errors.New("tesla client token invalid or revoked")
)
