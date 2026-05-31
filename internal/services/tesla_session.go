// tesla_session.go — raw byte-forwarder over an active BLE connection.
//
// V4.4 Phase 3b of the BLE-key rearchitecture. With the client now
// holding its own non-extractable WebCrypto P-256 keypair (Phase 3a),
// it can derive a Tesla session key locally — but it still needs the
// Pi's BLE radio to actually talk to the car. This file is that
// bridge: open a BLE session, exchange raw protobuf bytes, close.
// The Pi never inspects the bytes, never decrypts them, never holds
// a session key — they're opaque RoutableMessage frames.
//
// Concurrency model:
//
//   * Linux can host only one BLE adapter client at a time, and the
//     SDK's session state isn't thread-safe under interleaving. So
//     exactly ONE BLE session is alive at any moment, enforced by
//     TeslaService.bleMu (acquired in AcquireBLEForVIN, released in
//     the session's close callback).
//
//   * While a session is open, the existing /api/ble/cmd/* path
//     blocks on bleMu — first one wins, second waits until the first
//     calls Close (or the idle reaper does it). The "either / or"
//     property survives because both paths route through bleMu.
//
//   * Idle TTL: 5 min from last Exchange. After that the reaper
//     force-closes and releases bleMu so a stuck client never
//     livelocks the BLE adapter.
//
// Phase 3c will port the Tesla session crypto (P-256 ECDH against the
// car's ephemeral pubkey from SessionInfo, AES-GCM under the derived
// key, HMAC counter) into TypeScript. The wire shape on this file
// stays the same: client posts bytes, gets bytes back.
package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/connector/ble"
)

// bleSessionTTL is how long a session can sit idle before the reaper
// closes it. 5 min matches Tesla's own BLE session timeout window
// reasonably well — long enough for a multi-command UX flow, short
// enough that a stuck client doesn't pin the BLE adapter overnight.
const bleSessionTTL = 5 * time.Minute

// bleSessionDefaultTimeout is the per-Exchange wait if the caller
// doesn't pass timeout_ms. Tesla BLE round-trips are usually 300-800
// ms; 5 s is a generous upper bound that catches transient stalls
// without holding the HTTP request open absurdly long.
const bleSessionDefaultTimeout = 5 * time.Second

// bleSessionMaxTimeout caps per-Exchange waits so a misbehaving
// client can't tie up the BLE radio + HTTP worker indefinitely.
const bleSessionMaxTimeout = 30 * time.Second

// BLESession is the public-facing description returned by Open. The
// raw connection is intentionally NOT exported — Exchange / Close are
// the only operations external callers can perform.
type BLESession struct {
	ID  string `json:"session_id"`
	VIN string `json:"vin"`
}

// internalSession is the live bookkeeping for one open BLE link.
type internalSession struct {
	id        string
	vin       string
	conn      *ble.Connection
	release   func() // closes conn + releases TeslaService.bleMu
	createdAt time.Time
	lastUsed  time.Time
}

// BLESessionService manages the at-most-one active BLE session. Held
// by services.Services; consumed by the /api/ble/sessions handlers.
//
// Construction needs a TeslaService reference because Open routes
// through AcquireBLEForVIN. We don't embed TeslaService — composition,
// not inheritance, so the public surface stays narrow.
type BLESessionService struct {
	tesla *TeslaService

	mu       sync.Mutex
	sessions map[string]*internalSession // 0 or 1 entries; bleMu serialises
}

// NewBLESessionService wires the service.
func NewBLESessionService(t *TeslaService) *BLESessionService {
	return &BLESessionService{
		tesla:    t,
		sessions: make(map[string]*internalSession),
	}
}

// Sentinel errors so handlers can map to HTTP codes precisely.
var (
	ErrBLESessionNotFound = errors.New("BLE session not found")
	ErrBLESessionTimeout  = errors.New("BLE session exchange timed out waiting for response")
)

// Open scans for the given VIN and opens a fresh BLE connection. If
// vin is empty, falls back to TeslaService's configured VIN. Returns
// the session metadata on success — the caller drives subsequent
// Exchange + Close by session ID.
//
// Holds bleMu for the session's lifetime. If a session already exists
// (forgotten by a previous client), Open blocks on bleMu until that
// session is reaped — there's no "take over" semantic because we
// don't know whether the previous client is mid-command.
func (s *BLESessionService) Open(ctx context.Context, vin string) (*BLESession, error) {
	if vin == "" {
		v, err := s.tesla.RequireVIN()
		if err != nil {
			return nil, err
		}
		vin = v
	}

	conn, release, err := s.tesla.AcquireBLEForVIN(ctx, vin)
	if err != nil {
		return nil, err
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		release()
		return nil, fmt.Errorf("session id: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	now := time.Now()
	sess := &internalSession{
		id:        id,
		vin:       vin,
		conn:      conn,
		release:   release,
		createdAt: now,
		lastUsed:  now,
	}

	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()

	log.Printf("[BLE-SESSION] opened %s (vin=%s)", id, vin)
	go s.reaper(id)

	return &BLESession{ID: id, VIN: vin}, nil
}

// Exchange sends payload over the BLE link and waits up to timeout
// for one response frame. Caller is responsible for the payload
// being a well-formed RoutableMessage — the Pi doesn't parse it.
//
// The "one response" semantic is right for command/state-read RPCs
// (which is what 99% of the protocol consists of). For commands that
// trigger multiple async responses, the client calls Exchange again
// with an empty payload and a short timeout to drain — or, eventually,
// we add a streaming endpoint. For Phase 3b's purposes, this is enough.
//
// Updates lastUsed so the reaper's TTL clock resets.
func (s *BLESessionService) Exchange(ctx context.Context, id string, payload []byte, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = bleSessionDefaultTimeout
	}
	if timeout > bleSessionMaxTimeout {
		timeout = bleSessionMaxTimeout
	}

	sess, err := s.get(id)
	if err != nil {
		return nil, err
	}
	if err := sess.conn.Send(ctx, payload); err != nil {
		return nil, fmt.Errorf("BLE send: %w", err)
	}

	select {
	case resp, ok := <-sess.conn.Receive():
		if !ok {
			return nil, errors.New("BLE connection closed")
		}
		s.touch(id)
		return resp, nil
	case <-time.After(timeout):
		return nil, ErrBLESessionTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close removes the session, closes the BLE connection, and releases
// the adapter mutex. Idempotent — closing an unknown id returns
// ErrBLESessionNotFound, but the caller can treat that as "already
// cleaned up." Phase 3 client code does this in a finally{} block so
// stuck sessions are rare in practice.
func (s *BLESessionService) Close(id string) error {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return ErrBLESessionNotFound
	}
	delete(s.sessions, id)
	s.mu.Unlock()

	sess.release()
	log.Printf("[BLE-SESSION] closed %s (vin=%s, lifetime=%v)",
		id, sess.vin, time.Since(sess.createdAt))
	return nil
}

// get fetches a session by id with the map mutex held. Returns
// ErrBLESessionNotFound if no such id.
func (s *BLESessionService) get(id string) (*internalSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrBLESessionNotFound
	}
	return sess, nil
}

// touch updates lastUsed on the named session. Used by Exchange to
// keep the reaper from killing an actively-used session.
func (s *BLESessionService) touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.lastUsed = time.Now()
	}
}

// reaper background-closes the session if it sits idle past
// bleSessionTTL. Recomputes the wake time from lastUsed each cycle so
// an active session never gets killed mid-conversation. Exits once
// the session is gone — either reaped here or closed externally.
func (s *BLESessionService) reaper(id string) {
	for {
		s.mu.Lock()
		sess, ok := s.sessions[id]
		if !ok {
			s.mu.Unlock()
			return
		}
		idle := time.Since(sess.lastUsed)
		if idle >= bleSessionTTL {
			delete(s.sessions, id)
			s.mu.Unlock()
			sess.release()
			log.Printf("[BLE-SESSION] reaped %s (idle %v)", id, idle)
			return
		}
		// Wake up just after the next deadline.
		wait := bleSessionTTL - idle + time.Second
		s.mu.Unlock()
		time.Sleep(wait)
	}
}
