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

// Exchange sends payload over the BLE link and returns the response
// frame addressed to the routing_address (or, when that's absent,
// the uuid) carried in the outgoing payload. Caller is responsible
// for the payload being a well-formed RoutableMessage — we DO peek
// at it (fields 7 and 51) to know what to match against on the way
// back.
//
// Why we demux rather than returning the first frame: in practice
// the car often pushes asynchronous frames (VCSEC unsolicited
// notifications, late responses to prior commands, fragmented
// responses split across BLE notifications) into the BLE receive
// channel. A naive "return next frame" semantic delivers those
// to the caller as if they were the response to the current request,
// the client's AES-GCM decrypt fails because the AAD's REQUEST_HASH
// doesn't match, and the user sees a perpetual "Pi returned stale
// response" / decrypt-failure loop with no way out. Filtering here
// is the actual fix; the client doesn't have enough information to
// recover this on its own (each retry just adds another late-frame
// to the queue).
//
// Why route_address is the primary correlator and not request_uuid:
// the upstream Tesla SDK (internal/dispatcher/dispatcher.go) uses
// a per-request random routing_address for VCSEC, and only sets
// request_uuid in responses for NON-VCSEC domains. VCSEC GET_STATUS
// replies (used by every closure/lock state read) come back with
// to_destination.routing_address set and request_uuid empty — so a
// uuid-only filter swallows them and Verify perpetually times out.
// Matching by to_destination.routing_address works for both VCSEC
// and Infotainment and for the SessionInfo handshake.
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

	// Extract correlators from our outgoing RoutableMessage:
	//   wantAddr = fromDestination.routing_address (field 7 → 2)
	//   wantUUID = uuid (field 51)
	// The car copies our fromDestination into the response's
	// toDestination, and (for non-VCSEC domains) our uuid into
	// request_uuid. Either is enough to claim the frame as ours.
	wantAddr := extractRoutableFromRoutingAddress(payload)
	wantUUID := extractRoutableUUID(payload)

	// Drain any stale frames sitting in the BLE receive channel
	// before sending the next request — late responses from prior
	// commands, VCSEC unsolicited broadcasts, fragments. Anything
	// currently buffered cannot be a response to a request we
	// haven't sent yet.
	for drained := 0; ; drained++ {
		select {
		case stale, ok := <-sess.conn.Receive():
			if !ok {
				return nil, errors.New("BLE connection closed before send")
			}
			log.Printf("[BLE-SESSION] drained stale frame %d bytes from %s (count=%d)", len(stale), id, drained+1)
			continue
		default:
		}
		break
	}

	if err := sess.conn.Send(ctx, payload); err != nil {
		return nil, fmt.Errorf("BLE send: %w", err)
	}

	deadline := time.After(timeout)
	for {
		select {
		case resp, ok := <-sess.conn.Receive():
			if !ok {
				return nil, errors.New("BLE connection closed")
			}
			// No correlators in the outgoing request → no
			// demuxing possible. Return the first frame. This
			// path is defensive; in normal operation an
			// outgoing RoutableMessage always carries at
			// least a routing_address.
			if len(wantAddr) == 0 && len(wantUUID) == 0 {
				s.touch(id)
				return resp, nil
			}
			gotAddr := extractRoutableToRoutingAddress(resp)
			gotUUID := extractRoutableRequestUUID(resp)
			addrMatch := len(wantAddr) != 0 && bytesEqual(gotAddr, wantAddr)
			uuidMatch := len(wantUUID) != 0 && bytesEqual(gotUUID, wantUUID)
			if addrMatch || uuidMatch {
				s.touch(id)
				return resp, nil
			}
			// Frame is either an unsolicited broadcast (no
			// matching correlator) or the response to a
			// previous request. Skip and keep reading.
			log.Printf("[BLE-SESSION] skipping %d-byte non-matching frame from %s (want_addr=%x want_uuid=%x got_addr=%x got_uuid=%x)",
				len(resp), id, wantAddr, wantUUID, gotAddr, gotUUID)
			continue
		case <-deadline:
			return nil, ErrBLESessionTimeout
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// extractRoutableUUID pulls field 51 (uuid, LEN) out of a
// RoutableMessage protobuf. Returns nil if not present.
//
// Tag for field 51 wire-type 2 (LEN): (51<<3)|2 = 410 = 0x9A 0x03
// varint-encoded.
func extractRoutableUUID(buf []byte) []byte {
	return scanProtoField(buf, 51, 2)
}

// extractRoutableRequestUUID pulls field 50 (request_uuid, LEN) out
// of a RoutableMessage protobuf. Returns nil if not present.
//
// Tag for field 50 wire-type 2 (LEN): (50<<3)|2 = 402 = 0x92 0x03
// varint-encoded.
func extractRoutableRequestUUID(buf []byte) []byte {
	return scanProtoField(buf, 50, 2)
}

// extractRoutableFromRoutingAddress pulls
// from_destination.routing_address out of a RoutableMessage.
// fromDestination is field 7 (Destination message, LEN); inside
// it, routing_address is field 2 of the Destination oneof.
//
// Returns nil if the sub-field isn't present (e.g. the Destination
// oneof picked `domain` instead of `routing_address`).
func extractRoutableFromRoutingAddress(buf []byte) []byte {
	from := scanProtoField(buf, 7, 2)
	if from == nil {
		return nil
	}
	return scanProtoField(from, 2, 2)
}

// extractRoutableToRoutingAddress pulls to_destination.routing_address
// out of a RoutableMessage. to_destination is field 6.
func extractRoutableToRoutingAddress(buf []byte) []byte {
	to := scanProtoField(buf, 6, 2)
	if to == nil {
		return nil
	}
	return scanProtoField(to, 2, 2)
}

// scanProtoField walks a top-level protobuf message looking for a
// specific (fieldNumber, wireType) tag and returns the bytes of the
// first matching LEN-type field. Skips unknown fields without
// recursing into sub-messages.
//
// Hand-rolled rather than using protobuf.Unmarshal because:
//  1. We don't want to pull a generated proto descriptor into the
//     byte-forwarder package, which is meant to be format-agnostic.
//  2. Decoding the full RoutableMessage would force us to track the
//     proto file across the upstream SDK, and we'd recompile every
//     time Tesla added a sub-message we don't care about. A 30-line
//     wire-format walker is cheap and stable.
func scanProtoField(buf []byte, fieldNumber, wireType int) []byte {
	i := 0
	for i < len(buf) {
		tag, n := readVarint(buf[i:])
		if n == 0 {
			return nil
		}
		i += n
		fn := int(tag >> 3)
		wt := int(tag & 0x7)
		if fn == fieldNumber && wt == wireType && wt == 2 {
			ln, m := readVarint(buf[i:])
			if m == 0 || i+m+int(ln) > len(buf) {
				return nil
			}
			i += m
			return buf[i : i+int(ln)]
		}
		// Skip the field's payload by wire type.
		switch wt {
		case 0: // varint
			_, m := readVarint(buf[i:])
			if m == 0 {
				return nil
			}
			i += m
		case 1: // 64-bit
			if i+8 > len(buf) {
				return nil
			}
			i += 8
		case 2: // LEN
			ln, m := readVarint(buf[i:])
			if m == 0 || i+m+int(ln) > len(buf) {
				return nil
			}
			i += m + int(ln)
		case 5: // 32-bit
			if i+4 > len(buf) {
				return nil
			}
			i += 4
		default:
			return nil
		}
	}
	return nil
}

// readVarint decodes a protobuf varint from buf, returning the value
// and the number of bytes consumed (0 on truncation).
func readVarint(buf []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i, b := range buf {
		v |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
		if shift >= 64 {
			return 0, 0
		}
	}
	return 0, 0
}

// bytesEqual is a tiny equality helper to avoid importing
// bytes.Equal just for two-byte-slice comparisons.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
