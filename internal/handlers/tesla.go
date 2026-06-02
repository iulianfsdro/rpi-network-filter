// Tesla HTTP surface — V4.4 Phase 4.
//
// What's left here after the Phase 4 / Thread A purge:
//
//   • PairingInfo  — GET  /api/ble/pair                — returns VIN +
//                                                       paired flag +
//                                                       (legacy) Pi
//                                                       pubkey if it
//                                                       happens to be
//                                                       on disk.
//   • SetVIN       — PUT  /api/ble/vin                — operator sets
//                                                       the 17-char VIN
//                                                       so the BLE
//                                                       scanner knows
//                                                       what to look
//                                                       for.
//   • PairExternalPubkey — POST /api/ble/pair/external-pubkey —
//                          ships a client's public key over BLE so the
//                          car's keychain learns about it. The
//                          operator finishes by tapping the NFC card.
//   • CommandLog   — GET  /api/ble/log                — audit trail
//                                                       (mostly idle
//                                                       until Thread C
//                                                       wires names).
//   • State        — STUB. Client uses /pair for connectivity check;
//                          Thread C will replace this with proper
//                          client-side state reads through the byte
//                          forwarder.
//
// The token-management endpoints (ListTokens / IssueToken / RevokeToken)
// live in tesla_tokens.go; the byte-forwarder session endpoints live
// in tesla_session.go. Both are mounted by router.go.
//
// All the per-command (Lock / Unlock / Honk / …), state polling, and
// /garage page rendering that this file used to do are gone — the Pi
// no longer holds a signing key, so those paths can't function. The
// client app at client/index.html owns the Tesla UI now.
package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// decodeJSON reads + decodes a single JSON body into v with the
// standard guards: cap body size at 64KB, reject unknown fields so a
// typo in the client doesn't silently no-op.
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// TeslaHandler is the surviving Pi-side Tesla HTTP surface after the
// rearchitecture. Thin — every method either reads/writes a config
// value, hands off to BLESessionService, or audits a token action.
type TeslaHandler struct {
	tesla   *services.TeslaService
	tokens  *services.TeslaTokenService
	bleSess *services.BLESessionService
	audit   *services.AuditService
}

// NewTeslaHandler wires the dependencies. renderer is no longer
// needed (no Pi-side page to render) — kept off the signature
// entirely so callers can't accidentally try.
func NewTeslaHandler(svc *services.Services) *TeslaHandler {
	return &TeslaHandler{
		tesla:   svc.Tesla,
		tokens:  svc.TeslaToken,
		bleSess: svc.BLESession,
		audit:   svc.Audit,
	}
}

// ── Bootstrap config ─────────────────────────────────────────────

// PairingInfo returns the current pairing state — VIN + whether a
// Pi-side key is on disk (true only on pre-V4.4 deployments that
// haven't wiped the legacy keyfile). The client uses /pair primarily
// to learn the VIN so it can include it in the AES-GCM AAD's
// personalization tag — same value the car expects.
//
// public_key_pem is empty on a Phase-4-clean Pi. The client doesn't
// need it (it has its own enrolled keypair) but the field stays for
// backward-compat with any external tooling.
func (h *TeslaHandler) PairingInfo(w http.ResponseWriter, r *http.Request) {
	pub, err := h.tesla.PublicKeyPEM()
	if err != nil {
		pub = ""
	}
	JSON(w, http.StatusOK, map[string]any{
		"vin":            h.tesla.VIN(),
		"paired":         h.tesla.IsPaired(),
		"public_key_pem": pub,
	})
}

// SetVIN persists the operator's VIN. Validation lives in the service
// layer (17 chars, alphanumeric upper). Required before any /sessions
// call works — the BLE scanner needs to know which advertisement to
// match. Bearer-authed so the client app drives it.
func (h *TeslaHandler) SetVIN(w http.ResponseWriter, r *http.Request) {
	var body struct {
		VIN string `json:"vin"`
	}
	if err := decodeJSON(r, &body); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.tesla.SetVIN(body.VIN); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if user := GetUser(r); user != nil && h.audit != nil {
		h.audit.Log("tesla.set_vin", user.Username+" set VIN to "+body.VIN)
	}
	JSON(w, http.StatusOK, map[string]string{"vin": body.VIN})
}

// PairExternalPubkey enrols a client-supplied P-256 public key on the
// car. The client (laptop, phone PWA) generated a non-extractable
// WebCrypto keypair on first run; here it ships the public half so
// the car adds it to its owner-key list. The operator finishes by
// tapping their NFC key card on the centre console.
//
// Body shape: { "public_key_b64": "<base64 SEC1 uncompressed point>" }
// — 65 raw bytes (0x04 || X || Y), the format crypto.subtle's
// exportKey('raw', ecdhPubKey) produces.
//
// Internally uses an ephemeral throwaway ECDH key just to satisfy the
// SDK's NewVehicle signature; nothing about that key is persisted.
func (h *TeslaHandler) PairExternalPubkey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PublicKeyB64 string `json:"public_key_b64"`
	}
	if err := decodeJSON(r, &body); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	pubBytes, err := base64.StdEncoding.DecodeString(body.PublicKeyB64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid base64: "+err.Error())
		return
	}
	ctx, cancel := teslaCtx(r, 45*time.Second)
	defer cancel()
	if err := h.tesla.RequestPairingExternal(ctx, pubBytes); err != nil {
		JSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if user := GetUser(r); user != nil && h.audit != nil {
		h.audit.Log("tesla.pair_request_external",
			user.Username+" enrolled an external pubkey on the car")
	}
	JSON(w, http.StatusOK, map[string]bool{"requested": true})
}

// State is a Phase-4 stub. The Pi no longer holds a key, so it can't
// poll the car for state — Thread C will replace this with a
// client-side path that reads state through the byte forwarder. The
// stub exists so the client app's connect() health check keeps
// passing; it returns a shape the existing UI tolerates (empty
// snapshot → "—" placeholders everywhere).
func (h *TeslaHandler) State(w http.ResponseWriter, r *http.Request) {
	JSON(w, http.StatusOK, map[string]any{
		"snapshot": map[string]any{},
		"note":     "state polling moved to client-side (Thread C); this endpoint is a connectivity stub",
	})
}

// CommandLog returns the most recent N entries from tesla_command_log.
// Default 20, max 200. Currently mostly empty — Phase-4 commands go
// through /sessions which doesn't yet name what it's sending, so the
// log table sees little traffic. Thread C will add naming.
func (h *TeslaHandler) CommandLog(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	type entry struct {
		At        string `json:"at"`
		Command   string `json:"command"`
		Succeeded bool   `json:"succeeded"`
		LatencyMs int64  `json:"latency_ms"`
		Error     string `json:"error,omitempty"`
	}
	rows, err := h.tesla.CommandLog(limit)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]entry, 0, len(rows))
	for _, r := range rows {
		out = append(out, entry{
			At: r.At, Command: r.Command, Succeeded: r.Succeeded,
			LatencyMs: r.LatencyMs, Error: r.Error,
		})
	}
	JSON(w, http.StatusOK, out)
}

// ── helpers ──────────────────────────────────────────────────────

// teslaCtx derives a request-scoped context with the BLE-handler
// timeout. Inheriting from r.Context() so the upstream HTTP/2
// deadline propagates through.
func teslaCtx(r *http.Request, max time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), max)
}
