// tesla_session.go — HTTP surface for the raw BLE byte forwarder.
//
// V4.4 Phase 3b. Three endpoints, mounted under /api/ble:
//
//   POST   /api/ble/sessions             — open, returns {session_id, vin}
//   POST   /api/ble/sessions/{id}/exchange — body {payload_b64, timeout_ms}
//                                            returns {response_b64}
//   DELETE /api/ble/sessions/{id}        — close
//
// Payloads are RoutableMessage protobuf bytes. The handlers don't
// parse or inspect them — they just shuttle base64-encoded bytes to
// and from the BLE radio. All Tesla-protocol semantics live in the
// client; this layer is genuinely a forwarder.
package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// OpenBLESession creates a fresh BLE link and registers it in the
// session map. Only one session can be open at a time per Pi — see
// BLESessionService for the bleMu reasoning. Empty VIN in the request
// body falls back to the Pi's configured VIN.
func (h *TeslaHandler) OpenBLESession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		VIN string `json:"vin"`
	}
	// Tolerant decode — an empty body is fine; we just want VIN if
	// it's there.
	_ = decodeJSON(r, &body)

	ctx, cancel := teslaCtx(r, 30*time.Second)
	defer cancel()

	sess, err := h.bleSess.Open(ctx, body.VIN)
	if err != nil {
		JSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if user := GetUser(r); user != nil && h.audit != nil {
		h.audit.Log("tesla.ble_session_open",
			user.Username+" opened BLE session "+sess.ID+" (vin="+sess.VIN+")")
	}
	JSON(w, http.StatusOK, sess)
}

// ExchangeBLE sends one payload over the active session and returns
// the first response frame. The handler doesn't enforce any structure
// on payload — the client is expected to be sending well-formed
// RoutableMessage protobufs (whatever crypto.subtle has produced).
//
// timeout_ms is optional; we clamp to [0, 30000] and default to 5000.
// The HTTP context gets timeout+5s so the handler outlives the BLE
// wait without 502'ing on margin races.
func (h *TeslaHandler) ExchangeBLE(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var body struct {
		PayloadB64 string `json:"payload_b64"`
		TimeoutMs  int    `json:"timeout_ms"`
	}
	if err := decodeJSON(r, &body); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload, err := base64.StdEncoding.DecodeString(body.PayloadB64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid base64 in payload_b64: "+err.Error())
		return
	}

	timeout := time.Duration(body.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}

	ctx, cancel := teslaCtx(r, timeout+5*time.Second)
	defer cancel()

	resp, err := h.bleSess.Exchange(ctx, id, payload, timeout)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrBLESessionNotFound):
			JSONError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, services.ErrBLESessionTimeout):
			JSONError(w, http.StatusGatewayTimeout, err.Error())
		default:
			JSONError(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	JSON(w, http.StatusOK, map[string]string{
		"response_b64": base64.StdEncoding.EncodeToString(resp),
	})
}

// CloseBLESession tears down the session — closes the BLE link and
// releases the adapter mutex. Idempotent from the caller's POV: a
// 404 means "already closed or never existed."
func (h *TeslaHandler) CloseBLESession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.bleSess.Close(id); err != nil {
		if errors.Is(err, services.ErrBLESessionNotFound) {
			JSONError(w, http.StatusNotFound, err.Error())
			return
		}
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user := GetUser(r); user != nil && h.audit != nil {
		h.audit.Log("tesla.ble_session_close",
			user.Username+" closed BLE session "+id)
	}
	w.WriteHeader(http.StatusNoContent)
}
