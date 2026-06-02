// tesla_tokens.go — admin endpoints for managing BLE client tokens.
//
// These three endpoints live on /api/tesla/tokens, behind the same
// session-cookie auth as the rest of the Pi admin UI. They are NOT
// part of /api/ble/* — issuing and revoking tokens is an operator
// action; only the holder of a console login may do it, never a
// bearer-authed client.
//
// V4.4 Phase 1.
package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// ListTokens returns every issued token (active + revoked) with audit
// columns. The plaintext is never on this surface — it was only
// returned at issuance.
func (h *TeslaHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := h.tokens.List()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []services.TeslaClientToken{}
	}
	JSON(w, http.StatusOK, map[string]any{"tokens": rows})
}

// IssueToken creates a new bearer with the operator-supplied label and
// returns the plaintext **once**. The caller must surface it to the
// operator and forget it — there is no "re-display" endpoint. Audit
// log records the issuance with the user who authorised it.
func (h *TeslaHandler) IssueToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	issued, err := h.tokens.Issue(body.Name)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if user := GetUser(r); user != nil && h.audit != nil {
		h.audit.Log("tesla.token_issue",
			user.Username+" issued BLE client token '"+issued.Token.Name+"'")
	}
	JSON(w, http.StatusOK, map[string]any{
		"token": issued.Token,
		"plain": issued.Plain,
	})
}

// MyTokenInfo returns the bearer-authed caller's own token row —
// name, created/last-used timestamps, no plaintext. Lets the client
// app show "you're connected as 'ivan's macbook' since X" without
// exposing the admin token-list endpoint.
func (h *TeslaHandler) MyTokenInfo(w http.ResponseWriter, r *http.Request) {
	tok := GetBLEClient(r)
	if tok == nil {
		// Should be impossible — BLEBearerRequired set this — but
		// guard anyway so a refactor mistake surfaces loudly.
		JSONError(w, http.StatusUnauthorized, "no bearer context")
		return
	}
	JSON(w, http.StatusOK, tok)
}

// RevokeMyToken is the bearer-holder's self-destruct button. Marks
// the caller's own token as revoked. Reversible only via re-issuing
// from /settings on the Pi.
//
// Distinct from RevokeToken (admin): no id param, no privilege escalation.
func (h *TeslaHandler) RevokeMyToken(w http.ResponseWriter, r *http.Request) {
	tok := GetBLEClient(r)
	if tok == nil {
		JSONError(w, http.StatusUnauthorized, "no bearer context")
		return
	}
	if err := h.tokens.Revoke(tok.ID); err != nil {
		if errors.Is(err, services.ErrTeslaTokenNotFound) {
			JSONError(w, http.StatusNotFound, err.Error())
			return
		}
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.audit != nil {
		h.audit.Log("tesla.token_self_revoke",
			"client:"+tok.Name+" self-revoked their own token")
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeToken flips revoked_at on the given token id. The path param
// is the numeric id from the list endpoint, not the token plaintext —
// we never round-trip plaintext.
func (h *TeslaHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	if err := h.tokens.Revoke(id); err != nil {
		if errors.Is(err, services.ErrTeslaTokenNotFound) {
			JSONError(w, http.StatusNotFound, err.Error())
			return
		}
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user := GetUser(r); user != nil && h.audit != nil {
		h.audit.Log("tesla.token_revoke",
			user.Username+" revoked BLE client token id="+idStr)
	}
	w.WriteHeader(http.StatusNoContent)
}
