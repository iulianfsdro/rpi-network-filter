// handlers/remote.go — /remote-access page + Tailscale management API.
//
// Three endpoints power the page:
//   GET  /api/remote/status   → flat snapshot of {installed, daemon,
//                                  authenticated, hostname, ipv4}
//   POST /api/remote/install  → fire-and-forget install of the
//                                  tailscale package. Idempotent; the
//                                  UI polls Status afterwards.
//   POST /api/remote/up       → { "auth_key": "tskey-..." } — logs the
//                                  Pi into the tailnet.
//   POST /api/remote/logout   → disconnects.
//
// All four are behind APIAuthRequired — the same netfilterd web session
// that gates every other admin action. There is no public surface for
// "I want this Pi on the tailnet"; the only path is through an already-
// authenticated session on the LAN.
package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type RemoteHandler struct {
	remote   *services.RemoteService
	audit    *services.AuditService
	renderer *Renderer
}

func NewRemoteHandler(svc *services.Services, renderer *Renderer) *RemoteHandler {
	return &RemoteHandler{
		remote:   svc.Remote,
		audit:    svc.Audit,
		renderer: renderer,
	}
}

func (h *RemoteHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "remote-access.html", map[string]string{"page": "remote-access"})
}

func (h *RemoteHandler) Status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	st, err := h.remote.Status(ctx)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, st)
}

// Install runs `curl ... install.sh | sh`. ~30s round-trip. We hold the
// HTTP request open for the duration — at this scale (single operator,
// one click) that's simpler than backgrounding it.
func (h *RemoteHandler) Install(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := h.remote.Install(ctx); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if u := GetUser(r); u != nil {
		h.audit.Log("remote.install", u.Username+" installed Tailscale on the Pi")
	}
	JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *RemoteHandler) Up(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AuthKey string `json:"auth_key"`
	}
	if err := decodeJSON(r, &body); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := h.remote.Up(ctx, body.AuthKey); err != nil {
		JSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if u := GetUser(r); u != nil {
		// Note: do NOT include the auth key in the audit log. The service
		// layer's error messages also redact it.
		h.audit.Log("remote.up", u.Username+" connected the Pi to a tailnet")
	}
	JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *RemoteHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := h.remote.Logout(ctx); err != nil {
		JSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if u := GetUser(r); u != nil {
		h.audit.Log("remote.logout", u.Username+" disconnected the Pi from the tailnet")
	}
	JSON(w, http.StatusOK, map[string]bool{"ok": true})
}
