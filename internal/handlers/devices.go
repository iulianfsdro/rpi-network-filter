package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type DevicesHandler struct {
	network  *services.NetworkService
	firewall *services.FirewallService
	audit    *services.AuditService
	renderer *Renderer
}

func NewDevicesHandler(svc *services.Services, renderer *Renderer) *DevicesHandler {
	return &DevicesHandler{
		network:  svc.Network,
		firewall: svc.Firewall,
		audit:    svc.Audit,
		renderer: renderer,
	}
}

func (h *DevicesHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "devices.html", map[string]string{"page": "devices"})
}

func (h *DevicesHandler) List(w http.ResponseWriter, r *http.Request) {
	devices, err := h.network.ListDevices()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, devices)
}

func (h *DevicesHandler) Update(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")

	var req struct {
		Alias     string `json:"alias"`
		IsBlocked bool   `json:"is_blocked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.network.UpdateDevice(mac, req.Alias, req.IsBlocked); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("device.update", "MAC="+mac+" blocked="+boolStr(req.IsBlocked))

	// Re-apply firewall to update blocked device list
	go h.firewall.Apply()

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
