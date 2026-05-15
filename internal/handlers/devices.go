package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type DevicesHandler struct {
	network    *services.NetworkService
	firewall   *services.FirewallService
	audit      *services.AuditService
	trafficLog *services.TrafficLogService
	renderer   *Renderer
}

func NewDevicesHandler(svc *services.Services, renderer *Renderer) *DevicesHandler {
	return &DevicesHandler{
		network:    svc.Network,
		firewall:   svc.Firewall,
		audit:      svc.Audit,
		trafficLog: svc.TrafficLog,
		renderer:   renderer,
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
	// chi v5.1.0 does not URL-decode path params, so the raw value is
	// "AA%3ABB%3A…" instead of "AA:BB:…". Without the unescape the
	// UPDATE's WHERE matches zero rows and silently no-ops (returns
	// 200 with 0 rows affected) — the same bug migration v8 cleaned
	// up after on the policy-assign handler. devices.mac_address is
	// stored uppercase by parseDHCPLeases/parseARP, so normalise to
	// upper before the SQL comparison.
	raw := chi.URLParam(r, "mac")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid mac encoding")
		return
	}
	mac := strings.ToUpper(strings.TrimSpace(decoded))
	if !services.ValidMAC(mac) {
		JSONError(w, http.StatusBadRequest, "invalid mac format (want aa:bb:cc:dd:ee:ff)")
		return
	}

	var req struct {
		Alias            string `json:"alias"`
		IsBlocked        bool   `json:"is_blocked"`
		IgnoreTrafficLog bool   `json:"ignore_traffic_log"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.network.UpdateDevice(mac, req.Alias, req.IsBlocked, req.IgnoreTrafficLog); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("device.update",
		"MAC="+mac+
			" blocked="+boolStr(req.IsBlocked)+
			" ignore_log="+boolStr(req.IgnoreTrafficLog))

	// Re-apply firewall to update blocked device list
	go h.firewall.Apply()

	// When the user opts into log-suppression for this device, wipe the
	// existing query_log entries (matched by MAC for forward events and
	// by the device's last-known IP for DNS events), then refresh the
	// in-memory ignore cache so subsequent events are dropped at insert
	// time. Toggling off just refreshes the cache; past wiped rows are
	// gone for good.
	if req.IgnoreTrafficLog {
		ip := h.network.DeviceIPByMAC(mac)
		if n, err := h.trafficLog.WipeForDevice(mac, ip); err != nil {
			log.Printf("[DEVICES] wipe query_log for %s/%s failed: %v", mac, ip, err)
		} else if n > 0 {
			h.audit.Log("device.wipe_logs", fmt.Sprintf("MAC=%s ip=%s deleted=%d", mac, ip, n))
		}
	}
	h.trafficLog.RefreshIgnoreCache()

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
