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
	dns        *services.DNSService
	audit      *services.AuditService
	trafficLog *services.TrafficLogService
	renderer   *Renderer
}

func NewDevicesHandler(svc *services.Services, renderer *Renderer) *DevicesHandler {
	return &DevicesHandler{
		network:    svc.Network,
		firewall:   svc.Firewall,
		dns:        svc.DNS,
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

// macFromPath extracts and validates an uppercased MAC from chi's {mac}
// path parameter. devices.mac_address is stored uppercase by
// parseDHCPLeases/parseARP, so normalise here before the SQL comparison.
func macFromPath(r *http.Request) (string, error) {
	raw := chi.URLParam(r, "mac")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("invalid mac encoding")
	}
	mac := strings.ToUpper(strings.TrimSpace(decoded))
	if !services.ValidMAC(strings.ToLower(mac)) {
		return "", fmt.Errorf("invalid mac format (want aa:bb:cc:dd:ee:ff)")
	}
	return mac, nil
}

// Update edits per-device metadata: alias and the traffic-log mute flag.
// Status changes go through SetStatus (PUT /api/devices/{mac}/status).
func (h *DevicesHandler) Update(w http.ResponseWriter, r *http.Request) {
	mac, err := macFromPath(r)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		Alias            string `json:"alias"`
		IgnoreTrafficLog bool   `json:"ignore_traffic_log"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.network.UpdateDevice(mac, req.Alias, req.IgnoreTrafficLog); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("device.update",
		"MAC="+mac+" ignore_log="+boolStr(req.IgnoreTrafficLog))

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

// SetStatus moves a device between blocked / filtered / open. Each
// transition re-applies the firewall (forward-chain accept and prerouting
// redirects depend on it) and the DNS config (open devices get DHCP
// options bypassing the default-deny resolver).
func (h *DevicesHandler) SetStatus(w http.ResponseWriter, r *http.Request) {
	mac, err := macFromPath(r)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.network.SetStatus(mac, req.Status); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("device.status", "MAC="+mac+" status="+req.Status)
	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "status set but failed to apply firewall: "+err.Error())
		return
	}
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "status set but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Delete hard-removes a device row. After deletion the device is as if
// it had never connected: the network scanner re-inserts it on the next
// DHCP/ARP sighting with the default status='blocked', so it gets
// dropped by the forward chain until an operator explicitly reclassifies
// it. The traffic-log history for this MAC is wiped to match.
func (h *DevicesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	mac, err := macFromPath(r)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Snapshot the IP before deletion so we can wipe DNS-tagged log rows
	// (which carry client_ip, not MAC).
	ip := h.network.DeviceIPByMAC(mac)
	if err := h.network.Delete(mac); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n, err := h.trafficLog.WipeForDevice(mac, ip); err != nil {
		log.Printf("[DEVICES] wipe query_log for deleted %s/%s failed: %v", mac, ip, err)
	} else if n > 0 {
		h.audit.Log("device.wipe_logs", fmt.Sprintf("MAC=%s ip=%s deleted=%d (device removed)", mac, ip, n))
	}
	h.audit.Log("device.delete", "MAC="+mac)
	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "deleted but failed to apply firewall: "+err.Error())
		return
	}
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "deleted but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
