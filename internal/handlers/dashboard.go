package handlers

import (
	"net/http"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type DashboardHandler struct {
	svc      *services.Services
	renderer *Renderer
}

func NewDashboardHandler(svc *services.Services, renderer *Renderer) *DashboardHandler {
	return &DashboardHandler{svc: svc, renderer: renderer}
}

func (h *DashboardHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "dashboard.html", map[string]string{"page": "dashboard"})
}

func (h *DashboardHandler) API(w http.ResponseWriter, r *http.Request) {
	online, total, _ := h.svc.Network.GetDeviceCount()
	dnsCount, _ := h.svc.DNS.GetCount()
	sysInfo := h.svc.System.GetInfo()

	fwRules, _ := h.svc.Firewall.ListRules()
	activeRules := 0
	for _, r := range fwRules {
		if r.Enabled {
			activeRules++
		}
	}

	JSON(w, http.StatusOK, map[string]any{
		"devices_online": online,
		"devices_total":  total,
		"firewall_rules": activeRules,
		"dns_blocked":    dnsCount,
		"system":         sysInfo,
	})
}
