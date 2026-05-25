package handlers

import (
	"net/http"
	"time"

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
	sysInfo := h.svc.System.GetInfo()

	fwRules, _ := h.svc.Firewall.ListRules()
	activeRules := 0
	for _, r := range fwRules {
		if r.Enabled {
			activeRules++
		}
	}

	filters, _ := h.svc.Filter.List()
	enabledFilters := 0
	for _, f := range filters {
		if f.Enabled {
			enabledFilters++
		}
	}

	// Guardian hero counters: blocked / allowed over the trailing 24 h, plus
	// the size of the compile-time protected-deny floor. Best-effort — a
	// failed DB count folds to 0 so the dashboard never breaks the page.
	since := time.Now().Add(-24 * time.Hour)
	blocked24h := h.svc.TrafficLog.CountByActionSince("blocked", since)
	allowed24h := h.svc.TrafficLog.CountByActionSince("allowed", since)

	JSON(w, http.StatusOK, map[string]any{
		"devices_online":  online,
		"devices_total":   total,
		"firewall_rules":  activeRules,
		"filters_total":   len(filters),
		"filters_enabled": enabledFilters,
		"protected_deny":  services.ProtectedDenyCount(),
		"blocked_24h":     blocked24h,
		"allowed_24h":     allowed24h,
		"wan_reachable":   true, // placeholder until a WAN probe lives in SystemService
		"system":          sysInfo,
	})
}
