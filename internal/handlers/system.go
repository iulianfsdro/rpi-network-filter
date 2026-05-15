package handlers

import (
	"net/http"
	"strconv"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type SystemHandler struct {
	system     *services.SystemService
	audit      *services.AuditService
	trafficLog *services.TrafficLogService
}

func NewSystemHandler(svc *services.Services) *SystemHandler {
	return &SystemHandler{
		system:     svc.System,
		audit:      svc.Audit,
		trafficLog: svc.TrafficLog,
	}
}

func (h *SystemHandler) Info(w http.ResponseWriter, r *http.Request) {
	info := h.system.GetInfo()
	JSON(w, http.StatusOK, info)
}

func (h *SystemHandler) Reboot(w http.ResponseWriter, r *http.Request) {
	h.audit.Log("system.reboot", "user requested reboot")
	JSON(w, http.StatusOK, map[string]string{"status": "rebooting"})
	go h.system.Reboot()
}

func (h *SystemHandler) TestConnectivity(w http.ResponseWriter, r *http.Request) {
	results := h.system.TestConnectivity()
	JSON(w, http.StatusOK, results)
}

func (h *SystemHandler) TrafficLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	page, _ := strconv.Atoi(q.Get("page"))
	perPage, _ := strconv.Atoi(q.Get("per_page"))

	filter := services.TrafficFilter{
		Page:    page,
		PerPage: perPage,
		Action:  q.Get("action"),
		Query:   q.Get("q"),
		From:    q.Get("from"),
		To:      q.Get("to"),
		Source:  q.Get("source"),
	}

	result := h.trafficLog.QueryPaginated(filter)
	JSON(w, http.StatusOK, result)
}

func (h *SystemHandler) ClearTrafficLog(w http.ResponseWriter, r *http.Request) {
	if err := h.trafficLog.Clear(); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("traffic.clear", "user cleared traffic log")
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *SystemHandler) StatsSummary(w http.ResponseWriter, r *http.Request) {
	rangeStr := r.URL.Query().Get("range")
	stats := h.trafficLog.Summary(rangeStr)
	JSON(w, http.StatusOK, stats)
}

func (h *SystemHandler) StatsTopDomains(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	result := h.trafficLog.TopDomains(q.Get("action"), q.Get("range"), q.Get("q"), limit)
	if result == nil {
		result = []services.DomainCount{}
	}
	JSON(w, http.StatusOK, result)
}

func (h *SystemHandler) StatsTopClients(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	result := h.trafficLog.TopClients(q.Get("range"), limit)
	if result == nil {
		result = []services.ClientCount{}
	}
	JSON(w, http.StatusOK, result)
}

func (h *SystemHandler) StatsTimeSeries(w http.ResponseWriter, r *http.Request) {
	rangeStr := r.URL.Query().Get("range")
	result := h.trafficLog.TimeSeries(rangeStr)
	if result == nil {
		result = []services.TimePoint{}
	}
	JSON(w, http.StatusOK, result)
}

func (h *SystemHandler) AuditLog(w http.ResponseWriter, r *http.Request) {
	logs, err := h.audit.Recent(50)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, logs)
}
