package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type BandwidthHandler struct {
	bandwidth *services.BandwidthService
	audit     *services.AuditService
	renderer  *Renderer
}

func NewBandwidthHandler(svc *services.Services, renderer *Renderer) *BandwidthHandler {
	return &BandwidthHandler{
		bandwidth: svc.Bandwidth,
		audit:     svc.Audit,
		renderer:  renderer,
	}
}

func (h *BandwidthHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "bandwidth.html", map[string]string{"page": "bandwidth"})
}

func (h *BandwidthHandler) List(w http.ResponseWriter, r *http.Request) {
	limits, err := h.bandwidth.ListLimits()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if limits == nil {
		limits = []models.BandwidthLimit{}
	}
	JSON(w, http.StatusOK, limits)
}

func (h *BandwidthHandler) Create(w http.ResponseWriter, r *http.Request) {
	var limit models.BandwidthLimit
	if err := json.NewDecoder(r.Body).Decode(&limit); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	id, err := h.bandwidth.CreateLimit(limit)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("bandwidth.create", "device="+limit.DeviceMAC)

	if err := h.bandwidth.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "limit saved but failed to apply: "+err.Error())
		return
	}

	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *BandwidthHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid limit id")
		return
	}

	var limit models.BandwidthLimit
	if err := json.NewDecoder(r.Body).Decode(&limit); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.bandwidth.UpdateLimit(id, limit); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("bandwidth.update", "device="+limit.DeviceMAC)

	if err := h.bandwidth.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "limit updated but failed to apply: "+err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *BandwidthHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid limit id")
		return
	}

	if err := h.bandwidth.DeleteLimit(id); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("bandwidth.delete", "limit_id="+chi.URLParam(r, "id"))

	if err := h.bandwidth.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "limit deleted but failed to apply: "+err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
