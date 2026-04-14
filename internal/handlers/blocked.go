package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type BlockedHandler struct {
	blocked  *services.BlockedService
	dns      *services.DNSService
	audit    *services.AuditService
	renderer *Renderer
}

func NewBlockedHandler(svc *services.Services, renderer *Renderer) *BlockedHandler {
	return &BlockedHandler{
		blocked:  svc.Blocked,
		dns:      svc.DNS,
		audit:    svc.Audit,
		renderer: renderer,
	}
}

func (h *BlockedHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "blocklist.html", map[string]string{"page": "blocklist"})
}

func (h *BlockedHandler) List(w http.ResponseWriter, r *http.Request) {
	domains, err := h.blocked.List()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if domains == nil {
		domains = []models.BlockedDomain{}
	}
	JSON(w, http.StatusOK, domains)
}

func (h *BlockedHandler) Create(w http.ResponseWriter, r *http.Request) {
	var d models.BlockedDomain
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if d.Domain == "" {
		JSONError(w, http.StatusBadRequest, "domain is required")
		return
	}
	// Default: enabled + suffix match (most useful for blanket vendor blocks)
	d.Enabled = true
	if d.MatchType == "" {
		d.MatchType = "suffix"
	}

	id, err := h.blocked.Create(d)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("blocklist.create", d.Domain)

	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "saved but failed to apply DNS: "+err.Error())
		return
	}

	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *BlockedHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid id")
		return
	}

	var d models.BlockedDomain
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.blocked.Update(id, d); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("blocklist.update", d.Domain)
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "updated but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *BlockedHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid id")
		return
	}

	if err := h.blocked.Delete(id); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("blocklist.delete", "id="+chi.URLParam(r, "id"))
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "deleted but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
