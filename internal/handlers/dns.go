package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type DNSHandler struct {
	dns      *services.DNSService
	audit    *services.AuditService
	renderer *Renderer
}

func NewDNSHandler(svc *services.Services, renderer *Renderer) *DNSHandler {
	return &DNSHandler{
		dns:      svc.DNS,
		audit:    svc.Audit,
		renderer: renderer,
	}
}

func (h *DNSHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "dns.html", map[string]string{"page": "dns"})
}

func (h *DNSHandler) List(w http.ResponseWriter, r *http.Request) {
	entries, err := h.dns.ListEntries()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []models.DNSBlockEntry{}
	}
	JSON(w, http.StatusOK, entries)
}

func (h *DNSHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string `json:"domain"`
		Category string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	id, err := h.dns.CreateEntry(req.Domain, req.Category)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("dns.create", req.Domain)

	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "entry saved but failed to apply: "+err.Error())
		return
	}

	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *DNSHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid entry id")
		return
	}

	if err := h.dns.DeleteEntry(id); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("dns.delete", "entry_id="+chi.URLParam(r, "id"))

	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "entry deleted but failed to apply: "+err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *DNSHandler) Import(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text     string `json:"text"`
		Category string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	count, err := h.dns.ImportDomains(req.Text, req.Category)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("dns.import", fmt.Sprintf("imported %d domains, category=%s", count, req.Category))

	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "imported but failed to apply: "+err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]any{"imported": count})
}
