package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type FirewallHandler struct {
	firewall *services.FirewallService
	audit    *services.AuditService
	renderer *Renderer
}

func NewFirewallHandler(svc *services.Services, renderer *Renderer) *FirewallHandler {
	return &FirewallHandler{
		firewall: svc.Firewall,
		audit:    svc.Audit,
		renderer: renderer,
	}
}

func (h *FirewallHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "firewall.html", map[string]string{"page": "firewall"})
}

// ── Firewall rules CRUD (the /firewall manual-rules page) ──────

func (h *FirewallHandler) List(w http.ResponseWriter, r *http.Request) {
	rules, err := h.firewall.ListRules()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rules == nil {
		rules = []models.FirewallRule{}
	}
	JSON(w, http.StatusOK, rules)
}

func (h *FirewallHandler) Create(w http.ResponseWriter, r *http.Request) {
	var rule models.FirewallRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	id, err := h.firewall.CreateRule(rule)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("firewall.create", rule.Description)

	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "rule saved but failed to apply: "+err.Error())
		return
	}

	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *FirewallHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	var rule models.FirewallRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.firewall.UpdateRule(id, rule); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("firewall.update", rule.Description)

	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "rule updated but failed to apply: "+err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *FirewallHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	if err := h.firewall.DeleteRule(id); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit.Log("firewall.delete", "rule_id="+chi.URLParam(r, "id"))

	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "rule deleted but failed to apply: "+err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
