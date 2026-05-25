package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// extractMAC URL-decodes the {mac} path param (chi does not decode path
// parameters), lowercases it, and validates the aa:bb:cc:dd:ee:ff shape
// via the canonical services.ValidMAC.
func extractMAC(r *http.Request) (string, error) {
	raw := chi.URLParam(r, "mac")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", errors.New("invalid mac encoding")
	}
	mac := strings.ToLower(strings.TrimSpace(decoded))
	if !services.ValidMAC(mac) {
		return "", errors.New("invalid mac format (want aa:bb:cc:dd:ee:ff)")
	}
	return mac, nil
}

type FiltersHandler struct {
	filter   *services.FilterService
	firewall *services.FirewallService
	dns      *services.DNSService
	audit    *services.AuditService
	renderer *Renderer
}

func NewFiltersHandler(svc *services.Services, renderer *Renderer) *FiltersHandler {
	return &FiltersHandler{
		filter:   svc.Filter,
		firewall: svc.Firewall,
		dns:      svc.DNS,
		audit:    svc.Audit,
		renderer: renderer,
	}
}

func (h *FiltersHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "filters.html", map[string]string{"page": "filters"})
}

// ── Filter CRUD ────────────────────────────────────────────────

func (h *FiltersHandler) List(w http.ResponseWriter, r *http.Request) {
	fs, err := h.filter.List()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if fs == nil {
		fs = []models.Filter{}
	}
	JSON(w, http.StatusOK, fs)
}

func (h *FiltersHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	f, err := h.filter.Get(id)
	if err != nil {
		if errors.Is(err, services.ErrFilterNotFound) {
			JSONError(w, http.StatusNotFound, "filter not found")
			return
		}
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, f)
}

func (h *FiltersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var f models.Filter
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id, err := h.filter.Create(f)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("filter.create", f.Name)
	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *FiltersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	var f models.Filter
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.filter.Update(id, f); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("filter.update", f.Name)
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// SetEnabled flips the global enable flag for a filter. Because filters
// are global, this changes the allow-list for every filtered device in
// one shot — re-apply DNS to pick up the new server= lines.
func (h *FiltersHandler) SetEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.filter.SetEnabled(id, req.Enabled); err != nil {
		if errors.Is(err, services.ErrFilterNotFound) {
			JSONError(w, http.StatusNotFound, "filter not found")
			return
		}
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("filter.set_enabled", strconv.FormatInt(id, 10)+"="+strconv.FormatBool(req.Enabled))
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "saved but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *FiltersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	if err := h.filter.Delete(id); err != nil {
		switch {
		case errors.Is(err, services.ErrFilterNotFound):
			JSONError(w, http.StatusNotFound, "filter not found")
		case errors.Is(err, services.ErrSystemFilter):
			JSONError(w, http.StatusConflict, err.Error())
		default:
			JSONError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	h.audit.Log("filter.delete", strconv.FormatInt(id, 10))
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "deleted but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Per-filter domain list ─────────────────────────────────────

func (h *FiltersHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	filterID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	ds, err := h.filter.ListDomains(filterID)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ds == nil {
		ds = []models.FilterDomain{}
	}
	JSON(w, http.StatusOK, ds)
}

func (h *FiltersHandler) CreateDomain(w http.ResponseWriter, r *http.Request) {
	filterID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	var d models.FilterDomain
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// CreateDomain rejects empty descriptions and protected/ancestor names.
	id, err := h.filter.CreateDomain(filterID, d)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("filter.domain.create", d.Domain)
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "saved but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *FiltersHandler) UpdateDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "domainID"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid domain id")
		return
	}
	var d models.FilterDomain
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.filter.UpdateDomain(id, d); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("filter.domain.update", strconv.FormatInt(id, 10))
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "updated but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// SetDomainEnabled is the single-domain toggle endpoint, used by the
// checkbox on the Filters page. It does not require a description — the
// description was supplied at CreateDomain time and is unchanged here.
func (h *FiltersHandler) SetDomainEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "domainID"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid domain id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.filter.SetDomainEnabled(id, req.Enabled); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("filter.domain.enabled", strconv.FormatInt(id, 10)+"="+strconv.FormatBool(req.Enabled))
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "saved but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *FiltersHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "domainID"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid domain id")
		return
	}
	if err := h.filter.DeleteDomain(id); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("filter.domain.delete", strconv.FormatInt(id, 10))
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "deleted but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
