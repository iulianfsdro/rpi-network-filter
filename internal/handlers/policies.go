package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

var macRe = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// extractMAC URL-decodes the {mac} path param (chi does not decode path
// parameters), lowercases it, and validates the aa:bb:cc:dd:ee:ff shape.
// Returns the normalized MAC or an error suitable to hand back as 400.
func extractMAC(r *http.Request) (string, error) {
	raw := chi.URLParam(r, "mac")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", errors.New("invalid mac encoding")
	}
	mac := strings.ToLower(strings.TrimSpace(decoded))
	if !macRe.MatchString(mac) {
		return "", errors.New("invalid mac format (want aa:bb:cc:dd:ee:ff)")
	}
	return mac, nil
}

type PoliciesHandler struct {
	policy   *services.PolicyService
	firewall *services.FirewallService
	audit    *services.AuditService
	renderer *Renderer
}

func NewPoliciesHandler(svc *services.Services, renderer *Renderer) *PoliciesHandler {
	return &PoliciesHandler{
		policy:   svc.Policy,
		firewall: svc.Firewall,
		audit:    svc.Audit,
		renderer: renderer,
	}
}

func (h *PoliciesHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "policies.html", map[string]string{"page": "policies"})
}

// ── Policy CRUD ────────────────────────────────────────────────

func (h *PoliciesHandler) List(w http.ResponseWriter, r *http.Request) {
	pols, err := h.policy.List()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pols == nil {
		pols = []models.Policy{}
	}
	JSON(w, http.StatusOK, pols)
}

func (h *PoliciesHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	p, err := h.policy.Get(id)
	if err != nil {
		if errors.Is(err, services.ErrPolicyNotFound) {
			JSONError(w, http.StatusNotFound, "policy not found")
			return
		}
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, p)
}

func (h *PoliciesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var p models.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id, err := h.policy.Create(p)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("policy.create", p.Name)
	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *PoliciesHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	var p models.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.policy.Update(id, p); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("policy.update", p.Name)
	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "updated but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *PoliciesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	if err := h.policy.Delete(id); err != nil {
		switch {
		case errors.Is(err, services.ErrPolicyNotFound):
			JSONError(w, http.StatusNotFound, "policy not found")
		case errors.Is(err, services.ErrDefaultPolicyLock):
			JSONError(w, http.StatusConflict, err.Error())
		default:
			JSONError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	h.audit.Log("policy.delete", strconv.FormatInt(id, 10))
	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "deleted but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Per-policy allow list ──────────────────────────────────────

func (h *PoliciesHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	policyID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	ds, err := h.policy.ListDomains(policyID)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ds == nil {
		ds = []models.PolicyDomain{}
	}
	JSON(w, http.StatusOK, ds)
}

func (h *PoliciesHandler) CreateDomain(w http.ResponseWriter, r *http.Request) {
	policyID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	var d models.PolicyDomain
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !d.Enabled {
		d.Enabled = true
	}
	id, err := h.policy.CreateDomain(policyID, d)
	if err != nil {
		if errors.Is(err, services.ErrDomainBlocked) {
			JSONError(w, http.StatusConflict, err.Error())
			return
		}
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("policy.domain.create", d.Domain)
	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "saved but failed to apply: "+err.Error())
		return
	}
	// Fire a DNS query through the local dnsmasq so the nft set populates
	// before the first client tries to connect. Background to keep the
	// HTTP response fast — worst case, the client's own query beats ours.
	go h.policy.ResolveDomain(d.Domain)
	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *PoliciesHandler) UpdateDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "domainID"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid domain id")
		return
	}
	var d models.PolicyDomain
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.policy.UpdateDomain(id, d); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("policy.domain.update", strconv.FormatInt(id, 10))
	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "updated but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *PoliciesHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "domainID"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid domain id")
		return
	}
	if err := h.policy.DeleteDomain(id); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("policy.domain.delete", strconv.FormatInt(id, 10))
	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "deleted but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Device assignments ─────────────────────────────────────────

func (h *PoliciesHandler) ListAssignments(w http.ResponseWriter, r *http.Request) {
	as, err := h.policy.ListAssignments()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if as == nil {
		as = []models.DevicePolicy{}
	}
	JSON(w, http.StatusOK, as)
}

type assignRequest struct {
	PolicyID int64 `json:"policy_id"`
}

func (h *PoliciesHandler) AssignDevice(w http.ResponseWriter, r *http.Request) {
	mac, err := extractMAC(r)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req assignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.policy.AssignDevice(mac, req.PolicyID); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("policy.device.assign", mac)
	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "assigned but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *PoliciesHandler) UnassignDevice(w http.ResponseWriter, r *http.Request) {
	mac, err := extractMAC(r)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.policy.UnassignDevice(mac); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("policy.device.unassign", mac)
	if err := h.firewall.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "unassigned but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
