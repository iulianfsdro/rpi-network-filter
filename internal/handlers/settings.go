package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type SettingsHandler struct {
	db       *sql.DB
	svc      *services.Services
	renderer *Renderer
}

func NewSettingsHandler(db *sql.DB, svc *services.Services, renderer *Renderer) *SettingsHandler {
	return &SettingsHandler{db: db, svc: svc, renderer: renderer}
}

func (h *SettingsHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "settings.html", map[string]string{"page": "settings"})
}

func (h *SettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT key, value FROM settings")
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		settings[k] = v
	}

	JSON(w, http.StatusOK, settings)
}

func (h *SettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	var settings map[string]string
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	tx, err := h.db.Begin()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	needsHotspotRestart := false
	needsDNSReload := false

	for k, v := range settings {
		if _, err := tx.Exec("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?", k, v, v); err != nil {
			tx.Rollback()
			JSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		switch k {
		case "ap_ssid", "ap_password", "ap_channel":
			needsHotspotRestart = true
		case "dns_upstream":
			needsDNSReload = true
		}
	}

	if err := tx.Commit(); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.svc.Audit.Log("settings.update", "updated settings")

	if needsHotspotRestart {
		go h.svc.Hotspot.Apply()
	}
	if needsDNSReload {
		go h.svc.DNS.Apply()
	}

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *SettingsHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Password) < 8 {
		JSONError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	if err := h.svc.Auth.ResetPassword(user.Username, req.Password); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.svc.Audit.Log("auth.password_change", "user="+user.Username)

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
