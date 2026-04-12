package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type AuthHandler struct {
	auth     *services.AuthService
	renderer *Renderer
}

func NewAuthHandler(auth *services.AuthService, renderer *Renderer) *AuthHandler {
	return &AuthHandler{auth: auth, renderer: renderer}
}

func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	// If already authenticated, redirect to dashboard
	cookie, err := r.Cookie("session")
	if err == nil {
		if _, err := h.auth.ValidateSession(cookie.Value); err == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}
	h.renderer.RenderLogin(w, nil)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	token, err := h.auth.Login(req.Username, req.Password)
	if err != nil {
		JSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		h.auth.Logout(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	JSON(w, http.StatusOK, map[string]any{
		"username": user.Username,
	})
}
