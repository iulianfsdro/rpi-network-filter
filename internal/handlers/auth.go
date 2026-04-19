package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type AuthHandler struct {
	auth     *services.AuthService
	renderer *Renderer

	// Per-IP login throttle: 5 failed attempts per minute before 401-with-backoff.
	loginMu       sync.Mutex
	loginAttempts map[string]*loginBucket
}

type loginBucket struct {
	failures  int
	firstHit  time.Time
	lockUntil time.Time
}

const (
	loginMaxFailures = 5
	loginWindow      = time.Minute
	loginLockout     = 2 * time.Minute
)

func NewAuthHandler(auth *services.AuthService, renderer *Renderer) *AuthHandler {
	return &AuthHandler{
		auth:          auth,
		renderer:      renderer,
		loginAttempts: make(map[string]*loginBucket),
	}
}

// clientIP strips the port from r.RemoteAddr so the rate-limit keys on
// "192.168.4.5" rather than "192.168.4.5:54321".
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

// loginLocked returns true (and the remaining lockout) if the client is
// currently in a cooling-off window after too many failures.
func (h *AuthHandler) loginLocked(ip string) (bool, time.Duration) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	b, ok := h.loginAttempts[ip]
	if !ok {
		return false, 0
	}
	if now := time.Now(); now.Before(b.lockUntil) {
		return true, b.lockUntil.Sub(now)
	}
	return false, 0
}

func (h *AuthHandler) recordLoginFailure(ip string) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	now := time.Now()
	b, ok := h.loginAttempts[ip]
	if !ok || now.Sub(b.firstHit) > loginWindow {
		h.loginAttempts[ip] = &loginBucket{failures: 1, firstHit: now}
		return
	}
	b.failures++
	if b.failures >= loginMaxFailures {
		b.lockUntil = now.Add(loginLockout)
		log.Printf("[AUTH] login brute-force lockout for %s (%d failures in %s)",
			ip, b.failures, loginWindow)
	}
}

func (h *AuthHandler) recordLoginSuccess(ip string) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	delete(h.loginAttempts, ip)
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
	ip := clientIP(r)
	if locked, remaining := h.loginLocked(ip); locked {
		w.Header().Set("Retry-After", toSeconds(remaining))
		JSONError(w, http.StatusTooManyRequests,
			"too many failed attempts; try again in "+remaining.Truncate(time.Second).String())
		return
	}

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
		h.recordLoginFailure(ip)
		JSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	h.recordLoginSuccess(ip)

	// Secure flag: only set when the daemon is serving over TLS (which is
	// the normal production path). The browser refuses a Secure cookie
	// over a plain-HTTP connection, so during a dev run on HTTP we omit
	// it to avoid a silent login loop.
	cookie := &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	}
	http.SetCookie(w, cookie)

	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func toSeconds(d time.Duration) string {
	s := int(d.Round(time.Second).Seconds())
	if s < 1 {
		s = 1
	}
	return strconv.Itoa(s)
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
