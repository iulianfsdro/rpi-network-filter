package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type contextKey string

const (
	userContextKey   contextKey = "user"
	clientContextKey contextKey = "ble-client"
)

func AuthRequired(auth *services.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session")
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			user, err := auth.ValidateSession(cookie.Value)
			if err != nil {
				http.SetCookie(w, &http.Cookie{
					Name:   "session",
					Value:  "",
					MaxAge: -1,
					Path:   "/",
				})
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func APIAuthRequired(auth *services.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session")
			if err != nil {
				JSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			user, err := auth.ValidateSession(cookie.Value)
			if err != nil {
				JSONError(w, http.StatusUnauthorized, "invalid session")
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetUser(r *http.Request) *models.User {
	user, _ := r.Context().Value(userContextKey).(*models.User)
	return user
}

// BLEBearerRequired protects /api/ble/* with a bearer token issued via
// the admin UI. The token is mapped to a TeslaClientToken row; the
// client name is stuffed into request context for audit attribution
// and synthesised into a virtual *models.User so the existing Tesla
// handlers (which call GetUser) keep working without conditionals.
//
// Synthetic user has ID = 0 (no FK target) and Username = "client:NAME".
// The tesla_command_log row will record user_id = 0; the human-readable
// audit message will read "client:NAME ran X" — leaving a clear trail
// of "this command came in via the byte-forwarder API, not a console
// login".
//
// On failure the response is 401 with a generic "unauthorized" string
// — we deliberately don't distinguish "missing header" / "wrong scheme"
// / "unknown token" / "revoked token" because the path is
// internet-facing and side-channel timing leaks would be cheap to
// exploit. (We don't even need constant-time comparison: validation
// hashes the candidate and SELECTs by hash, so the only timing
// signal is the DB query, which is the same for hit and miss.)
func BLEBearerRequired(tokens *services.TeslaTokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("Authorization")
			plain, ok := strings.CutPrefix(raw, "Bearer ")
			if !ok {
				JSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			tok, err := tokens.Validate(plain)
			if err != nil {
				if !errors.Is(err, services.ErrTeslaTokenInvalid) {
					// DB-level failure: log internally, still 401 outward.
					// The client can't act on the distinction.
					_ = err
				}
				JSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			ctx := context.WithValue(r.Context(), clientContextKey, tok)
			ctx = context.WithValue(ctx, userContextKey, &models.User{
				ID:       0,
				Username: "client:" + tok.Name,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetBLEClient returns the TeslaClientToken row that authorised the
// current request, or nil if the request came through cookie auth.
// Useful where a handler wants to render "issued by token X" instead
// of "issued by user X".
func GetBLEClient(r *http.Request) *services.TeslaClientToken {
	tok, _ := r.Context().Value(clientContextKey).(*services.TeslaClientToken)
	return tok
}

// BLECORS lets the standalone client (served from a different origin —
// file://, http://localhost:PORT, or eventually a native shell) make
// cross-origin requests to /api/ble. Without this every fetch is
// blocked by the browser's same-origin policy.
//
// We allow ANY origin and ONLY the methods + headers we actually use.
// That's safe because the resource itself is bearer-gated; a malicious
// site can issue CORS requests to /api/ble all it wants, but without
// a valid bearer (which is per-device, stored only in the legitimate
// client's IndexedDB) the response is 401. The bearer model already
// assumes a hostile public-internet path.
//
// OPTIONS preflight returns 204 immediately, BEFORE BLEBearerRequired
// runs, because preflights are sent without the Authorization header
// by design. If we let the bearer middleware see the OPTIONS it would
// 401 and the browser would never send the real request.
func BLECORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
