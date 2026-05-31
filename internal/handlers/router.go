package handlers

import (
	"database/sql"
	"io/fs"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

func NewRouter(svc *services.Services, cfg config.Config) http.Handler {
	// This will be called from main.go which sets up the embedded FS
	// For now, return a placeholder — the real wiring happens in NewRouterWithFS
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("netfilterd running — embedded FS not configured"))
	})
}

func NewRouterWithFS(db *sql.DB, svc *services.Services, cfg config.Config, webFS fs.FS) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Subfilesystems
	staticFS, _ := fs.Sub(webFS, "static")
	tmplFS, _ := fs.Sub(webFS, ".")

	renderer := NewRenderer(tmplFS)

	// Handlers
	authH := NewAuthHandler(svc.Auth, renderer)
	dashH := NewDashboardHandler(svc, renderer)
	devH := NewDevicesHandler(svc, renderer)
	fwH := NewFirewallHandler(svc, renderer)
	bwH := NewBandwidthHandler(svc, renderer)
	filtH := NewFiltersHandler(svc, renderer)
	settingsH := NewSettingsHandler(db, svc, renderer)
	sysH := NewSystemHandler(svc)
	teslaH := NewTeslaHandler(svc)
	remoteH := NewRemoteHandler(svc, renderer)

	// Static assets
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Public cert download so clients can install netfilterd's self-signed
	// cert as a trusted root and get green-lock HTTPS. Chicken-and-egg
	// note: the browser will still complain about the cert warning once
	// (user clicks through), then downloads this file, installs it, and
	// from then on sees a trusted connection.
	r.Get("/netfilter-ca.crt", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, cfg.TLSCert)
	})

	// Public routes
	r.Get("/login", authH.LoginPage)

	// Authenticated page routes
	r.Group(func(r chi.Router) {
		r.Use(AuthRequired(svc.Auth))
		r.Get("/", dashH.Page)
		r.Get("/traffic", func(w http.ResponseWriter, r *http.Request) {
			renderer.RenderPage(w, "traffic.html", map[string]string{"page": "traffic"})
		})
		r.Get("/stats", func(w http.ResponseWriter, r *http.Request) {
			renderer.RenderPage(w, "stats.html", map[string]string{"page": "stats"})
		})
		r.Get("/devices", devH.Page)
		r.Get("/firewall", fwH.Page)
		r.Get("/filters", filtH.Page)
		r.Get("/bandwidth", bwH.Page)
		r.Get("/settings", settingsH.Page)
		// V4.4 Phase 4: /garage was the Pi-as-Tesla-driver UI.
		// The Pi no longer holds a signing key; the client app
		// (client/index.html) is the Tesla UI now.
		r.Get("/remote-access", remoteH.Page)
	})

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Post("/login", authH.Login)
		r.Post("/logout", authH.Logout)

		// /api/ble/* — the bearer-authed surface owned by the client
		// app. Bearer-only (NO cookie auth path) so it can be exposed
		// publicly via Tailscale Funnel without dragging /login,
		// /traffic, /settings along with it.
		//
		// V4.4 Phase 4 stripped this down to the byte forwarder + the
		// minimum config needed to bootstrap a client: read/write the
		// VIN, enrol a client pubkey, and the raw BLE sessions API.
		// All the per-command and state-poll endpoints that needed a
		// Pi-resident signing key are gone.
		r.Route("/ble", func(r chi.Router) {
			// CORS comes BEFORE bearer auth so OPTIONS preflights
			// don't need a token. The bearer is still required on
			// every real request — CORS is just browser plumbing.
			r.Use(BLECORS)
			r.Use(BLEBearerRequired(svc.TeslaToken))

			// Bootstrap config — what the client needs to know
			// before opening a session.
			r.Get("/pair", teslaH.PairingInfo)
			r.Put("/vin", teslaH.SetVIN)
			r.Post("/pair/external-pubkey", teslaH.PairExternalPubkey)

			// State stub for the client's connectivity check (real
			// state lives on the client side post-Phase-4 / Thread C).
			r.Get("/state", teslaH.State)

			// Audit trail (client-driven commands write here once the
			// session-API layer learns to name them; today this is
			// mostly empty).
			r.Get("/log", teslaH.CommandLog)

			// Bearer self-management. NOT an admin path — you can
			// only see / revoke YOUR OWN token. Issuance stays on
			// the cookie-authed /api/tesla/tokens path so a leaked
			// bearer doesn't enable privilege escalation.
			r.Get("/token", teslaH.MyTokenInfo)
			r.Delete("/token", teslaH.RevokeMyToken)

			// Raw byte forwarder — Phase 3b. Open a session, exchange
			// opaque RoutableMessage bytes both ways, close. The Pi
			// never inspects or decrypts payloads.
			r.Post("/sessions", teslaH.OpenBLESession)
			r.Post("/sessions/{id}/exchange", teslaH.ExchangeBLE)
			r.Delete("/sessions/{id}", teslaH.CloseBLESession)
		})

		r.Group(func(r chi.Router) {
			r.Use(APIAuthRequired(svc.Auth))
			r.Get("/me", authH.Me)
			r.Get("/dashboard", dashH.API)

			r.Route("/devices", func(r chi.Router) {
				r.Get("/", devH.List)
				r.Put("/{mac}", devH.Update)
				r.Put("/{mac}/status", devH.SetStatus)
				r.Delete("/{mac}", devH.Delete)
			})

			r.Route("/filters", func(r chi.Router) {
				r.Get("/", filtH.List)
				r.Post("/", filtH.Create)
				r.Get("/{id}", filtH.Get)
				r.Put("/{id}", filtH.Update)
				r.Put("/{id}/enabled", filtH.SetEnabled)
				r.Delete("/{id}", filtH.Delete)
				r.Get("/{id}/domains", filtH.ListDomains)
				r.Post("/{id}/domains", filtH.CreateDomain)
				r.Put("/domains/{domainID}", filtH.UpdateDomain)
				r.Put("/domains/{domainID}/enabled", filtH.SetDomainEnabled)
				r.Delete("/domains/{domainID}", filtH.DeleteDomain)
			})

			r.Route("/firewall/rules", func(r chi.Router) {
				r.Get("/", fwH.List)
				r.Post("/", fwH.Create)
				r.Put("/{id}", fwH.Update)
				r.Delete("/{id}", fwH.Delete)
			})

			r.Route("/bandwidth/limits", func(r chi.Router) {
				r.Get("/", bwH.List)
				r.Post("/", bwH.Create)
				r.Put("/{id}", bwH.Update)
				r.Delete("/{id}", bwH.Delete)
			})

			r.Route("/settings", func(r chi.Router) {
				r.Get("/", settingsH.Get)
				r.Put("/", settingsH.Update)
				r.Put("/password", settingsH.ChangePassword)
			})

			r.Route("/system", func(r chi.Router) {
				r.Get("/info", sysH.Info)
				r.Get("/audit", sysH.AuditLog)
				r.Get("/connectivity", sysH.TestConnectivity)
				r.Get("/traffic", sysH.TrafficLog)
				r.Post("/traffic/clear", sysH.ClearTrafficLog)
				r.Get("/traffic/muted", sysH.MutedList)
				r.Post("/traffic/muted", sysH.MutedAdd)
				r.Delete("/traffic/muted/{id}", sysH.MutedRemove)
				r.Get("/stats/summary", sysH.StatsSummary)
				r.Get("/stats/top-domains", sysH.StatsTopDomains)
				r.Get("/stats/top-clients", sysH.StatsTopClients)
				r.Get("/stats/timeseries", sysH.StatsTimeSeries)
				r.Post("/reboot", sysH.Reboot)
			})

			// /api/tesla — admin namespace for BLE-client-token
			// management only. V4.4 Phase 4 stripped the per-command,
			// state-poll, and pairing endpoints from here; the only
			// reason this namespace still exists is that the
			// session-cookie operator needs a way to mint + revoke
			// bearer tokens for /api/ble/* clients, and the /settings
			// page lives behind cookie auth.
			r.Route("/tesla", func(r chi.Router) {
				r.Get("/tokens", teslaH.ListTokens)
				r.Post("/tokens", teslaH.IssueToken)
				r.Delete("/tokens/{id}", teslaH.RevokeToken)
			})

			r.Route("/remote", func(r chi.Router) {
				r.Get("/status", remoteH.Status)
				r.Post("/install", remoteH.Install)
				r.Post("/up", remoteH.Up)
				r.Post("/logout", remoteH.Logout)
				r.Post("/funnel/ble/enable", remoteH.EnableBLEFunnel)
				r.Post("/funnel/ble/disable", remoteH.DisableBLEFunnel)
			})
		})
	})

	return r
}
