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
	dnsH := NewDNSHandler(svc, renderer)
	blockH := NewBlockedHandler(svc, renderer)
	bwH := NewBandwidthHandler(svc, renderer)
	settingsH := NewSettingsHandler(db, svc, renderer)
	sysH := NewSystemHandler(svc)

	// Static assets
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

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
		r.Get("/allowlist", fwH.AllowListPage)
		r.Get("/blocklist", blockH.Page)
		r.Get("/dns", dnsH.Page)
		r.Get("/bandwidth", bwH.Page)
		r.Get("/settings", settingsH.Page)
	})

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Post("/login", authH.Login)
		r.Post("/logout", authH.Logout)

		r.Group(func(r chi.Router) {
			r.Use(APIAuthRequired(svc.Auth))
			r.Get("/me", authH.Me)
			r.Get("/dashboard", dashH.API)

			r.Route("/devices", func(r chi.Router) {
				r.Get("/", devH.List)
				r.Put("/{mac}", devH.Update)
			})

			r.Route("/firewall/rules", func(r chi.Router) {
				r.Get("/", fwH.List)
				r.Post("/", fwH.Create)
				r.Put("/{id}", fwH.Update)
				r.Delete("/{id}", fwH.Delete)
			})

			r.Route("/firewall/allowed-domains", func(r chi.Router) {
				r.Get("/", fwH.ListAllowedDomains)
				r.Post("/", fwH.CreateAllowedDomain)
				r.Put("/{id}", fwH.UpdateAllowedDomain)
				r.Delete("/{id}", fwH.DeleteAllowedDomain)
				r.Get("/ips", fwH.AllowedDomainIPs)
			})

			r.Route("/firewall/blocked-domains", func(r chi.Router) {
				r.Get("/", blockH.List)
				r.Post("/", blockH.Create)
				r.Put("/{id}", blockH.Update)
				r.Delete("/{id}", blockH.Delete)
			})

			r.Route("/dns/blocklist", func(r chi.Router) {
				r.Get("/", dnsH.List)
				r.Post("/", dnsH.Create)
				r.Post("/import", dnsH.Import)
				r.Delete("/{id}", dnsH.Delete)
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
				r.Get("/stats/summary", sysH.StatsSummary)
				r.Get("/stats/top-domains", sysH.StatsTopDomains)
				r.Get("/stats/top-clients", sysH.StatsTopClients)
				r.Get("/stats/timeseries", sysH.StatsTimeSeries)
				r.Post("/reboot", sysH.Reboot)
			})
		})
	})

	return r
}
