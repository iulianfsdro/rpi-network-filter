package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/database"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
	"github.com/iulianfsdro/rpi-network-filter/internal/handlers"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
	"github.com/iulianfsdro/rpi-network-filter/web"
)

func main() {
	configPath := flag.String("config", "/etc/netfilterd/config.yaml", "config file path")
	dryRun := flag.Bool("dry-run", false, "log system commands without executing")
	initAdmin := flag.Bool("init-admin", false, "create initial admin user")
	resetAdmin := flag.Bool("reset-admin", false, "reset admin password")
	adminUser := flag.String("username", "admin", "admin username")
	adminPass := flag.String("password", "", "admin password")
	version := flag.Bool("version", false, "print version")
	flag.Parse()

	if *version {
		fmt.Println("netfilterd v0.1.0")
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *dryRun {
		cfg.DryRun = true
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0755); err != nil {
		log.Fatalf("Failed to create DB directory: %v", err)
	}

	db, err := database.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	exec := executor.New(cfg.DryRun)

	svc := services.New(db, exec, cfg)

	if *initAdmin || *resetAdmin {
		if *adminPass == "" {
			log.Fatal("--password is required with --init-admin or --reset-admin")
		}
		if *initAdmin {
			if err := svc.Auth.CreateUser(*adminUser, *adminPass); err != nil {
				log.Fatalf("Failed to create admin: %v", err)
			}
			log.Printf("Admin user '%s' created", *adminUser)
		} else {
			if err := svc.Auth.ResetPassword(*adminUser, *adminPass); err != nil {
				log.Fatalf("Failed to reset password: %v", err)
			}
			log.Printf("Password reset for '%s'", *adminUser)
		}
		os.Exit(0)
	}

	// Write the captive-check spoof override before ApplyAll so the
	// dnsmasq reload that FirewallService.Apply triggers picks it up
	// without an extra reload.
	if err := svc.Spoof.WriteDnsmasqConf(); err != nil {
		log.Printf("[WARN] Failed to write spoof dnsmasq override: %v", err)
	}

	// Apply all rules on startup
	svc.ApplyAll()

	// Start background services
	go svc.Network.StartScanner()
	go func() {
		if err := svc.Spoof.ListenAndServe(); err != nil {
			log.Printf("[SPOOF] listener exited: %v", err)
		}
	}()
	svc.TrafficLog.StartTailing()
	// Periodic re-resolve of allow-list domains so the per-policy nft sets
	// stay populated even when clients cache DNS answers past the dnsmasq
	// TTL. 6 hours is aggressive enough to matter, rare enough to be cheap.
	svc.Policy.StartRefreshLoop(6 * time.Hour)

	router := handlers.NewRouterWithFS(db, svc, cfg, web.Content)

	if cfg.DryRun {
		log.Printf("DRY-RUN mode enabled — system commands will be logged but not executed")
	}

	log.Printf("Starting netfilterd on %s", cfg.ListenAddr)

	useTLS := cfg.UseTLS
	if useTLS {
		if _, err := os.Stat(cfg.TLSCert); os.IsNotExist(err) {
			log.Printf("TLS enabled but cert not found at %s, falling back to HTTP", cfg.TLSCert)
			useTLS = false
		}
	}

	if useTLS {
		log.Printf("HTTPS enabled")
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		server := &http.Server{
			Addr:      cfg.ListenAddr,
			Handler:   router,
			TLSConfig: tlsCfg,
		}
		if err := server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		log.Printf("HTTP mode (no TLS)")
		if err := http.ListenAndServe(cfg.ListenAddr, router); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}
