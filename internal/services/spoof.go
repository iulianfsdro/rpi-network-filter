package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

// Tesla MCU3 polls connman.vn.tesla.services as its captive-portal /
// connectivity probe and declares the WiFi link "online" only when it
// gets a 200 with these headers. Packet capture confirmed the probe is
// plain HTTP on tcp/80.
//
// The Tesla refuses to connect to a private (RFC1918) IP for the check —
// a check domain resolving to a private address is the fingerprint of
// DNS hijacking, which connman's captive-portal detector rejects before
// it ever opens a socket. So we do NOT hijack DNS. connman resolves to
// its real public CloudFront IP (which the Tesla connects to happily),
// and the firewall's nat prerouting chain transparently DNATs that :80
// connection to this responder. See FirewallService.generateConfig.
const (
	spoofConnManHost = "connman.vn.tesla.services"
	// Legacy DNS-hijack override written by earlier versions. Removed on
	// startup — hijacking connman to the Pi's private IP tripped the
	// Tesla's captive-portal detector and the car never connected.
	spoofDnsmasqPath = "/etc/dnsmasq.d/netfilter-spoof.conf"
)

// Keys are the EXACT case the Tesla connman expects (capital M in
// "ConnMan"), matching the proven tesla-android reference config. They
// are written via direct map assignment in handle() — not Header.Set,
// which would canonicalise "X-ConnMan-Status" down to "X-Connman-Status"
// and (connman matches case-sensitively) make the car flag a captive
// portal.
var spoofConnManHeaders = map[string]string{
	"X-ConnMan-Status": "online",
	"X-Cache":          "Hit from cloudfront",
}

// SpoofService runs the captive-check responder (currently just Tesla
// connman). The Tesla's :80 traffic is steered here by a firewall DNAT
// rule; this service just answers it.
type SpoofService struct {
	cfg  config.Config
	exec *executor.Executor
}

func NewSpoofService(cfg config.Config, exec *executor.Executor) *SpoofService {
	return &SpoofService{cfg: cfg, exec: exec}
}

// EnsureNoDnsmasqHijack removes the legacy address= override if present.
// The connman spoof now relies on transparent DNAT (firewall prerouting),
// which requires connman.vn.tesla.services to resolve to its real public
// IP — the Tesla will not connect to a private address for its check.
// Idempotent: a no-op once the file is gone.
func (s *SpoofService) EnsureNoDnsmasqHijack() error {
	if _, err := os.Stat(spoofDnsmasqPath); err != nil {
		return nil // already absent
	}
	if err := os.Remove(spoofDnsmasqPath); err != nil {
		return fmt.Errorf("remove stale spoof override %s: %w", spoofDnsmasqPath, err)
	}
	if _, err := s.exec.Run("systemctl", "restart", "dnsmasq"); err != nil {
		return fmt.Errorf("restart dnsmasq after removing spoof override: %w", err)
	}
	log.Printf("[SPOOF] removed legacy DNS hijack %s; connman resolves to its real IP now", spoofDnsmasqPath)
	return nil
}

// newServer builds the shared http.Server (same handler + timeouts) for
// both the plain-HTTP and HTTPS listeners.
func (s *SpoofService) newServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

// ListenAndServe binds tcp/80 on cfg.LANGateway — the DNAT target for the
// Tesla's connman probe. Blocks; intended to run in its own goroutine.
func (s *SpoofService) ListenAndServe() error {
	addr := net.JoinHostPort(s.cfg.LANGateway, "80")
	log.Printf("[SPOOF] captive-check responder listening on http://%s (host %s)", addr, spoofConnManHost)
	return s.newServer(addr).ListenAndServe()
}

// ListenAndServeTLS binds tcp/443 with a self-signed cert. connman's probe
// is HTTP, so this is a belt-and-braces listener for the case a firmware
// revision switches to HTTPS. Blocks; intended to run in its own goroutine.
func (s *SpoofService) ListenAndServeTLS() error {
	cert, err := selfSignedCert(spoofConnManHost)
	if err != nil {
		return fmt.Errorf("generate spoof TLS cert: %w", err)
	}
	addr := net.JoinHostPort(s.cfg.LANGateway, "443")
	srv := s.newServer(addr)
	srv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
	}
	log.Printf("[SPOOF] captive-check TLS responder listening on https://%s (host %s)", addr, spoofConnManHost)
	return srv.ListenAndServeTLS("", "")
}

// selfSignedCert builds an in-memory self-signed certificate for host.
// Regenerated on every boot — connman doesn't pin our cert.
func selfSignedCert(host string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// handle answers every request on the spoof listeners with the connman
// "online" 200. tcp/80 + tcp/443 on the Pi exist solely for this spoof,
// so the response is unconditional. Host + scheme are logged so a real
// Tesla probe shows up in the journal as evidence.
func (s *SpoofService) handle(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// Direct map assignment bypasses Go's MIME canonicalisation so the
	// keys go out on the wire with their literal case (X-ConnMan-Status).
	hdr := w.Header()
	for k, v := range spoofConnManHeaders {
		hdr[k] = []string{v}
	}
	w.WriteHeader(http.StatusOK)
	log.Printf("[SPOOF] %s %s://%s%s → 200 (client=%s)", r.Method, scheme, r.Host, r.URL.Path, r.RemoteAddr)
}
