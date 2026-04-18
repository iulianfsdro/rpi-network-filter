package services

// Well-known DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) resolver IPs that
// modern browsers, mobile OSes, and some IoT devices will fall back to
// if their plaintext DNS (port 53) is blocked — completely sidestepping
// our dnsmasq and the per-policy nftable allow sets.
//
// Dropping these at the forward chain forces the client back onto our
// dnsmasq, which is the only place our per-policy allow-listing has a
// chance to be enforced.
//
// Kept deliberately small and well-known rather than pulling a huge
// community list; false positives here cost users more than missed
// edge-case resolvers. Update as needed.
var dohResolverIPs = []string{
	// Cloudflare
	"1.1.1.1",
	"1.0.0.1",
	// Google
	"8.8.8.8",
	"8.8.4.4",
	// Quad9
	"9.9.9.9",
	"149.112.112.112",
	// AdGuard
	"94.140.14.14",
	"94.140.15.15",
	// OpenDNS
	"208.67.222.222",
	"208.67.220.220",
	// CleanBrowsing
	"185.228.168.9",
	"185.228.169.9",
	// ControlD
	"76.76.2.0",
	"76.76.10.0",
}

// DoHResolverIPs returns the list of IPs to drop at the forward chain for
// tcp/443 (DoH) and udp/853 (DoT). Copied to prevent accidental mutation
// by callers.
func DoHResolverIPs() []string {
	out := make([]string, len(dohResolverIPs))
	copy(out, dohResolverIPs)
	return out
}
