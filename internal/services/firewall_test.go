package services

import (
	"strings"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
)

// TestGenerateConfig_V3Shape verifies the generated nftables ruleset has
// the V3 shape: the filtered device's :443 is redirected to the SNI proxy
// and :80 DNAT'd to the connman spoof; trusted devices get a forward
// accept; blocked devices get a hard drop; the forward chain is default-
// deny; and none of the removed V2 machinery (per-policy sets/chains,
// DoH set) remains. Unknown devices have no row — the default policy drop
// catches them.
func TestGenerateConfig_V3Shape(t *testing.T) {
	s := &FirewallService{cfg: config.Config{
		LANInterface: "wlan0",
		WANInterface: "eth1",
		LANGateway:   "192.168.4.1",
		SNIProxyPort: 8444,
		DNSUpstream:  "1.1.1.1,8.8.8.8",
	}}
	snap := deviceSnapshot{
		filtered: []string{"0c:29:8f:93:2a:08"}, // Tesla
		open:     []string{"aa:bb:cc:dd:ee:ff"}, // laptop
		blocked:  []string{"11:22:33:44:55:66"}, // hostile device
	}
	out := s.generateConfig(nil, snap)

	must := []string{
		`ether saddr 0c:29:8f:93:2a:08 tcp dport 443 redirect to :8444`,
		`ether saddr 0c:29:8f:93:2a:08 tcp dport 80 dnat to 192.168.4.1`,
		`ether saddr aa:bb:cc:dd:ee:ff accept`, // open passthrough
		`ether saddr 11:22:33:44:55:66 drop`,   // blocked device
		`type filter hook forward priority filter; policy drop;`,
		// Open device's DNS is DNAT'd to the upstream so it bypasses the
		// Pi's default-deny dnsmasq regardless of cached DHCP lease.
		`ether saddr aa:bb:cc:dd:ee:ff udp dport 53 dnat to 1.1.1.1:53`,
		`ether saddr aa:bb:cc:dd:ee:ff tcp dport 53 dnat to 1.1.1.1:53`,
	}
	for _, m := range must {
		if !strings.Contains(out, m) {
			t.Errorf("generated nftables config is missing:\n  %q", m)
		}
	}

	mustNot := []string{"pol_", "doh_resolvers", "@pol"}
	for _, m := range mustNot {
		if strings.Contains(out, m) {
			t.Errorf("generated config still contains a removed V2 construct: %q", m)
		}
	}

	// A filtered device must NOT have a blanket forward accept — its web
	// traffic is intercepted in prerouting, everything else is dropped.
	if strings.Contains(out, "ether saddr 0c:29:8f:93:2a:08 accept") {
		t.Errorf("filtered device must not have a forward-chain accept rule")
	}
}
