package services

import (
	"strings"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

// TestBuildDNSConfig verifies the default-deny dnsmasq config: everything
// is sinkholed; only allow-listed domains get a server= line; connman is
// always resolvable; and a protected endpoint never gets a server= line
// even when it sneaks into the allow list.
func TestBuildDNSConfig(t *testing.T) {
	out := buildDNSConfig(
		[]string{"1.1.1.1"},
		[]string{"auth.tesla.com", "hermes-prd.ap.tesla.services", "maps-eu-prd.go.tesla.services"},
		[]string{"aa:bb:cc:dd:ee:ff"},
	)

	must := []string{
		"address=/#/0.0.0.0\n", // 0.0.0.0 sinkhole — NXDOMAIN destabilised the Tesla's
		//                         connman state in Tier-4; 0.0.0.0 keeps it settled.
		//                         server=/<specific>/ overrides correctly beat the # wildcard.
		"server=/auth.tesla.com/1.1.1.1",
		"server=/maps-eu-prd.go.tesla.services/1.1.1.1",
		"server=/connman.vn.tesla.services/1.1.1.1",
		"dhcp-host=aa:bb:cc:dd:ee:ff,set:open",
		"dhcp-option=tag:open,6,1.1.1.1",
	}
	for _, m := range must {
		if !strings.Contains(out, m) {
			t.Errorf("buildDNSConfig output is missing: %q", m)
		}
	}

	// A protected endpoint must NEVER get a resolvable server= line — it
	// stays sinkholed by address=/#/ even though it slipped into the allow
	// list passed in (defensive: the floor must hold at the DNS layer too).
	if strings.Contains(out, "server=/hermes-prd.ap.tesla.services/") {
		t.Errorf("protected endpoint got a resolvable server= line — DNS leak")
	}
}

// TestAllowedDomainsExcludesDisabled — a disabled filter_domain must not
// reach the DNS config (it is inert until enabled); the filter as a
// whole must also be enabled, otherwise its rows stay off-list.
func TestAllowedDomainsExcludesDisabled(t *testing.T) {
	db := memDB(t)
	fID := freshFilter(t, db, "TestFilter") // freshFilter creates with enabled=1
	mustExec(t, db, `INSERT INTO filter_domains (preset_id, domain, enabled) VALUES (?,'live.example.com',1)`, fID)
	mustExec(t, db, `INSERT INTO filter_domains (preset_id, domain, enabled) VALUES (?,'staged.example.com',0)`, fID)

	s := NewDNSService(db, executor.New(true), config.Config{DNSUpstream: "1.1.1.1"})
	got, err := s.allowedDomains()
	if err != nil {
		t.Fatalf("allowedDomains: %v", err)
	}
	set := map[string]bool{}
	for _, d := range got {
		set[d] = true
	}
	if !set["live.example.com"] {
		t.Errorf("enabled domain missing from allowedDomains: %v", got)
	}
	if set["staged.example.com"] {
		t.Errorf("disabled domain leaked into allowedDomains: %v", got)
	}

	// Now flip the filter off — even the enabled domain must drop out.
	mustExec(t, db, `UPDATE filters SET enabled=0 WHERE id=?`, fID)
	got, _ = s.allowedDomains()
	for _, d := range got {
		if d == "live.example.com" {
			t.Errorf("domain leaked while filter is OFF: %v", got)
		}
	}
}
