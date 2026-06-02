package services

import (
	"strings"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

// TestMergeARP_LiveOverridesLeasesIP — when the DHCP leases file has
// seeded a MAC at the old IP (the bug that caused the Tesla device row to
// keep reappearing at 192.168.4.233 after a delete even though the live
// lease was .234), the next scan's parseARP must overwrite that with the
// IP actually showing in /proc/net/arp. Without this, deleting a device
// would resurrect its OLD IP every tick.
func TestMergeARP_LiveOverridesLeasesIP(t *testing.T) {
	const tesla = "0C:29:8F:93:2A:08"
	// Devices map seeded by parseDHCPLeases — the leases file still
	// pointed Tesla at .233 even though the kernel has a fresh ARP for
	// .234 on the same MAC.
	devices := map[string]*models.Device{
		tesla: {MACAddress: tesla, IPAddress: "192.168.4.233", Hostname: "Tesla"},
	}
	// Real /proc/net/arp shape: IP HWtype Flags HWaddress Mask Device.
	// Flags 0x2 = REACHABLE.
	arp := `IP address       HW type     Flags       HW address            Mask     Device
192.168.4.234    0x1         0x2         0c:29:8f:93:2a:08     *        wlan0
`
	mergeARP(devices, strings.NewReader(arp), "wlan0")

	got := devices[tesla].IPAddress
	if got != "192.168.4.234" {
		t.Errorf("live ARP did not override stale leases IP: got %q, want 192.168.4.234", got)
	}
	// Hostname from DHCP must survive the override — ARP has no hostname.
	if devices[tesla].Hostname != "Tesla" {
		t.Errorf("DHCP hostname clobbered by ARP override: got %q, want %q",
			devices[tesla].Hostname, "Tesla")
	}
}

// TestMergeARP_SkipsIncomplete — kernel writes Flags=0x0 +
// HWaddress=00:00:00:00:00:00 for an IP it's still resolving. Those rows
// must never enter the map; otherwise they'd surface as a phantom device
// with a null MAC (the bug migration v17 cleaned up after).
func TestMergeARP_SkipsIncomplete(t *testing.T) {
	devices := map[string]*models.Device{}
	arp := `IP address       HW type     Flags       HW address            Mask     Device
192.168.4.99     0x1         0x0         00:00:00:00:00:00     *        wlan0
`
	mergeARP(devices, strings.NewReader(arp), "wlan0")

	if len(devices) != 0 {
		t.Errorf("incomplete ARP entry leaked into devices map: %+v", devices)
	}
}

// TestMergeARP_RestrictsToLANIface — entries on a different interface
// (eth0/usb0/eth1) must be ignored. We only care about LAN-side clients.
func TestMergeARP_RestrictsToLANIface(t *testing.T) {
	devices := map[string]*models.Device{}
	arp := `IP address       HW type     Flags       HW address            Mask     Device
1.2.3.4          0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth1
`
	mergeARP(devices, strings.NewReader(arp), "wlan0")

	if len(devices) != 0 {
		t.Errorf("entry from wrong interface (eth1) leaked when lanIface=wlan0: %+v", devices)
	}
}

// TestMergeARP_InsertsNewMAC — for a MAC NOT seeded by parseDHCPLeases
// (e.g. a static-IP device that never DHCP'd), the ARP entry should
// create a fresh row.
func TestMergeARP_InsertsNewMAC(t *testing.T) {
	devices := map[string]*models.Device{}
	arp := `IP address       HW type     Flags       HW address            Mask     Device
192.168.4.50     0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
`
	mergeARP(devices, strings.NewReader(arp), "wlan0")

	const mac = "AA:BB:CC:DD:EE:FF"
	d, ok := devices[mac]
	if !ok {
		t.Fatalf("ARP-only MAC %q never inserted: %+v", mac, devices)
	}
	if d.IPAddress != "192.168.4.50" {
		t.Errorf("ARP-only insert IP = %q, want 192.168.4.50", d.IPAddress)
	}
}
