#!/bin/bash
set -euo pipefail

# NetFilter Setup Script for Raspberry Pi 4 (Debian 13 / Trixie)
# WAN: USB LTE modem (eth1 / usb0 / enx*)
# LAN: Built-in WiFi (wlan0) as hotspot
#
# Expected workflow (see README):
#   scp netfilterd-arm64 pi@<ip>:/tmp/netfilterd
#   scp -r deploy/*      pi@<ip>:/tmp/deploy/
#   ssh pi@<ip> "sudo bash /tmp/deploy/setup.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

# Resolve where this script actually lives so paths don't depend on CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_SRC="${NETFILTERD_BIN:-/tmp/netfilterd}"

echo "================================================"
echo "  NetFilter - RPi4 Network Filter Router Setup"
echo "================================================"
echo ""
echo "WAN: USB LTE modem"
echo "LAN: Built-in WiFi hotspot (wlan0)"
echo "Policy: Default DENY — all client traffic blocked"
echo "        unless explicitly allowed via web UI"
echo ""

# --- Preflight ---------------------------------------------------------------

for f in hostapd-base.conf dnsmasq-base.conf nftables-base.conf sysctl.conf \
         netfilterd.service nf-wlan0.service; do
    [[ -f "$SCRIPT_DIR/$f" ]] || error "Missing $SCRIPT_DIR/$f — scp the full deploy/ dir to /tmp/deploy/"
done

[[ -f "$BINARY_SRC" ]] || error "Missing binary at $BINARY_SRC. Build on host: CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o netfilterd-arm64 ./cmd/netfilterd && scp netfilterd-arm64 pi@<ip>:/tmp/netfilterd"

# --- WAN detect --------------------------------------------------------------

info "Detecting LTE modem interface..."
WAN_IFACE=""
for cand in eth1 usb0; do
    if ip link show "$cand" &>/dev/null; then
        WAN_IFACE="$cand"
        break
    fi
done
if [[ -z "$WAN_IFACE" ]]; then
    WAN_IFACE="$(ip -o link show | awk -F': ' '/^[0-9]+: enx/ {print $2; exit}')"
fi
if [[ -z "$WAN_IFACE" ]]; then
    warn "LTE modem not detected."
    read -rp "WAN interface name [eth1]: " WAN_IFACE
    WAN_IFACE=${WAN_IFACE:-eth1}
fi
info "WAN interface: $WAN_IFACE"

# --- Prompts -----------------------------------------------------------------

read -rp "Hotspot SSID [NetFilter]: " AP_SSID
AP_SSID=${AP_SSID:-NetFilter}

read -rsp "Hotspot password [changeme123]: " AP_PASS; echo
AP_PASS=${AP_PASS:-changeme123}
if [[ ${#AP_PASS} -lt 8 ]]; then
    error "WPA2 password must be at least 8 characters"
fi

read -rp "WiFi country code (ISO 3166-1, e.g. US, GB, DE) [US]: " COUNTRY_CODE
COUNTRY_CODE=${COUNTRY_CODE:-US}
COUNTRY_CODE="${COUNTRY_CODE^^}"

read -rsp "Admin web UI password: " ADMIN_PASS; echo
[[ -z "$ADMIN_PASS" ]] && error "Admin password is required"

# --- Packages ----------------------------------------------------------------

info "Installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y hostapd dnsmasq nftables iw wireless-tools iproute2 \
    rfkill network-manager openssl ca-certificates

# --- Stop/unmask services before reconfiguring -------------------------------

info "Preparing services..."
systemctl stop hostapd dnsmasq netfilterd 2>/dev/null || true
systemctl unmask hostapd 2>/dev/null || true

# --- NetworkManager: leave wlan0 alone ---------------------------------------

info "Excluding wlan0 from NetworkManager (persists across reboots)..."
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/99-netfilter-unmanaged.conf << 'NMCONF'
[keyfile]
unmanaged-devices=interface-name:wlan0
NMCONF
# Intentionally NOT reloading NetworkManager here — a reload/restart would
# drop any SSH session coming in over wlan0 (the home-WiFi client link).
# The drop-in is applied on the next boot; for the current boot, nf-wlan0's
# ExecStartPre issues `nmcli device set wlan0 managed no` at runtime.

# --- systemd-resolved: free port 53 ------------------------------------------

info "Freeing port 53 from systemd-resolved..."
if systemctl list-unit-files systemd-resolved.service &>/dev/null; then
    systemctl disable --now systemd-resolved 2>/dev/null || true
fi
# Replace the symlinked resolv.conf with a static one pointing AT the
# public resolvers directly — NOT through dnsmasq. The Pi's own processes
# (apt, curl, etc.) need a working resolver, but dnsmasq runs default-
# deny for LAN clients and would NXDOMAIN every Pi query if 127.0.0.1
# were first in the list. LAN clients still query dnsmasq via DHCP-pushed
# DNS = the Pi's wlan0 IP; this resolv.conf is only consulted by the Pi
# itself.
if [[ -L /etc/resolv.conf ]] || [[ ! -s /etc/resolv.conf ]]; then
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf << 'RESOLV'
nameserver 1.1.1.1
nameserver 8.8.8.8
RESOLV
fi

# --- wlan0 static IP as a real systemd unit ----------------------------------

info "Installing nf-wlan0.service..."
cp "$SCRIPT_DIR/nf-wlan0.service" /etc/systemd/system/nf-wlan0.service

# Remove any legacy dhcpcd snippet from earlier setup runs.
if [[ -f /etc/dhcpcd.conf ]] && grep -q "NetFilter: wlan0 as access point" /etc/dhcpcd.conf; then
    warn "Removing legacy dhcpcd.conf stanza (now handled by nf-wlan0.service)"
    sed -i '/# NetFilter: wlan0 as access point/,/nohook wpa_supplicant/d' /etc/dhcpcd.conf
fi

# --- IP forwarding -----------------------------------------------------------

info "Enabling IP forwarding..."
cp "$SCRIPT_DIR/sysctl.conf" /etc/sysctl.d/99-netfilter.conf
sysctl -p /etc/sysctl.d/99-netfilter.conf >/dev/null

# --- Service configs ---------------------------------------------------------

info "Installing service configs..."

# hostapd — written via heredoc so special characters in the password
# (/, |, &, \) don't break sed escaping. Base conf is kept for netfilterd
# to reference when the user edits hotspot settings via the web UI.
mkdir -p /etc/hostapd
cat > /etc/hostapd/hostapd.conf << HOSTAPD
country_code=${COUNTRY_CODE}
interface=wlan0
driver=nl80211
ssid=${AP_SSID}
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=${AP_PASS}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
HOSTAPD
chmod 600 /etc/hostapd/hostapd.conf

if [[ -f /etc/default/hostapd ]] && ! grep -q '^DAEMON_CONF=' /etc/default/hostapd; then
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
elif [[ ! -f /etc/default/hostapd ]]; then
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' > /etc/default/hostapd
fi

# dnsmasq
cp "$SCRIPT_DIR/dnsmasq-base.conf" /etc/dnsmasq.conf
mkdir -p /etc/dnsmasq.d

# nftables
sed "s/eth1/${WAN_IFACE}/g" "$SCRIPT_DIR/nftables-base.conf" > /etc/nftables.conf
chmod 644 /etc/nftables.conf

# --- Install binary ----------------------------------------------------------

info "Installing netfilterd binary from $BINARY_SRC..."
install -m 0755 "$BINARY_SRC" /usr/local/bin/netfilterd
mkdir -p /etc/netfilterd /var/lib/netfilterd

# --- TLS cert ----------------------------------------------------------------

if [[ ! -f /etc/netfilterd/server.crt ]] || [[ ! -f /etc/netfilterd/server.key ]]; then
    info "Generating self-signed TLS certificate with SANs..."
    cat > /tmp/netfilter-openssl.cnf <<'CNF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = v3_req
x509_extensions    = v3_req

[dn]
C  = US
O  = NetFilter Appliance
CN = netfilter.local

[v3_req]
basicConstraints     = CA:TRUE
keyUsage             = digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage     = serverAuth
subjectAltName       = @alt_names

[alt_names]
DNS.1 = netfilter.local
DNS.2 = netfilter
IP.1  = 192.168.4.1
IP.2  = 127.0.0.1
CNF
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout /etc/netfilterd/server.key \
        -out /etc/netfilterd/server.crt \
        -config /tmp/netfilter-openssl.cnf \
        -extensions v3_req 2>/dev/null
    rm -f /tmp/netfilter-openssl.cnf
    chmod 600 /etc/netfilterd/server.key
    chmod 644 /etc/netfilterd/server.crt
fi

# --- App config --------------------------------------------------------------

cat > /etc/netfilterd/config.yaml << YAML
listen_addr: "192.168.4.1:8443"
use_tls: true
tls_cert: "/etc/netfilterd/server.crt"
tls_key: "/etc/netfilterd/server.key"
db_path: "/var/lib/netfilterd/netfilter.db"
wan_interface: "${WAN_IFACE}"
lan_interface: "wlan0"
lan_subnet: "192.168.4.0/24"
lan_gateway: "192.168.4.1"
dhcp_range_start: "192.168.4.100"
dhcp_range_end: "192.168.4.250"
dns_upstream: "1.1.1.1,8.8.8.8"
dry_run: false
log_level: "info"
YAML

# --- systemd units -----------------------------------------------------------

info "Installing systemd service..."
cp "$SCRIPT_DIR/netfilterd.service" /etc/systemd/system/netfilterd.service
systemctl daemon-reload

# --- Admin user --------------------------------------------------------------

info "Creating admin user..."
/usr/local/bin/netfilterd --config /etc/netfilterd/config.yaml \
    --init-admin --username admin --password "$ADMIN_PASS"

# --- WiFi unblock ------------------------------------------------------------

info "Unblocking WiFi radio..."
rfkill unblock wifi || true
iw reg set "$COUNTRY_CODE" || true

# --- Enable services (without starting yet) ----------------------------------

info "Enabling services..."
systemctl enable nf-wlan0 nftables hostapd dnsmasq netfilterd >/dev/null

# --- Detached bring-up -------------------------------------------------------
#
# Starting nf-wlan0 + hostapd takes wlan0 out of client mode, which kills any
# SSH session coming in over the home-WiFi link. We detach the final cascade
# via nohup so the Pi finishes on its own after the SSH connection drops.

BRINGUP_LOG=/var/log/netfilter-bringup.log
cat > /tmp/netfilter-bringup.sh << 'BRINGUP'
#!/bin/bash
set +e
echo "=== bringup $(date -Iseconds) ==="
systemctl restart nftables
systemctl start nf-wlan0
systemctl start hostapd
systemctl start dnsmasq
systemctl start netfilterd
sleep 3
for unit in nf-wlan0 nftables hostapd dnsmasq netfilterd; do
    printf "  %-12s %s\n" "$unit" "$(systemctl is-active "$unit")"
done
ip -4 -o addr show wlan0
BRINGUP
chmod +x /tmp/netfilter-bringup.sh

echo ""
echo "================================================"
echo "  Ready to bring up the hotspot"
echo "================================================"
echo ""
echo "  Hotspot SSID:  ${AP_SSID}"
echo "  Country code:  ${COUNTRY_CODE}"
echo "  Web UI:        https://192.168.4.1:8443"
echo "  Admin user:    admin"
echo ""
echo "  WAN interface: ${WAN_IFACE}"
echo "  LAN interface: wlan0 → 192.168.4.1/24 (hotspot)"
echo ""
echo "  Heads-up: the final step will take wlan0 into AP mode."
echo "  If you're SSHed in over wlan0, your session will drop."
echo "  The bring-up runs detached and continues on its own."
echo ""
echo "  Bring-up log:  ${BRINGUP_LOG}"
echo "  After it settles, connect a device to the '${AP_SSID}' SSID"
echo "  and open https://192.168.4.1:8443"
echo ""
echo "================================================"

info "Detaching final bring-up... (SSH may drop in a few seconds)"
nohup /tmp/netfilter-bringup.sh > "$BRINGUP_LOG" 2>&1 < /dev/null &
disown || true
sleep 1
exit 0
