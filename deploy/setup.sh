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

info "Excluding wlan0 from NetworkManager..."
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/99-netfilter-unmanaged.conf << 'NMCONF'
[keyfile]
unmanaged-devices=interface-name:wlan0
NMCONF
systemctl reload NetworkManager 2>/dev/null || systemctl restart NetworkManager || true

# --- systemd-resolved: free port 53 ------------------------------------------

info "Freeing port 53 from systemd-resolved..."
if systemctl list-unit-files systemd-resolved.service &>/dev/null; then
    systemctl disable --now systemd-resolved 2>/dev/null || true
fi
# Replace the symlinked resolv.conf with a static one pointing at our dnsmasq.
if [[ -L /etc/resolv.conf ]] || [[ ! -s /etc/resolv.conf ]]; then
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf << 'RESOLV'
nameserver 127.0.0.1
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
    info "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/netfilterd/server.key \
        -out /etc/netfilterd/server.crt \
        -days 3650 -nodes \
        -subj "/CN=netfilter.local" 2>/dev/null
    chmod 600 /etc/netfilterd/server.key
fi

# --- App config --------------------------------------------------------------

cat > /etc/netfilterd/config.yaml << YAML
listen_addr: "192.168.4.1:8443"
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

# --- Enable and start --------------------------------------------------------

info "Enabling and starting services..."
systemctl enable nf-wlan0 nftables hostapd dnsmasq netfilterd
systemctl start nf-wlan0
systemctl start nftables
systemctl start hostapd
systemctl start dnsmasq
systemctl start netfilterd

# --- Status summary ----------------------------------------------------------

echo ""
echo "------------------------------------------------"
echo "  Service status"
echo "------------------------------------------------"
for unit in nf-wlan0 nftables hostapd dnsmasq netfilterd; do
    state=$(systemctl is-active "$unit" 2>/dev/null || echo "inactive")
    printf "  %-12s %s\n" "$unit" "$state"
done
echo "  wlan0 addr:  $(ip -4 -o addr show wlan0 2>/dev/null | awk '{print $4}' || echo 'none')"

echo ""
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "  Hotspot SSID:  ${AP_SSID}"
echo "  Country code:  ${COUNTRY_CODE}"
echo "  Web UI:        https://192.168.4.1:8443"
echo "  Admin user:    admin"
echo ""
echo "  WAN interface: ${WAN_IFACE}"
echo "  LAN interface: wlan0 (hotspot, 192.168.4.1/24)"
echo ""
echo "  Default policy: ALL client traffic BLOCKED"
echo "  Add accept rules via the web UI to allow traffic."
echo ""
echo "  Troubleshoot: sudo journalctl -u hostapd -u dnsmasq -u netfilterd -e"
echo "================================================"
