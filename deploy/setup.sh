#!/bin/bash
set -e

# NetFilter Setup Script for Raspberry Pi 4
# WAN: USB LTE modem (eth1)
# LAN: Built-in WiFi (wlan0) as hotspot

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check root
[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

echo "================================================"
echo "  NetFilter - RPi4 Network Filter Router Setup"
echo "================================================"
echo ""
echo "WAN: USB LTE modem"
echo "LAN: Built-in WiFi hotspot (wlan0)"
echo "Policy: Default DENY — all client traffic blocked"
echo "        unless explicitly allowed via web UI"
echo ""

# Detect WAN interface from USB modem
info "Detecting LTE modem interface..."
WAN_IFACE=""
for iface in eth1 usb0 enx*; do
    if ip link show "$iface" &>/dev/null; then
        WAN_IFACE="$iface"
        break
    fi
done

if [ -z "$WAN_IFACE" ]; then
    warn "LTE modem not detected. Plug in the modem and re-run, or enter interface name."
    read -p "WAN interface name [eth1]: " WAN_IFACE
    WAN_IFACE=${WAN_IFACE:-eth1}
fi
info "WAN interface: $WAN_IFACE"

# Get hotspot config
read -p "Hotspot SSID [NetFilter]: " AP_SSID
AP_SSID=${AP_SSID:-NetFilter}
read -sp "Hotspot password [changeme123]: " AP_PASS
echo ""
AP_PASS=${AP_PASS:-changeme123}

read -sp "Admin web UI password: " ADMIN_PASS
echo ""
[ -z "$ADMIN_PASS" ] && error "Admin password is required"

# Phase 1: Install packages
info "Installing packages..."
apt update
apt install -y hostapd dnsmasq nftables iw wireless-tools iproute2 curl

# Install Go
if ! command -v go &>/dev/null; then
    info "Installing Go..."
    GO_VERSION="1.22.5"
    ARCH=$(dpkg --print-architecture)
    curl -Lo /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/golang.sh
fi
info "Go version: $(go version)"

# Phase 2: Stop and unmask services
info "Preparing services..."
systemctl stop hostapd dnsmasq 2>/dev/null || true
systemctl unmask hostapd 2>/dev/null || true

# Phase 3: Configure wlan0 with static IP
info "Configuring wlan0 static IP..."
if ! grep -q "interface wlan0" /etc/dhcpcd.conf 2>/dev/null; then
    cat >> /etc/dhcpcd.conf << 'DHCPCD'

# NetFilter: wlan0 as access point
interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
DHCPCD
fi

# Phase 4: Enable IP forwarding
info "Enabling IP forwarding..."
cp deploy/sysctl.conf /etc/sysctl.d/99-netfilter.conf
sysctl -p /etc/sysctl.d/99-netfilter.conf

# Phase 5: Install base configs
info "Installing service configs..."

# hostapd
sed "s/ssid=NetFilter/ssid=${AP_SSID}/" deploy/hostapd-base.conf | \
sed "s/wpa_passphrase=changeme123/wpa_passphrase=${AP_PASS}/" > /etc/hostapd/hostapd.conf

# Make sure hostapd uses our config
if ! grep -q "DAEMON_CONF" /etc/default/hostapd 2>/dev/null; then
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
fi

# dnsmasq
cp deploy/dnsmasq-base.conf /etc/dnsmasq.conf
mkdir -p /etc/dnsmasq.d

# nftables — update WAN interface name
sed "s/eth1/${WAN_IFACE}/g" deploy/nftables-base.conf > /etc/nftables.conf

# Phase 6: Download frontend assets
info "Downloading frontend assets..."
curl -sLo web/static/css/pico.min.css "https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css"
curl -sLo web/static/js/alpine.min.js "https://cdn.jsdelivr.net/npm/alpinejs@3/dist/cdn.min.js"

# Phase 7: Build Go binary
info "Building netfilterd..."
export PATH=$PATH:/usr/local/go/bin
cd "$(dirname "$0")/.."
go mod tidy
go build -o /usr/local/bin/netfilterd ./cmd/netfilterd/
info "Binary installed at /usr/local/bin/netfilterd"

# Phase 8: Generate TLS certificate
info "Generating self-signed TLS certificate..."
mkdir -p /etc/netfilterd /var/lib/netfilterd
openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/netfilterd/server.key \
    -out /etc/netfilterd/server.crt \
    -days 3650 -nodes \
    -subj "/CN=netfilter.local" 2>/dev/null

# Phase 9: Write config
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

# Phase 10: Install systemd service
info "Installing systemd service..."
cp deploy/netfilterd.service /etc/systemd/system/
systemctl daemon-reload

# Phase 11: Create admin user
info "Creating admin user..."
/usr/local/bin/netfilterd --config /etc/netfilterd/config.yaml --init-admin --username admin --password "$ADMIN_PASS"

# Phase 12: Enable and start services
info "Starting services..."
systemctl enable nftables hostapd dnsmasq netfilterd
systemctl start nftables
systemctl start hostapd
systemctl start dnsmasq
systemctl start netfilterd

echo ""
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "  Hotspot SSID:  ${AP_SSID}"
echo "  Web UI:        https://192.168.4.1:8443"
echo "  Admin user:    admin"
echo ""
echo "  WAN interface: ${WAN_IFACE} (LTE modem)"
echo "  LAN interface: wlan0 (hotspot)"
echo ""
echo "  Default policy: ALL client traffic BLOCKED"
echo "  Add accept rules in the Firewall page to"
echo "  allow specific traffic through."
echo ""
echo "  LTE modem admin: http://192.168.8.1"
echo "================================================"
