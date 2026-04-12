# rpi-network-filter

A Raspberry Pi 4 network filter appliance that acts as a WiFi hotspot with a default-deny firewall and web-based management UI. Built for controlling exactly which internet traffic is allowed through — ideal for kiosk browsers, embedded devices, IoT, or any scenario where you want fine-grained outbound control.

## How it works

```
[Client device] --WiFi--> [RPi4 hotspot] --NAT--> [LTE modem / WAN] --> Internet
                             wlan0                     eth1
```

- RPi4 broadcasts a WiFi hotspot (hostapd + dnsmasq)
- All forwarded traffic is **blocked by default** via nftables
- You allow traffic through two mechanisms:
  - **IP/port firewall rules** — classic allow rules for specific IPs and ports
  - **Domain allow-list** — add a domain (e.g. `mail.google.com`), dnsmasq resolves it and auto-populates an nftables IP set with a 1-hour timeout
- Web UI lets you manage everything from a browser on the hotspot

## Features

- **Default-deny firewall** — nothing gets through unless you allow it
- **Domain-based allow-list** — allow by domain name, not just IP. Uses dnsmasq `nftset=` integration for automatic DNS-to-IP resolution
- **Traffic monitor** — real-time view of DNS queries and blocked/allowed connections with filtering, search, and pagination
- **Statistics** — time-series charts and top-N lists for blocked, allowed, queries, and clients
- **Device management** — see connected devices, assign aliases, block individual devices
- **DNS blocklist** — Pi-hole-style domain blocking with bulk import (hosts file format)
- **Bandwidth limits** — per-device traffic shaping via `tc`
- **Hotspot settings** — change SSID, password, channel from the web UI
- **Persistent logging** — SQLite-backed traffic log with 30-day retention, survives reboots

## Screenshots

The web UI runs on port 80 over the hotspot network:

| Dashboard | Traffic Monitor | Allow List |
|-----------|----------------|------------|
| Device overview, connectivity test | Live DNS queries + firewall log | Domain-based allow rules with nftset |

## Requirements

- Raspberry Pi 4 (tested on Debian 13 / Trixie arm64)
- USB LTE modem or any WAN interface on `eth1`
- microSD card (8GB+)

## Quick start

### 1. Flash Raspberry Pi OS

Flash Debian 13 (Trixie) 64-bit to a microSD card. Enable SSH and set up a user (`pi`).

### 2. Build the binary

On your development machine (cross-compile for arm64):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o netfilterd-arm64 ./cmd/netfilterd
```

The binary is fully self-contained (~19MB) — no C toolchain or shared libraries needed on the Pi.

### 3. Run the setup script

Copy the binary and deploy directory to the Pi, then run the first-boot setup:

```bash
scp netfilterd-arm64 pi@<pi-ip>:/tmp/netfilterd
scp -r deploy/* pi@<pi-ip>:/tmp/deploy/

ssh pi@<pi-ip>
sudo bash /tmp/deploy/setup.sh
```

The setup script will:
- Install required packages (hostapd, dnsmasq, nftables, etc.)
- Configure the WiFi hotspot (prompts for SSID and password)
- Set up NAT routing and the default-deny firewall
- Install the binary and systemd service
- Create the admin user (prompts for password)
- Reboot into a fully working appliance

### 4. Connect and manage

1. Connect to the WiFi hotspot (default: `NetFilter`)
2. Open `http://192.168.4.1` in your browser
3. Log in with your admin credentials

## Architecture

```
cmd/netfilterd/          Entry point, CLI flags
internal/
  config/                YAML config loader with defaults
  database/              SQLite setup + versioned migrations
  executor/              Shell command executor (with dry-run mode)
  handlers/              HTTP handlers (chi router, Alpine.js templates)
  models/                Data models
  services/              Business logic (auth, firewall, DNS, traffic, etc.)
deploy/
  setup.sh               First-boot provisioning script
  hostapd-base.conf      Hotspot config template
  dnsmasq-base.conf      DNS/DHCP config template
  nftables-base.conf     Firewall base rules (default-deny)
  sysctl.conf            IP forwarding
web/
  static/                CSS (Pico.css), JS (Alpine.js, Chart.js)
  templates/             Go HTML templates
  embed.go               Embeds static + templates into the binary
```

## Tech stack

- **Go** — single binary, no runtime dependencies
- **SQLite** (via modernc.org/sqlite) — pure Go, no CGO needed
- **chi** — HTTP router
- **Alpine.js** — lightweight reactive UI
- **Pico.css** — minimal CSS framework
- **Chart.js** — statistics charts
- **nftables** — firewall rules
- **dnsmasq** — DNS/DHCP with nftset integration
- **hostapd** — WiFi access point

## Configuration

The config file lives at `/etc/netfilterd/config.yaml`:

```yaml
listen_addr: "192.168.4.1:80"
db_path: "/var/lib/netfilterd/netfilter.db"
wan_interface: "eth1"
lan_interface: "wlan0"
lan_subnet: "192.168.4.0/24"
lan_gateway: "192.168.4.1"
dhcp_range_start: "192.168.4.100"
dhcp_range_end: "192.168.4.250"
```

## CLI flags

```
netfilterd [flags]

  --config string     Config file path (default "/etc/netfilterd/config.yaml")
  --dry-run           Log system commands without executing
  --init-admin        Create initial admin user
  --reset-admin       Reset admin password
  --username string   Admin username (default "admin")
  --password string   Admin password
  --version           Print version
```

## Development

```bash
# Run locally in dry-run mode (no real firewall/network changes)
go run ./cmd/netfilterd --config config.yaml --dry-run

# Cross-compile for RPi4
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o netfilterd-arm64 ./cmd/netfilterd

# Deploy update to running Pi
scp netfilterd-arm64 pi@192.168.4.1:/tmp/netfilterd
ssh pi@192.168.4.1 "sudo systemctl stop netfilterd && sudo mv /tmp/netfilterd /usr/local/bin/netfilterd && sudo chmod +x /usr/local/bin/netfilterd && sudo systemctl start netfilterd"
```

## License

[MIT](LICENSE)
