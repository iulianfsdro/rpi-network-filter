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
- **Domain-based allow-list** — allow by domain name, not just IP. Uses dnsmasq `nftset=` integration for automatic DNS-to-IP resolution. Matching is suffix-based: `tesla.com` covers all subdomains. `*.tesla.com` syntax is accepted and normalized.
- **Hard block-list** — domains that can never be allow-listed (e.g. firmware update endpoints). Enforced at two layers: the allow-list create path rejects matching domains with HTTP 409, and dnsmasq sinkholes them to `0.0.0.0` so they fail to resolve at all. Seeded with Tesla OTA/diagnostic endpoints out of the box.
- **Traffic monitor** — real-time view of DNS queries and blocked/allowed connections with filtering, search, and pagination. Quick-allow button is idempotent (safe to click twice).
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

## Quick start — zero-network first boot (recommended)

The Pi self-provisions on first power-on from the SD card alone. You never need
ethernet or a separate WiFi link: plug in the LTE modem, power on, wait, join
the `NetFilter` hotspot.

### 1. Flash Raspberry Pi OS Lite (64-bit, Trixie)

Use Raspberry Pi Imager. **Open Advanced Settings (gear icon):**
- hostname: `netfilter`
- set a user (e.g. `pi` + your password)
- enable SSH (password or public key)
- set locale / timezone
- **leave wireless LAN UNCONFIGURED** — `wlan0` must be free for AP mode

### 2. Build the binary

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o netfilterd-arm64 ./cmd/netfilterd
```

### 3. Stuff the bootfs partition

Re-insert the SD card so Windows mounts the `bootfs` partition (e.g. drive `E:`).
From Git Bash in the repo root:

```bash
scripts/prepare-sd.sh /e          # adjust drive letter
```

This copies the binary and `deploy/` directory onto the SD card, writes default
setup answers (`NetFilter` / `changeme123` / `US` / admin pass `netfilter` — edit
`E:/netfilter/answers.txt` to override), and injects a provisioning hook into the
Imager-generated `firstrun.sh`.

### 4. Boot

Eject the card, insert into the Pi, plug in the USB LTE modem, power on. First
boot runs in ~3–5 minutes: `netfilter-provision.service` installs packages,
writes configs, brings up `hostapd`/`dnsmasq`/`nftables`/`netfilterd`, then
self-disables.

### 5. Connect

1. Join the `NetFilter` SSID (default password `changeme123`).
2. Open <https://192.168.4.1:8443> (accept the self-signed cert).
3. Log in as `admin` / `netfilter` (change immediately in the UI).

### Troubleshooting

```bash
# After the Pi boots, log in with the user you set in Imager
sudo cat /var/log/netfilter-provision.log      # first-boot output
sudo cat /tmp/setup.log                         # setup.sh output
sudo cat /var/log/netfilter-bringup.log         # final service bring-up
sudo systemctl is-active hostapd dnsmasq nftables netfilterd nf-wlan0
```

---

## Manual install (existing Pi)

Already have a running Pi you want to convert? SSH in and run the setup script
against the repo's `deploy/` directory:

```bash
scp netfilterd-arm64 pi@<pi-ip>:/tmp/netfilterd
scp -r deploy/*      pi@<pi-ip>:/tmp/deploy/
ssh -t pi@<pi-ip> "sudo bash /tmp/deploy/setup.sh"
```

`setup.sh` prompts for SSID, hotspot password, country code, and admin password.
Packages, configs, binary, TLS cert, and the systemd unit are installed in one
pass. The final service bring-up is detached via `nohup` so an SSH-over-`wlan0`
session that gets dropped when `hostapd` seizes the radio does not strand the
provisioning mid-run.

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

## Block list (hard deny)

The block list is a separate table (`blocked_domains`) from the allow list and from the pi-hole-style `dns_blocklist`. Its purpose is to enforce *"this vendor must never reach my network, even by accident"*.

**Two layers of enforcement**

1. **Allow-list guard** — `POST /api/firewall/allowed-domains` (and the Allow button in the traffic monitor) calls `BlockedService.IsBlocked(domain)` before any insert. If the domain matches a `blocked_domains` entry (exact or suffix), the request returns HTTP 409 with the matched rule and reason, and the UI toasts the error.
2. **DNS sinkhole** — `DNSService.Apply` writes `address=/<domain>/0.0.0.0` for every enabled block entry to `/etc/dnsmasq.d/blocklist.conf`. dnsmasq's `address=` directive is suffix-matching, so `address=/tesla-cdn.com/0.0.0.0` also sinks `cdn1.tesla-cdn.com`.

**Match types**

- `suffix` (default) — matches the domain and all deeper subdomains. Accept `*.foo.com`, `foo.com`, or any equivalent form; input is normalized.
- `exact` — matches only the exact string.

**Seeded entries (Tesla firmware + remote service)**

On first boot, the v5 migration seeds the following entries. Remove any you don't want via the Block List UI:

| Domain | Match | Reason |
|---|---|---|
| `ota.vn.tesla.services` | exact | Tesla firmware update channel |
| `ota.cn.tesla.services` | exact | Tesla firmware update channel (China) |
| `firmware.vn.tesla.services` | suffix | Tesla firmware metadata |
| `software-update.tesla.com` | suffix | Tesla update orchestration |
| `dl.tesla.com` | exact | Tesla firmware blob CDN |
| `tesla-cdn.com` | suffix | Tesla asset and firmware CDN |
| `tesla-cdn.net` | suffix | Tesla asset and firmware CDN |
| `diag.vn.tesla.services` | exact | Tesla remote diagnostics |
| `remote-diagnostics.tesla.com` | suffix | Tesla remote service access |

**Limitations**

- The block list only protects traffic that actually flows through this appliance. If the blocked device has its own cellular modem (e.g. a Tesla with an active SIM), it will reach the blocked endpoints directly and this filter has no effect.
- TLS certificate pinning means you cannot MITM these connections to inspect content — blocking is all-or-nothing per hostname.
- Some vendors share infrastructure between firmware updates and normal app functionality. The seeded Tesla list blocks only firmware/diagnostic hostnames, preserving app functionality via `api.mp.tesla.services` and `fleet-api.*.cloud.tesla.com`.

## Schema versions

| Version | Purpose |
|---|---|
| v1 | Core tables (users, sessions, devices, firewall_rules, dns_blocklist, bandwidth_limits, settings, audit_log) |
| v2 | `query_log` table + indexes for persistent traffic history |
| v3 | `kv_store` for journalctl cursor state |
| v4 | `allowed_domains` table for dynamic allow-list via dnsmasq nftset integration |
| v5 | `blocked_domains` table + Tesla firmware endpoint seed data |

Migrations are idempotent and applied on startup. Adding new ones: append a SQL string to `migrations` in `internal/database/migrations.go` — the version is the slice index + 1.

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
