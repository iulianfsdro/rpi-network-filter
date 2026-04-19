# rpi-network-filter

A Raspberry Pi 4 network-filter appliance. It runs a WiFi hotspot with a
default-deny firewall and a web-based management UI, so every outbound
packet from every device on the hotspot has to be explicitly allowed.
Designed for IoT containment, locking down a Tesla to a minimum set of
endpoints, or anywhere you want fine-grained outbound control.

```
[Client devices] --WiFi--> [RPi4 hotspot] --NAT--> [LTE modem / WAN] --> Internet
                              wlan0                      eth1
```

---

## What v2 actually does

Per-device policies. Each policy has its own allow list and its own
nftables IP set. A device's MAC maps to exactly one policy; unmapped
devices fall through to the `Default` policy.

Three policy modes:

| Mode | Behaviour |
|---|---|
| `strict` | Accept only IPs resolved from the policy's allow list. Drop everything else. |
| `permissive` | Accept allow-list IPs; on a miss, fall through to the `Default` policy's chain. |
| `open` | Accept everything. Still honours the global hard block-list and DoH/DoT chokepoint. For trusted devices (owner phone, laptop, TV). |

Three seeded policies out of the box:

- **Default** — `strict` + empty → every unassigned device is **blocked by default**.
- **Tesla** — `strict` with the Preset B allow-list (connman, auth, managed-charging, go.tesla.services, maps.googleapis.com) so the car can navigate, Supercharge, play music, and auth — but can't push firmware, change config, rotate features, or stream telemetry / Sentry clips home.
- **Open** — trusted devices bypass the allow list.

On top of that:

- **Hard block-list** (`blocked_domains`) — DNS-sinkholed globally, pre-empts every policy. ~60 Tesla OTA / Hermes / telemetry / surveillance / engineering / corporate endpoints seeded at install (see [Block list](#block-list-hard-deny)).
- **DoH/DoT chokepoint** — 14 well-known encrypted-DNS resolvers (Cloudflare, Google, Quad9, AdGuard, OpenDNS, CleanBrowsing, ControlD) dropped at the forward chain on tcp/443 + udp/853 so clients can't sidestep dnsmasq.
- **Proactive resolve** — adding a domain to an allow list fires a synchronous DNS query through the local dnsmasq before the HTTP response returns, so the nft set is populated for the client's first connection (fixes the v1 "allowed but still blocked" race).
- **6 h re-resolve cron** — walks every enabled allow-list entry and refreshes the per-policy sets; 30-day nft set timeouts mean long-idle TLS connections don't break between polls.
- **Traffic monitor splits DNS events from forward-chain decisions** so "blocked" and "allowed" counters mean what they say.
- **Real HTTPS** via DuckDNS + Let's Encrypt DNS-01 — green-lock on every device including Tesla's locked-down Chromium. No CA install on clients.

---

## Requirements

- Raspberry Pi 4 (tested on Debian 13 / Trixie arm64)
- USB LTE modem (or any WAN interface — defaults to `eth1`)
- microSD card (8 GB+)
- Go 1.22+ on your build machine

---

## Quick start — zero-network first boot

The Pi self-provisions on first power-on from the SD card alone. You
never need transitional ethernet or a separate WiFi link: plug in the
LTE modem, power on, wait ~5 minutes, join the `NetFilter` hotspot.

### 1. Flash Raspberry Pi OS Lite (64-bit, Trixie)

Use Raspberry Pi Imager. **Customise** (gear icon):

- hostname: `netfilter`
- user: `pi` + a password you remember
- SSH: enabled (password or public key)
- locale / timezone
- **leave wireless LAN UNCONFIGURED** — `wlan0` must stay free for AP mode

### 2. Build the binary

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o netfilterd-arm64 ./cmd/netfilterd
```

Single ~19 MB static binary, no CGO.

### 3. Stuff the bootfs partition

Reinsert the SD card so Windows mounts the `bootfs` partition (e.g. `E:`).
From Git Bash in the repo root:

```bash
scripts/prepare-sd.sh /e       # adjust drive letter
```

Copies the binary + `deploy/` dir to `/boot/firmware/netfilter/`, writes
default answers (SSID `NetFilter`, hotspot pw `changeme123`, country `US`,
admin pw `netfilter` — edit `E:/netfilter/answers.txt` to override), and
injects a provisioning hook into Imager's cloud-init `user-data`.

### 4. Boot

Eject, insert into the Pi, **plug in the USB LTE modem**, power on.
First boot takes ~3–5 minutes while `netfilter-provision.service`
installs packages, writes configs, builds the systemd stack, and
brings up hostapd / dnsmasq / nftables / netfilterd.

### 5. Connect + log in

1. Join the `NetFilter` SSID (default password `changeme123`).
2. Open <https://192.168.4.1:8443> (accept the self-signed cert warning — it goes away after [step 6](#6-real-https-optional)).
3. Log in as `admin` / `netfilter`. Change the password in Settings immediately.

### 6. Real HTTPS (optional but recommended)

Self-signed certs break Tesla's Chromium and annoy every other browser.
Swap for a real Let's Encrypt cert via DuckDNS DNS-01:

1. Sign up at <https://www.duckdns.org>, pick a subdomain, copy the token.
2. From Git Bash:

   ```bash
   scp scripts/setup-letsencrypt.sh pi@192.168.4.1:/tmp/
   ssh -t pi@192.168.4.1 "sudo bash /tmp/setup-letsencrypt.sh YOURNAME.duckdns.org YOUR-TOKEN"
   ```

3. The script installs `acme.sh`, issues a real cert, deploys it to
   `/etc/netfilterd/`, sets up daily auto-renewal, and tells dnsmasq
   to resolve your hostname locally to `192.168.4.1`.
4. Every device on the hotspot (Tesla included) now trusts
   `https://YOURNAME.duckdns.org:8443` out of the box.

### Troubleshooting

```bash
# on the Pi, logged in as the user you set in Imager
sudo systemctl is-active nf-wlan0 nftables hostapd dnsmasq netfilterd
sudo cat /var/log/netfilter-provision.log     # first-boot
sudo journalctl -u netfilterd -n 80 --no-pager
sudo nft list chain inet filter forward        # verify vmap dispatch
```

---

## Using the appliance

### Assign devices to policies

1. Each device that joins the hotspot shows up at `/devices`.
2. For each one, pick a policy from the dropdown:
   - **Open** for devices you own and trust (your phone, laptop, TV).
   - **Tesla** for every Tesla WiFi interface (cars often advertise two: MCU + AP board).
   - **Default** (or leave unassigned) for anything you haven't vetted yet — it will be blocked.

### Edit policy allow lists

Go to `/policies`, expand a policy, add or remove domains. Entries are
suffix-matched by default: `tesla.com` covers `x.tesla.com`, `a.b.tesla.com`, etc.
Leading `*.` is accepted and stripped. On add, the daemon synchronously
resolves the domain via the local dnsmasq so the nft set is populated
before your HTTP response returns.

### Traffic monitor

`/traffic` has three tabs:

- **All** — every event.
- **DNS queries** — dnsmasq's query log (what resolvers asked for what).
- **Firewall decisions** — nflog output with the policy that produced each verdict. Log prefix is `[NETFILTER-ACCEPT pol=Name]`, `[NETFILTER-DROP pol=Name]`, or `[NETFILTER-DROP-DOH]` / `[NETFILTER-DROP-DOT]` for the chokepoint.

Clear Log resets the counters; handy after you flip a device from blocked
to Open so the Dashboard stops showing historical drops.

---

## Architecture

```
cmd/netfilterd/          Entry point, CLI flags
internal/
  config/                YAML config loader
  database/              SQLite + versioned migrations (v1 → v10)
  executor/              Shell command wrapper (with dry-run)
  handlers/              HTTP handlers (chi router)
  models/                Data models (Policy, PolicyDomain, DevicePolicy, ...)
  services/
    auth.go              Session login + brute-force throttle
    blocked.go           Hard deny-list + NormalizeDomain
    dns.go               dnsmasq DNS-blocklist config writer
    doh.go               DoH/DoT resolver IP list
    firewall.go          Generates nftables ruleset (per-policy chains)
    hotspot.go           hostapd config writer
    policy.go            Policy CRUD + proactive resolve + refresh cron
    trafficlog.go        journald tail for kernel nflog + dnsmasq
    validate.go          Input-validation regex guards (injection)
deploy/
  setup.sh               First-boot provisioning script
  provision.sh           Orchestrates first-boot from /boot/firmware
  netfilter-provision.service
  hostapd-base.conf
  dnsmasq-base.conf
  nftables-base.conf
  nf-wlan0.service       wlan0 static-IP oneshot unit
  netfilterd.service
scripts/
  prepare-sd.sh          Stuffs bootfs partition with first-boot payload
  deploy-v2.sh           One-command rebuild + redeploy to a running Pi
  setup-letsencrypt.sh   Real cert via DuckDNS DNS-01
  regen-certs.sh         Self-signed cert with SANs (fallback)
web/
  static/                CSS (Pico.css), JS (Alpine.js, Chart.js)
  templates/             Go HTML templates
  embed.go               Embeds static + templates into the binary
docs/
  V2_ROADMAP.md          Design doc for the per-policy rewrite
```

### nftables shape (generated)

```nft
table inet filter {
    set pol_1_ips { type ipv4_addr; flags timeout; timeout 30d; }  # Default
    set pol_2_ips { ... elements = { connman IPs + auth + maps + ... } }  # Tesla
    set pol_3_ips { ... }                                           # Open
    set doh_resolvers { type ipv4_addr; elements = { 1.1.1.1, 8.8.8.8, ... } }

    chain pol_1_chain {                              # Default (strict)
        ip daddr @pol_1_ips log prefix "[NETFILTER-ACCEPT pol=Default] " accept
        ct state new log prefix "[NETFILTER-DROP pol=Default] " drop
        drop
    }
    chain pol_2_chain { ... Tesla ... }
    chain pol_3_chain {                              # Open
        ip daddr @pol_3_ips log prefix "[NETFILTER-ACCEPT pol=Open] " accept
        accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        ip daddr @doh_resolvers tcp dport 443 log prefix "[NETFILTER-DROP-DOH] " drop
        ip daddr @doh_resolvers udp dport 853 log prefix "[NETFILTER-DROP-DOT] " drop
        ether saddr vmap {
            4c:fc:aa:17:37:75 : goto pol_2_chain,   # Tesla
            f0:d4:15:68:ec:a0 : goto pol_3_chain    # laptop
        }
        jump pol_1_chain                             # unassigned → Default
    }
}
```

---

## Tech stack

- **Go** — single static binary, no CGO
- **SQLite** via `modernc.org/sqlite` (pure Go) — WAL + foreign-keys ON
- **chi** — HTTP router
- **Alpine.js** + **Pico.css** — lightweight reactive UI
- **Chart.js** — statistics
- **nftables** — firewall rules
- **dnsmasq** — DHCP + DNS + `nftset=` integration to populate policy IP sets on DNS resolution
- **hostapd** — WiFi access point
- **acme.sh** — ACME DNS-01 client for Let's Encrypt

---

## Block list (hard deny)

`blocked_domains` is a separate table from per-policy allow lists and
from the Pi-hole-style `dns_blocklist`. Its purpose is
*"this endpoint must never reach my network, even by accident."*

**Two layers of enforcement**

1. **Allow-list guard** — `POST /api/policies/:id/domains` (and the Allow button in the traffic monitor) calls `BlockedService.IsBlocked` before any insert. A match returns HTTP 409.
2. **DNS sinkhole** — `DNSService.Apply` writes `address=/<domain>/0.0.0.0` for every enabled block entry to `/etc/dnsmasq.d/blocklist.conf`. dnsmasq does suffix-matching, so `tesla-cdn.com` also sinks `cdn1.tesla-cdn.com`.

**Match types**

- `suffix` — domain + all deeper subdomains. Accepts `*.foo.com`, `foo.com`, or anything equivalent; input is normalized.
- `exact` — matches only the exact string.

**Seeded entries**

Migration v5 seeds ~9 Tesla OTA / diagnostic endpoints. Migration v10
adds Preset B from the `fw_dump/TESLA_DOMAINS_BLOCKLIST.md` analysis:

- Control plane — `mothership`, `firmware-ota`, `firmware-bundles`, `firmware-media`, all Hermes variants (WS, REST, stream, cellular), AP Firmware API
- Telemetry / surveillance / upload — `telemetry-prd`, `logupload-prod`, `x1`, `x3-prod`, `x3-static`, `s3.ap`, AWS Sentry snapshot buckets (US + EU), `hypnos`, `remote-access-registry`, manufacturing endpoints, AP diag logs
- Engineering — `*-eng` variants of everything above
- Corporate — Jenkins (`typhoon.fw`), internal GitHub, Stash, Confluence, Artifactory, Toolbox variants, EPC, parts portal

Total: ~60 domains. Remove anything you actually want via `/blocklist` in the UI.

**Limitations**

- Only filters traffic through this appliance. A Tesla with an active LTE modem can reach any endpoint directly — put the car on WiFi-only in its Settings for the filter to bite.
- TLS pinning means you can't MITM to inspect content — blocking is all-or-nothing per hostname.
- Some domains are shared between services (e.g. the Hermes tunnel multiplexes firmware + telemetry + commands over one mTLS connection to `hermes-prd.ap.tesla.services`). Preset B blocks Hermes entirely, which is why Tesla mobile app loses live features.

---

## Schema versions

| v | Purpose |
|---|---|
| 1 | Core tables (users, sessions, devices, firewall_rules, dns_blocklist, bandwidth_limits, settings, audit_log) |
| 2 | `query_log` + indexes for persistent traffic history |
| 3 | `kv_store` for journalctl cursor state |
| 4 | `allowed_domains` table for dynamic allow-list via `nftset=` |
| 5 | `blocked_domains` + Tesla OTA/diagnostic seed |
| 6 | **per-policy model**: `policies`, `policy_allowed_domains`, `device_policies`; Default (strict + empty) + Tesla seed; drops `allowed_domains` |
| 7 | `query_log.source` + `policy` columns (traffic monitor split) |
| 8 | Cleanup: wipe URL-encoded MACs from `device_policies` (handler bug fix) |
| 9 | Rebuild `policies` table with `mode IN ('permissive','strict','open')`; seed Open policy |
| 10 | Tesla MCU3 Preset B: ~50 entries to `blocked_domains`, 4 entries to Tesla policy allow list |

Migrations are idempotent and applied in order on startup. Adding a new one: append a SQL string to `migrations` in `internal/database/migrations.go`; the version is slice index + 1.

---

## Configuration

`/etc/netfilterd/config.yaml`:

```yaml
listen_addr: "192.168.4.1:8443"
use_tls: true
tls_cert: "/etc/netfilterd/server.crt"
tls_key:  "/etc/netfilterd/server.key"
db_path:  "/var/lib/netfilterd/netfilter.db"
wan_interface: "eth1"
lan_interface: "wlan0"
lan_subnet:    "192.168.4.0/24"
lan_gateway:   "192.168.4.1"
dhcp_range_start: "192.168.4.100"
dhcp_range_end:   "192.168.4.250"
dns_upstream: "1.1.1.1,8.8.8.8"
dry_run:   false
log_level: "info"
```

### CLI flags

```
netfilterd [flags]
  --config       Config file path (default /etc/netfilterd/config.yaml)
  --dry-run      Log system commands without executing
  --init-admin   Create initial admin user
  --reset-admin  Reset admin password
  --username     Admin username (default "admin")
  --password     Admin password
  --version      Print version
```

---

## Development

```bash
# Dry-run locally (no real firewall/network changes)
go run ./cmd/netfilterd --config config.yaml --dry-run

# Unit tests (validators, migrations, handler extractMAC)
go test ./...

# Cross-compile for RPi4
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o netfilterd-arm64 ./cmd/netfilterd

# Rebuild + redeploy to a running Pi in one shot
scripts/deploy-v2.sh                 # Pi at default 192.168.4.1
scripts/deploy-v2.sh 10.0.0.42       # elsewhere
```

---

## Manual install (existing Pi)

Already have a Pi running some other OS and want to convert? Same setup
script the cloud-init hook uses:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o netfilterd-arm64 ./cmd/netfilterd
scp netfilterd-arm64 pi@<pi-ip>:/tmp/netfilterd
scp -r deploy/*      pi@<pi-ip>:/tmp/deploy/
ssh -t pi@<pi-ip> "sudo bash /tmp/deploy/setup.sh"
```

`setup.sh` prompts for SSID, hotspot password, country code, and admin
password. The final service bring-up is detached via `nohup` so an SSH
session over `wlan0` getting dropped when hostapd seizes the radio doesn't
strand the provisioning mid-run.

---

## License

[MIT](LICENSE)
