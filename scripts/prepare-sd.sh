#!/bin/bash
# Stuff a freshly-flashed SD card's bootfs partition with NetFilter's
# first-boot payload so the Pi self-provisions on first power-on.
#
# Prerequisites:
#   1. Flash "Raspberry Pi OS Lite (64-bit, Trixie)" with Raspberry Pi Imager.
#      In Advanced Settings (gear icon):
#        - hostname: netfilter
#        - set a user (e.g. pi / your password)
#        - enable SSH (password or public-key)
#        - set locale / timezone
#        - LEAVE WIRELESS LAN UNCONFIGURED (wlan0 must be free for AP mode)
#   2. Re-insert the SD so the bootfs partition is mounted.
#   3. Build the arm64 binary:
#        CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o netfilterd-arm64 ./cmd/netfilterd
#
# Usage:
#   scripts/prepare-sd.sh <path-to-bootfs>
#   e.g. on Windows Git Bash:
#        scripts/prepare-sd.sh /e         # if bootfs is drive E:

set -euo pipefail

usage() {
    echo "Usage: $0 <bootfs-mount-path>" >&2
    echo "Example: $0 /e   (Windows drive E:)" >&2
    exit 1
}

[[ $# -eq 1 ]] || usage
BOOT="$1"
[[ -d "$BOOT" ]] || { echo "Not a directory: $BOOT"; exit 1; }
[[ -f "$BOOT/cmdline.txt" ]] || { echo "Doesn't look like a Pi bootfs (no cmdline.txt): $BOOT"; exit 1; }

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/netfilterd-arm64"
[[ -f "$BIN" ]] || {
    echo "Missing $BIN — build it first:"
    echo "  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o netfilterd-arm64 ./cmd/netfilterd"
    exit 1
}

PAYLOAD="$BOOT/netfilter"
echo "Staging payload at $PAYLOAD"
rm -rf "$PAYLOAD"
mkdir -p "$PAYLOAD/deploy"
cp "$REPO_ROOT/deploy"/* "$PAYLOAD/deploy/"
cp "$BIN" "$PAYLOAD/netfilterd"

# Default answers for setup.sh prompts. Edit before flashing if you want
# non-default SSID / passwords / country code.
cat > "$PAYLOAD/answers.txt" <<'ANSWERS'
NetFilter
changeme123
US
netfilter
ANSWERS

echo "  - SSID:           NetFilter"
echo "  - hotspot pass:   changeme123"
echo "  - country code:   US"
echo "  - admin UI pass:  netfilter"
echo "  Edit $PAYLOAD/answers.txt to override."

# Hook into Imager's firstrun.sh so our provisioning service gets installed
# during the same first-boot that creates the user.
FIRSTRUN="$BOOT/firstrun.sh"
if [[ -f "$FIRSTRUN" ]]; then
    if grep -q "netfilter-provision" "$FIRSTRUN"; then
        echo "firstrun.sh already hooked; skipping injection."
    else
        echo "Injecting provisioning hook into $FIRSTRUN"
        # Insert three install/enable lines immediately before the final `exit 0`.
        python - "$FIRSTRUN" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
src = p.read_text()
hook = (
    "\n# --- NetFilter provisioning ---\n"
    "install -m 0755 /boot/firmware/netfilter/deploy/provision.sh /usr/local/sbin/netfilter-provision.sh\n"
    "install -m 0644 /boot/firmware/netfilter/deploy/netfilter-provision.service /etc/systemd/system/netfilter-provision.service\n"
    "systemctl enable netfilter-provision.service\n"
)
if "exit 0" in src:
    src = src.replace("exit 0", hook + "exit 0", 1)
else:
    src = src.rstrip() + "\n" + hook
p.write_text(src)
PY
    fi
else
    cat <<'WARN'
WARNING: no firstrun.sh found on bootfs.

You almost certainly skipped Raspberry Pi Imager's "Advanced Settings" step
(gear icon). Without it, the Pi has no user configured and SSH is disabled —
you will not be able to log in. Re-flash using Advanced Settings.
WARN
    exit 2
fi

echo ""
echo "bootfs prepared: $BOOT"
echo ""
echo "Next steps:"
echo "  1. Eject the SD card."
echo "  2. Insert into the Pi; plug in the USB LTE modem."
echo "  3. Power on. First-boot takes ~3-5 minutes."
echo "  4. Your laptop should see SSID 'NetFilter' — connect with password 'changeme123'."
echo "  5. Browse https://192.168.4.1:8443 (admin / netfilter)."
echo ""
echo "Troubleshooting: after first boot, log in via the Imager user and run"
echo "  sudo cat /var/log/netfilter-provision.log"
