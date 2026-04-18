#!/bin/bash
# Build the v2 netfilterd binary and deploy it to a live v1 Pi by swapping
# the /usr/local/bin/netfilterd executable and restarting the service.
# Preserves admin password, audit log, device history, and block list.
#
# Usage (from repo root in Git Bash on Windows):
#   scripts/deploy-v2.sh                   # Pi at default 192.168.4.1
#   scripts/deploy-v2.sh 192.168.110.205   # Pi at a different IP
#
# Rollback: checkout master and re-run this script against the same IP.

set -euo pipefail

PI_HOST="${1:-192.168.4.1}"
PI_USER="${PI_USER:-pi}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/netfilterd-arm64"

echo "==> Building netfilterd-arm64 from $(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD) @ $(git -C "$REPO_ROOT" rev-parse --short HEAD)"
cd "$REPO_ROOT"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o "$BIN" ./cmd/netfilterd
ls -lh "$BIN"

echo ""
echo "==> Copying binary to ${PI_USER}@${PI_HOST}:/tmp/netfilterd"
scp "$BIN" "${PI_USER}@${PI_HOST}:/tmp/netfilterd"

echo ""
echo "==> Installing + restarting service on ${PI_HOST}"
ssh "${PI_USER}@${PI_HOST}" bash -s <<'REMOTE'
set -e
sudo install -m 0755 /tmp/netfilterd /usr/local/bin/netfilterd
sudo systemctl restart netfilterd
sleep 2
echo ""
echo "=== netfilterd journal (last 40 lines) ==="
sudo journalctl -u netfilterd -n 40 --no-pager
echo ""
echo "=== service status ==="
for unit in nf-wlan0 nftables hostapd dnsmasq netfilterd; do
    state=$(systemctl is-active "$unit" 2>/dev/null || echo inactive)
    printf "  %-12s %s\n" "$unit" "$state"
done
REMOTE

echo ""
echo "==> Done. Open https://${PI_HOST}:8443/policies to assign the Tesla."
echo ""
echo "Rollback:"
echo "  git -C \"$REPO_ROOT\" checkout master && scripts/deploy-v2.sh ${PI_HOST}"
