#!/bin/bash
# First-boot orchestrator. Run once by netfilter-provision.service.
# Expects the following on the bootfs partition (mounted at /boot/firmware):
#   /boot/firmware/netfilter/netfilterd              -- pre-built arm64 binary
#   /boot/firmware/netfilter/deploy/*                -- full deploy/ directory
#   /boot/firmware/netfilter/answers.txt (optional)  -- four-line setup answers
#
# On success writes /var/lib/netfilter-provisioned and self-disables.

set -euo pipefail

LOCK=/var/lib/netfilter-provisioned
[[ -f $LOCK ]] && { echo "Already provisioned; nothing to do."; exit 0; }

SRC=/boot/firmware/netfilter
[[ -d "$SRC" ]] || SRC=/boot/netfilter   # pre-Bookworm path
[[ -d "$SRC/deploy" ]] || { echo "No $SRC/deploy — re-run scripts/prepare-sd.sh"; exit 1; }
[[ -f "$SRC/netfilterd" ]] || { echo "No $SRC/netfilterd binary"; exit 1; }

echo "=== NetFilter first-boot provisioning $(date -Iseconds) ==="

mkdir -p /tmp/deploy
cp -f "$SRC/deploy"/* /tmp/deploy/
chmod +x /tmp/deploy/setup.sh
install -m 0755 "$SRC/netfilterd" /tmp/netfilterd

if [[ -f "$SRC/answers.txt" ]]; then
    cp "$SRC/answers.txt" /tmp/answers.txt
else
    printf 'NetFilter\nchangeme123\nUS\nnetfilter\n' > /tmp/answers.txt
fi

bash /tmp/deploy/setup.sh < /tmp/answers.txt

mkdir -p /var/lib
touch "$LOCK"
systemctl disable netfilter-provision.service
echo "=== Provisioning complete ==="
