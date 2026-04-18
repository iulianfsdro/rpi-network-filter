#!/bin/bash
# Regenerate netfilterd's TLS cert with proper Subject Alternative Names
# so modern browsers (and iOS 13+ in particular) will accept it once the
# user installs it as a trusted root.
#
# Run on the Pi:
#   sudo bash /tmp/regen-certs.sh
#
# Then restart netfilterd. After install, download the cert from
# http://192.168.4.1/netfilter-ca.crt (served without auth by the daemon)
# and install it as a trusted CA on each device that needs green-lock HTTPS.

set -euo pipefail

CERT_DIR=/etc/netfilterd
SERVER_CRT=$CERT_DIR/server.crt
SERVER_KEY=$CERT_DIR/server.key

mkdir -p "$CERT_DIR"

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
ST = NetFilter
L  = NetFilter
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
    -keyout "$SERVER_KEY" \
    -out "$SERVER_CRT" \
    -config /tmp/netfilter-openssl.cnf \
    -extensions v3_req

chmod 600 "$SERVER_KEY"
chmod 644 "$SERVER_CRT"

rm -f /tmp/netfilter-openssl.cnf

echo "New cert written:"
openssl x509 -in "$SERVER_CRT" -noout -subject -issuer -dates
openssl x509 -in "$SERVER_CRT" -noout -ext subjectAltName

echo ""
echo "Restart netfilterd to pick up the new cert:"
echo "  sudo systemctl restart netfilterd"
echo ""
echo "Then on each client device, install the cert as a trusted root:"
echo "  http://192.168.4.1/netfilter-ca.crt"
