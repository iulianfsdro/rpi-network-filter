# airgap — Tesla BLE client

A standalone web app that drives the Pi's BLE radio over `/api/ble/*`
via a bearer token. The Pi becomes a remote control surface; the app
runs locally on your machine.

V4.4 Phase 2: the app is wired up end-to-end against the byte-forwarder
API, but **the long-term ECDH key still lives on the Pi**. Phase 3 moves
the key to WebCrypto on this client; the API stays the same.

## Run it

```bash
cd client
python3 -m http.server 7777
# → http://localhost:7777
```

That's it. No build, no node modules — just `index.html` plus a CSS
file and a JS file, served as static assets.

## First-time enrolment

1. On the Pi's `/settings` page, scroll to **BLE client tokens** and
   issue a new token. Copy the plaintext (shown once).
2. On the Pi's `/remote-access` page, optionally flip **Expose
   `/api/ble` publicly** so this client can reach the Pi without
   installing Tailscale.
3. Open this app and paste:
   - **API URL** — either `https://<your-pi-tailnet-host>/api/ble`
     (Funnel) or `https://192.168.4.1:8443/api/ble` (LAN).
   - **Bearer token** — the plaintext from step 1.
4. Hit **Connect**. The app health-checks `/api/ble/state` and lands
   on the Garage screen.

Config persists in `localStorage`. To re-enrol, click the cog icon
top-right and hit **Forget this Pi**.

## Self-signed TLS

If you're on the LAN path (`https://192.168.4.1:8443/...`) the Pi's
cert is self-signed. Your browser will refuse the connection the first
time. Two fixes:

- Visit the Pi URL once in a separate tab, click through the warning,
  done. The cert gets cached.
- Or download `https://192.168.4.1:8443/netfilter-ca.crt` and trust it
  in Keychain.

On the Funnel path the cert is Let's Encrypt — no warning.

## Why a separate app instead of the Pi's `/garage`?

The Pi's `/garage` page is going away. Long-term, the Pi shouldn't be
a control surface — it should be a dumb byte-forwarder for a client
that holds its own crypto key. This app is the first iteration of
that client. Phase 3 ports the Tesla protocol crypto here and retires
the Pi-resident private key.
