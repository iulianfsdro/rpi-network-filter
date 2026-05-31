// airgap client — bearer-authed companion to the Pi's /api/ble surface.
//
// V4.4 Phase 2. The Pi still does the BLE crypto using its on-disk key;
// this client is just a UI on top of the byte-forwarder. Phase 3 moves
// the crypto into WebCrypto inside the client and retires the Pi-resident
// key entirely — at which point this exact same script will (a) generate
// a P-256 keypair on first run with `extractable: false`, (b) ship its
// public key to the Pi for `SendAddKeyRequest`, and (c) intercept every
// /api/ble/cmd/* call to do the ECDH+AES-GCM locally before forwarding
// the ciphertext through /api/ble/exchange. The screens and the
// command-fan stay identical; only the API helper learns crypto.
//
// Storage is localStorage for now (host-bound, survives reload, easy to
// nuke from devtools). For Phase 3 the keypair will move to IndexedDB
// as a CryptoKey object so the OS-level key store backs it — that's
// the only viable place to hold a non-extractable WebCrypto key across
// reloads.

const CFG_KEY = 'airgap-cfg';

// ─── Bearer-aware fetch wrapper ───────────────────────────────────
// Mirrors the shape of netfilterd's app.js api{} object so porting the
// existing /garage Alpine model is mechanical: same .get/.post/.put,
// just a different transport. No cookie path; the Authorization header
// is mandatory.
const api = {
    base: '',
    token: '',

    use(cfg) {
        this.base = (cfg.api || '').replace(/\/+$/, '');
        this.token = cfg.token || '';
    },

    async request(method, path, body) {
        if (!this.token) throw new Error('not enrolled');
        const url = this.base + path;
        const headers = { 'Authorization': 'Bearer ' + this.token };
        if (body !== undefined) headers['Content-Type'] = 'application/json';

        let res;
        try {
            res = await fetch(url, {
                method, headers,
                body: body !== undefined ? JSON.stringify(body) : undefined,
            });
        } catch (e) {
            // Network failure / CORS rejection / self-signed-cert rejection.
            // We can't distinguish reliably here — Safari/Chrome report
            // them identically. Surface the most likely cause.
            throw new Error('network error — wrong URL, cert not trusted, or Pi unreachable');
        }
        if (res.status === 401) {
            throw new Error('unauthorized — token revoked or wrong, re-enrol');
        }
        if (res.status === 204) return null;

        const text = await res.text();
        let json;
        try { json = text ? JSON.parse(text) : null; } catch { json = { error: text }; }

        if (!res.ok) {
            throw new Error(json?.error || ('HTTP ' + res.status));
        }
        return json;
    },

    get(path)         { return this.request('GET',    path); },
    post(path, body)  { return this.request('POST',   path, body ?? {}); },
};

// ─── Toast helper (matches the Pi's notify() API so handlers can be
//     copied verbatim from /garage) ───────────────────────────────
function notify(msg, kind) {
    const c = document.getElementById('toast-container');
    if (!c) { console.log('[toast]', kind, msg); return; }
    const el = document.createElement('div');
    el.className = 'toast' + (kind === 'error' || kind === 'danger' ? ' toast-error' : '');
    el.textContent = msg;
    c.appendChild(el);
    requestAnimationFrame(() => el.classList.add('show'));
    setTimeout(() => {
        el.classList.remove('show');
        setTimeout(() => el.remove(), 200);
    }, kind === 'error' || kind === 'danger' ? 4000 : 2200);
}

// ─── Alpine model ─────────────────────────────────────────────────
function clientApp() {
    return {
        // Screen routing. localStorage decides: if there's a saved
        // config the user lands on garage; otherwise on enrol.
        screen: 'enrol',

        // The enrolment form state. cfg shape: {api, token, nickname}.
        // - api      : the byte-forwarder base URL (Pi's /api/ble)
        // - token    : bearer token issued from the Pi's /settings page
        // - nickname : display-only friendly name; the crypto VIN
        //              lives on the Pi (set via PUT /api/ble/vin) and
        //              is fetched on connect so the client can use it
        //              for AES-GCM AAD personalization.
        cfg: { api: '', token: '', nickname: '' },

        // Migrate legacy cfg.vin entries (pre-Thread-B installs)
        // automatically — see init().
        vinInput: '',
        savingVin: false,
        busy: false,
        enrolError: '',

        // Pulled snapshot from /api/ble/state. Shape mirrors the
        // existing /api/tesla/state response — we touch only a subset
        // of fields for the v0 garage screen, full surface is added
        // incrementally.
        state: null,
        log: [],
        vin: '',

        // Form bindings.
        climateTarget: 22,
        chargeLimit: 80,

        // Device-key state (V4.4 Phase 3a). hasKey + keyFp are
        // populated by loadKeyState(); enrolling = true is set while
        // the BLE add-key-request is in flight.
        hasKey: false,
        keyFp: '',
        enrolling: false,
        keyError: '',

        // Direct-crypto state (V4.4 Phase 3c-4). directBusy locks
        // the button while a session is in flight; directStatus is
        // the human-readable trail of the last attempt.
        directBusy: false,
        directStatus: '',

        // Convenience helpers for templates that don't want a long
        // ternary at the binding site.
        get locked() { return this.state?.locked === true; },

        // ─── Lifecycle ──────────────────────────────────────────
        async init() {
            // Restore previous enrolment (if any) from localStorage.
            // Auto-migrate legacy cfg.vin (cosmetic field that doubled
            // as nickname pre-Thread-B) into cfg.nickname.
            try {
                const raw = localStorage.getItem(CFG_KEY);
                if (raw) {
                    const saved = JSON.parse(raw);
                    if (saved.vin && !saved.nickname) {
                        saved.nickname = saved.vin;
                    }
                    delete saved.vin;
                    if (saved.api && saved.token) {
                        this.cfg = {
                            api: saved.api,
                            token: saved.token,
                            nickname: saved.nickname || '',
                        };
                        api.use(this.cfg);
                        await this.connect(/*silent*/true);
                        return;
                    }
                }
            } catch (e) { /* fall through to enrol */ }
            this.screen = 'enrol';
        },

        // saveVin pushes the user-entered 17-char VIN to the Pi via
        // PUT /api/ble/vin. Subsequent /pair fetches will return it,
        // and crypto sessions will use it for AAD personalization.
        async saveVin() {
            const v = (this.vinInput || '').trim().toUpperCase();
            if (v.length !== 17) {
                notify('VIN must be exactly 17 characters', 'error');
                return;
            }
            if (!/^[A-HJ-NPR-Z0-9]{17}$/i.test(v)) {
                notify('VIN may only contain A-Z (no I,O,Q) and 0-9', 'error');
                return;
            }
            this.savingVin = true;
            try {
                await api.request('PUT', '/vin', { vin: v });
                this.vin = v;
                this.vinInput = '';
                notify('VIN saved ✓', 'success');
            } catch (e) {
                notify(e.message || 'save VIN failed', 'error');
            } finally {
                this.savingVin = false;
            }
        },

        // connect health-checks the Pi (issues /state) and on success
        // persists the cfg + flips to the garage screen. When called
        // with silent=true (e.g. on page reload with a stored config)
        // it never toasts on success.
        async connect(silent) {
            this.enrolError = '';
            this.busy = true;
            try {
                api.use(this.cfg);
                // /state is the Pi's connectivity stub post-Thread-A.
                // /pair is what carries the canonical VIN.
                this.state = await api.get('/state');
                const pairInfo = await api.get('/pair');
                this.vin = pairInfo?.vin || '';
                localStorage.setItem(CFG_KEY, JSON.stringify(this.cfg));
                this.screen = 'garage';
                if (!silent) notify('Connected ✓', 'success');
                await this.loadKeyState();
                await this.loadLog();
            } catch (e) {
                this.enrolError = e.message || 'connect failed';
                // Don't wipe the form on failure — operator probably has
                // a typo to fix.
                this.screen = 'enrol';
            } finally {
                this.busy = false;
            }
        },

        // forget wipes the enrolment and returns to the enrol screen.
        // Does NOT revoke the bearer on the Pi side — that's an admin
        // action on /settings → BLE client tokens. This is a client-
        // side opt-out only.
        async forget() {
            if (!confirm('Forget this Pi? You\'ll need to paste the URL and token again. The bearer stays valid on the Pi — revoke it from /settings if you want it dead. The device key in IndexedDB will also be wiped — the car-side enrolment of its pubkey persists until you remove it manually from the Tesla mobile app.')) return;
            localStorage.removeItem(CFG_KEY);
            try { await airgap.deleteDeviceKey(); } catch (e) { /* nothing to wipe */ }
            this.cfg = { api: '', token: '', vin: '' };
            this.state = null;
            this.log = [];
            this.hasKey = false;
            this.keyFp = '';
            this.screen = 'enrol';
        },

        // ─── Device key (Phase 3a) ──────────────────────────────
        //
        // loadKeyState pulls the persisted CryptoKeyPair from
        // IndexedDB and computes a short fingerprint for the UI.
        // Idempotent; called on garage-screen entry and after every
        // generate / rotate / forget.
        async loadKeyState() {
            try {
                const kp = await airgap.loadDeviceKey();
                if (!kp) {
                    this.hasKey = false;
                    this.keyFp = '';
                    return;
                }
                const raw = await airgap.exportPubkeyRaw(kp.publicKey);
                this.hasKey = true;
                this.keyFp = await airgap.fingerprintHex(raw);
            } catch (e) {
                this.hasKey = false;
                this.keyFp = '';
                this.keyError = 'key load failed: ' + (e.message || e);
            }
        },

        // generateKey makes a fresh non-extractable P-256 keypair in
        // WebCrypto and persists it. The private scalar never enters
        // JS-visible memory — even this code can't read it back.
        // Rotating an existing key requires explicit confirmation.
        async generateKey() {
            if (this.hasKey && !confirm('Replace the existing device key? The old key is destroyed locally; its car-side enrolment will still work until you remove it from the Tesla mobile app.')) return;
            this.keyError = '';
            try {
                const kp = await airgap.generateDeviceKey();
                await airgap.saveDeviceKey(kp);
                await this.loadKeyState();
                notify('Device key generated', 'success');
            } catch (e) {
                this.keyError = 'generate failed: ' + (e.message || e);
                notify(this.keyError, 'error');
            }
        },

        // directHonk / directFlashLights — Phase 3c-4.
        //
        // The end goal of the rearchitecture, exercised live: open a
        // BLE session, do the SessionInfo handshake LOCALLY (ECDH
        // against the car's ephemeral pubkey using our IndexedDB
        // key), encrypt the command LOCALLY, ship ciphertext through
        // the byte forwarder. The Pi sees opaque bytes the whole way.
        //
        // For this first proof of life:
        //   • No SessionInfo HMAC check (TODO in session.js)
        //   • No response decryption — the car's MessageStatus is
        //     unencrypted and the physical horn/flash is the signal
        //   • One session per click (open + send + close); fine for
        //     a few-second UX, refactored to a cache next pass
        async _directDo(actionBuilder, label) {
            if (this.directBusy) return;
            this.directBusy = true;
            this.directStatus = `[${label}] opening session…`;
            let session = null;
            try {
                const kp = await airgap.loadDeviceKey();
                if (!kp) throw new Error('no device key — generate one first');
                // The Pi's /pair endpoint is the canonical source of
                // truth for the VIN — same value the SDK scans for over
                // BLE AND the same value the car expects in the AAD's
                // personalization tag. Refresh every call so a freshly-
                // saved VIN works without a reconnect.
                const pairInfo = await api.get('/pair');
                if (!pairInfo?.vin) {
                    throw new Error('Pi has no VIN configured — enter one in the VIN card above');
                }
                this.vin = pairInfo.vin;
                const vin = pairInfo.vin;

                session = await airgap.openDirectSession({
                    api, vin, deviceKeyPair: kp,
                    domain: airgap.DOMAIN_INFOTAINMENT,
                });
                this.directStatus = `[${label}] session open · counter=${session.counter} · sending…`;

                const resp = await airgap.sendDirectCommandWithApi({
                    api, session, action: actionBuilder(),
                });

                // Full dump so we can read the exact car response.
                console.log('[airgap] response RoutableMessage:', resp);
                console.log('[airgap] response keys:', Object.keys(resp));
                console.log('[airgap] signedMessageStatus:', resp.signedMessageStatus);
                console.log('[airgap] signedMessageStatus keys:',
                    resp.signedMessageStatus ? Object.keys(resp.signedMessageStatus) : '(none)');

                const status = resp.signedMessageStatus;
                const opStatus = status?.operationStatus;
                // The car may name the fault `signedMessageFault` (proto
                // snake_case → camelCase) OR keep the original — try both.
                const fault = status?.signedMessageFault
                           ?? status?.signed_message_fault
                           ?? status?.fault;
                const faultName = ({
                    0: 'NONE', 1: 'BUSY', 2: 'TIMEOUT', 3: 'UNKNOWN_KEY_ID',
                    4: 'INACTIVE_KEY', 5: 'INVALID_SIGNATURE',
                    6: 'INVALID_TOKEN_OR_COUNTER',
                    7: 'INSUFFICIENT_PRIVILEGES', 8: 'INVALID_DOMAINS',
                    9: 'INVALID_COMMAND', 10: 'DECODING', 11: 'INTERNAL',
                    12: 'WRONG_PERSONALIZATION', 13: 'BAD_PARAMETER',
                    14: 'KEYCHAIN_IS_FULL', 15: 'INCORRECT_EPOCH',
                    16: 'IV_INCORRECT_LENGTH', 17: 'TIME_EXPIRED',
                    18: 'NOT_PROVISIONED', 19: 'COULD_NOT_HASH_METADATA',
                })[fault] || `unknown(${fault})`;

                if (opStatus === 0 || opStatus === undefined) {
                    this.directStatus = `[${label}] ✓ accepted by car`;
                    notify(`${label} via device key ✓`, 'success');
                } else {
                    const msg = `[${label}] status=${opStatus} fault=${fault}(${faultName})`;
                    this.directStatus = msg;
                    console.warn('[airgap]', msg);
                    notify(msg, 'error');
                }
                await this.loadLog();
            } catch (e) {
                console.error('[airgap] direct command failed:', e);
                this.directStatus = `[${label}] ✗ ${e.message || e}`;
                notify(`${label}: ${e.message || e}`, 'error');
            } finally {
                if (session) {
                    try { await session.close(); } catch {}
                }
                this.directBusy = false;
            }
        },
        directHonk()         { return this._directDo(airgap.honkAction,        'honk'); },
        directFlashLights()  { return this._directDo(airgap.flashLightsAction, 'flash-lights'); },

        // enrolKey ships the public half to the Pi for the BLE
        // add-key-request flow. The operator still has to tap the
        // NFC card on the centre console — this just kicks off the
        // car-side prompt.
        async enrolKey() {
            if (!this.hasKey) { notify('Generate a key first', 'error'); return; }
            this.keyError = '';
            this.enrolling = true;
            try {
                const kp = await airgap.loadDeviceKey();
                const raw = await airgap.exportPubkeyRaw(kp.publicKey);
                const b64 = airgap.bytesToBase64(raw);
                await api.post('/pair/external-pubkey', { public_key_b64: b64 });
                notify('Enrolment request sent — tap your NFC card on the centre console', 'success');
            } catch (e) {
                this.keyError = e.message || 'enrol failed';
                notify(this.keyError, 'error');
            } finally {
                this.enrolling = false;
            }
        },

        // ─── Polling + state refresh ────────────────────────────
        // Phase 2 keeps the polling story simple: refresh on demand
        // and after every command. Phase 3 will introduce a longer-
        // lived WebSocket for state push.
        async refresh() {
            try {
                this.state = await api.get('/state');
            } catch (e) { /* api wrapper toasted */ }
        },
        async loadLog() {
            try {
                this.log = (await api.get('/log')) || [];
            } catch (e) { /* api wrapper toasted */ }
        },

        // ─── Command fan-out ────────────────────────────────────
        // cmd is the bread-and-butter — fire a named command, toast on
        // success, refresh state after a short delay (the car needs a
        // beat for its sensors to catch up).
        async cmd(name) {
            try {
                await api.post('/cmd/' + name);
                notify(name.replace(/-/g, ' ') + ' ✓', 'success');
                setTimeout(() => this.refresh(), 1200);
                this.loadLog();
            } catch (e) {
                notify(e.message || (name + ' failed'), 'error');
            }
        },

        // cmdJSON is cmd's sibling for commands that take a body. Same
        // refresh + log pattern; only the wire shape differs.
        async cmdJSON(name, body) {
            try {
                await api.post('/cmd/' + name, body);
                notify(name.replace(/-/g, ' ') + ' ✓', 'success');
                setTimeout(() => this.refresh(), 1200);
                this.loadLog();
            } catch (e) {
                notify(e.message || (name + ' failed'), 'error');
            }
        },
    };
}
