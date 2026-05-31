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

        // The enrolment form state. cfg shape: {api, token, vin}.
        cfg: { api: '', token: '', vin: '' },
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

        // Convenience helpers for templates that don't want a long
        // ternary at the binding site.
        get locked() { return this.state?.locked === true; },

        // ─── Lifecycle ──────────────────────────────────────────
        async init() {
            // Restore previous enrolment (if any) from localStorage.
            try {
                const raw = localStorage.getItem(CFG_KEY);
                if (raw) {
                    const saved = JSON.parse(raw);
                    if (saved.api && saved.token) {
                        this.cfg = saved;
                        api.use(saved);
                        this.vin = saved.vin || '';
                        await this.connect(/*silent*/true);
                        return;
                    }
                }
            } catch (e) { /* fall through to enrol */ }
            this.screen = 'enrol';
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
                // /state proves three things at once: URL is reachable,
                // bearer is valid, and the Pi can read its own snapshot.
                this.state = await api.get('/state');
                localStorage.setItem(CFG_KEY, JSON.stringify(this.cfg));
                this.vin = this.cfg.vin || '';
                this.screen = 'garage';
                if (!silent) notify('Connected ✓', 'success');
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
        forget() {
            if (!confirm('Forget this Pi? You\'ll need to paste the URL and token again. The bearer stays valid on the Pi — revoke it from /settings if you want it dead.')) return;
            localStorage.removeItem(CFG_KEY);
            this.cfg = { api: '', token: '', vin: '' };
            this.state = null;
            this.log = [];
            this.screen = 'enrol';
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
