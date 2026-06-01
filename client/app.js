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

        // PIN-protected dialogs (Thread C-3).
        valetDialogOpen: false,
        valetPin: '',
        speedLimitDialogOpen: false,
        speedLimitPin: '',
        speedLimitMph: 70,

        // Navigation dialog.
        navDialogOpen: false,
        navMode: 'gps', // 'gps' | 'search' | 'waypoints'
        navLat: 0,
        navLon: 0,
        navLabel: '',
        navQuery: '',
        navWaypoints: '',

        // Boombox.
        boomboxId: 9,

        // Expose `airgap` on the model so x-on handlers can reference
        // enums (airgap.CLIMATE_KEEPER.DOG, airgap.NAV_ORDER.APPEND).
        airgap,

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

        // Bearer self-management (Thread E). Populated from
        // /api/ble/token on connect.
        tokenInfo: null,
        revokingSelf: false,

        // Convenience helpers for templates that don't want a long
        // ternary at the binding site.
        get locked() { return this.state?.locked === true; },

        // ─── Lifecycle ──────────────────────────────────────────
        async init() {
            // Best-effort close of cached BLE sessions on tab close /
            // reload — releases the Pi's BLE-mutex without waiting
            // for the server-side idle reaper. We don't `await`
            // anything inside beforeunload; just fire DELETE via
            // sendBeacon (which survives navigation).
            window.addEventListener('beforeunload', () => {
                airgap.closeAllCachedSessions();
            });

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

        // _autoParseEnrolUrl detects a pasted "airgap://enrol?...".
        // Pulled out so it can be called from x-effect or @input on
        // the API URL field. Idempotent — running it twice with the
        // same parsed URL is a no-op.
        _autoParseEnrolUrl() {
            const v = (this.cfg.api || '').trim();
            if (!v.startsWith('airgap://enrol?')) return;
            try {
                const u = new URL(v.replace('airgap://', 'http://airgap-internal/'));
                const api = u.searchParams.get('api');
                const token = u.searchParams.get('token');
                const nickname = u.searchParams.get('nickname');
                if (api && token) {
                    this.cfg.api = api;
                    this.cfg.token = token;
                    if (nickname) this.cfg.nickname = nickname;
                    notify('Enrolment URL parsed', 'success');
                }
            } catch (e) {
                console.warn('[airgap] failed to parse enrolment URL:', e.message || e);
            }
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
                await this.loadTokenInfo();
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
            airgap.closeAllCachedSessions();
            localStorage.removeItem(CFG_KEY);
            try { await airgap.deleteDeviceKey(); } catch (e) { /* nothing to wipe */ }
            this.cfg = { api: '', token: '', nickname: '' };
            this.state = null;
            this.log = [];
            this.hasKey = false;
            this.keyFp = '';
            this.vin = '';
            this.tokenInfo = null;
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
            this.directStatus = `[${label}] preparing…`;
            try {
                const kp = await airgap.loadDeviceKey();
                if (!kp) throw new Error('no device key — generate one first');
                const pairInfo = await api.get('/pair');
                if (!pairInfo?.vin) {
                    throw new Error('Pi has no VIN configured — enter one in the VIN card above');
                }
                this.vin = pairInfo.vin;
                const vin = pairInfo.vin;

                // Build the action first (async — needs proto loader)
                // so we know which domain to open the session against.
                // Thread C: the builder returns {domain, bytes}; the
                // domain picks VCSEC vs Infotainment.
                const action = await actionBuilder();

                const resp = await airgap.withCachedSession(
                    { api, vin, deviceKeyPair: kp, domain: action.domain },
                    async (session, cached) => {
                        this.directStatus = cached
                            ? `[${label}] cached session · counter=${session.counter} · sending…`
                            : `[${label}] new session · counter=${session.counter} · sending…`;
                        return await airgap.sendDirectCommandWithApi({
                            api, session, payloadBytes: action.bytes,
                        });
                    },
                );

                // Thread C-2: sendDirectCommandWithApi now returns
                // { routable, decryptedPayload }. Status comes from
                // the unencrypted RoutableMessage; decryptedPayload
                // (if non-null) is the CarServer.Response plaintext.
                const routable = resp.routable;
                if (resp.decryptedPayload) {
                    // Decode the inner CarServer.Response and merge
                    // any state-bearing fields into this.state so the
                    // battery / climate / closures tiles populate.
                    try {
                        const proto = await airgap.loadProto();
                        const carResp = airgap.decodeMessage(proto.Response, resp.decryptedPayload);
                        console.log('[airgap] decrypted CarServer.Response:', carResp);
                        this._mergeResponseIntoState(carResp);
                    } catch (e) {
                        console.warn('[airgap] decoded payload but not a Response:', e.message);
                    }
                }
                console.log('[airgap] response RoutableMessage:', routable);
                console.log('[airgap] signedMessageStatus:', routable.signedMessageStatus);

                const status = routable.signedMessageStatus;
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
                // withCachedSession evicts on error — no manual close
                // needed here.
            } finally {
                this.directBusy = false;
            }
        },
        // _mergeResponseIntoState pulls the field-level data the UI
        // tiles consume out of a decoded CarServer.Response. The
        // response is a oneof of many possible payloads; we cherry-
        // pick the ones the existing /garage-style tiles render.
        // Anything we don't recognise stays in console for debugging.
        _mergeResponseIntoState(carResp) {
            // Charge state: SOC, range, charging_state, charge_limit_soc
            const cs = carResp?.vehicleData?.chargeState || carResp?.chargeState;
            if (cs) {
                this.state = this.state || {};
                this.state.battery = {
                    soc:                cs.batteryLevel,
                    range_km:           cs.batteryRange != null ? Math.round(cs.batteryRange * 1.60934) : null,
                    charging_state:     cs.chargingState,
                    charge_limit_soc:   cs.chargeLimitSoc,
                };
            }
            // Climate state: inside/outside temps, target, on/off.
            const cl = carResp?.vehicleData?.climateState || carResp?.climateState;
            if (cl) {
                this.state = this.state || {};
                this.state.climate = {
                    inside_temp_c:  cl.insideTempCelsius,
                    outside_temp_c: cl.outsideTempCelsius,
                    target_temp_c:  cl.driverTempSetting,
                    is_on:          cl.isClimateOn,
                };
            }
        },

        directHonk()             { return this._directDo(airgap.honkAction,             'honk'); },
        directFlashLights()      { return this._directDo(airgap.flashLightsAction,      'flash-lights'); },
        // VCSEC actions — locks, closures, wake
        directLock()             { return this._directDo(airgap.lockAction,             'lock'); },
        directUnlock()           { return this._directDo(airgap.unlockAction,           'unlock'); },
        directWake()             { return this._directDo(airgap.wakeAction,             'wake'); },
        directOpenFrunk()        { return this._directDo(airgap.openFrunkAction,        'open-frunk'); },
        directOpenTrunk()        { return this._directDo(airgap.openTrunkAction,        'open-trunk'); },
        directCloseTrunk()       { return this._directDo(airgap.closeTrunkAction,       'close-trunk'); },
        directOpenChargePort()   { return this._directDo(airgap.openChargePortAction,   'open-charge-port'); },
        directCloseChargePort()  { return this._directDo(airgap.closeChargePortAction,  'close-charge-port'); },
        // Infotainment — climate, charging, sentry
        directClimateOn()        { return this._directDo(airgap.climateOnAction,        'climate-on'); },
        directClimateOff()       { return this._directDo(airgap.climateOffAction,       'climate-off'); },
        directSentryOn()         { return this._directDo(airgap.sentryOnAction,         'sentry-on'); },
        directSentryOff()        { return this._directDo(airgap.sentryOffAction,        'sentry-off'); },
        directStartCharging()    { return this._directDo(airgap.startChargingAction,    'start-charging'); },
        directStopCharging()     { return this._directDo(airgap.stopChargingAction,     'stop-charging'); },
        directChargeMaxRange()   { return this._directDo(airgap.chargeMaxRangeAction,   'charge-max-range'); },
        directChargeStandardRange() { return this._directDo(airgap.chargeStandardRangeAction, 'charge-standard-range'); },
        directSetChargeLimit()      {
            const p = Number(this.chargeLimit);
            return this._directDo(() => airgap.setChargeLimitAction(p), `set-charge-limit:${p}`);
        },
        directDefrostOn()           { return this._directDo(airgap.defrostOnAction,  'defrost-on'); },
        directDefrostOff()          { return this._directDo(airgap.defrostOffAction, 'defrost-off'); },
        directSetClimateTemp()      {
            const c = Number(this.climateTarget);
            return this._directDo(() => airgap.setClimateTempAction(c), `set-climate-temp:${c}`);
        },

        // State reads (Thread C-2). Each fires a GetVehicleData
        // request whose response (encrypted CarServer.Response) we
        // decrypt and stash on this.state so existing UI tiles
        // populate.
        directGetChargeState()      { return this._directDo(airgap.getChargeStateAction,  'get-charge-state'); },
        directGetClimateState()     { return this._directDo(airgap.getClimateStateAction, 'get-climate-state'); },
        directRefreshState() {
            // Fire both back-to-back; thanks to the session cache they
            // share one BLE session.
            return (async () => {
                await this.directGetChargeState();
                await this.directGetClimateState();
            })();
        },

        // ── Thread C-3 extras ──────────────────────────────────
        // Climate / comfort
        directSetClimateKeeper(mode) { return this._directDo(() => airgap.setClimateKeeperAction(mode), `climate-keeper:${mode}`); },
        directSetCabinOverheat(on)   { return this._directDo(() => airgap.setCabinOverheatAction(on),   `cabin-overheat:${on}`); },
        directKeepAccPowerOn()       { return this._directDo(() => airgap.setKeepAccPowerAction(true),  'keep-acc-power-on'); },
        directKeepAccPowerOff()      { return this._directDo(() => airgap.setKeepAccPowerAction(false), 'keep-acc-power-off'); },
        directWheelHeaterOn()        { return this._directDo(() => airgap.setSteeringWheelHeaterAction(true),  'wheel-heater-on'); },
        directWheelHeaterOff()       { return this._directDo(() => airgap.setSteeringWheelHeaterAction(false), 'wheel-heater-off'); },
        // Windows
        directVentWindows()          { return this._directDo(airgap.ventWindowsAction,  'vent-windows'); },
        directCloseWindows()         { return this._directDo(airgap.closeWindowsAction, 'close-windows'); },
        // Seat heaters / coolers — position + level
        directSeatHeater(position, level)  { return this._directDo(() => airgap.setSeatHeaterAction(position, level), `seat-heater:${position}=${level}`); },
        directSeatCooler(position, level)  { return this._directDo(() => airgap.setSeatCoolerAction(position, level), `seat-cooler:${position}=${level}`); },
        // Homelink + remote drive
        directHomelink()             {
            if (!this.state?.drive?.latitude || !this.state?.drive?.longitude) {
                notify('Homelink needs car location — fetch /drive state first', 'error');
                return;
            }
            return this._directDo(
                () => airgap.homelinkAction({ latitude: this.state.drive.latitude, longitude: this.state.drive.longitude }),
                'homelink',
            );
        },
        directRemoteDrive()          { return this._directDo(airgap.remoteDriveAction, 'remote-drive'); },
        // Valet (PIN dialog)
        directValetOn()              { return this._directDo(() => airgap.setValetModeAction(true,  this.valetPin), 'valet-on');  },
        directValetOff()             { return this._directDo(() => airgap.setValetModeAction(false, this.valetPin), 'valet-off'); },
        // Speed-limit (PIN dialog)
        directSpeedLimitActivate()   { return this._directDo(() => airgap.activateSpeedLimitAction(this.speedLimitPin),   'speed-limit-activate');   },
        directSpeedLimitDeactivate() { return this._directDo(() => airgap.deactivateSpeedLimitAction(this.speedLimitPin), 'speed-limit-deactivate'); },
        directSpeedLimitClearPin()   { return this._directDo(() => airgap.clearSpeedLimitPinAction(this.speedLimitPin),   'speed-limit-clear-pin');  },
        directSpeedLimitSet()        { return this._directDo(() => airgap.setSpeedLimitMphAction(Number(this.speedLimitMph)), `speed-limit-set:${this.speedLimitMph}mph`); },
        // Navigation (dialog)
        directNavigateGps()          {
            return this._directDo(() => {
                const label = (this.navLabel || '').trim();
                if (label) {
                    return airgap.navigateGpsWithLabelAction({ lat: Number(this.navLat), lon: Number(this.navLon), label, order: airgap.NAV_ORDER.REPLACE });
                }
                return airgap.navigateGpsAction({ lat: Number(this.navLat), lon: Number(this.navLon), order: airgap.NAV_ORDER.REPLACE });
            }, 'navigate-gps');
        },
        directNavigateSearch()       { return this._directDo(() => airgap.navigateSearchAction({ query: (this.navQuery||'').trim(), order: airgap.NAV_ORDER.REPLACE }), 'navigate-search'); },
        directNavigateWaypoints()    { return this._directDo(() => airgap.navigateWaypointsAction({ waypoints: (this.navWaypoints||'').trim() }), 'navigate-waypoints'); },
        // Boombox
        directBoombox(sound)         { return this._directDo(() => airgap.boomboxAction(sound), `boombox:${sound}`); },
        directBoomboxFromInput()     { return this._directDo(() => airgap.boomboxAction(Number(this.boomboxId)), `boombox:${this.boomboxId}`); },

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

        // ─── Token self-management (Thread E) ───────────────────

        async loadTokenInfo() {
            try {
                this.tokenInfo = await api.get('/token');
            } catch (e) {
                this.tokenInfo = null;
                console.warn('[airgap] token info fetch failed:', e.message || e);
            }
        },
        async revokeSelf() {
            if (!confirm('Revoke this device\'s access from the Pi? Server-side revocation is permanent until the operator issues a fresh token. The car-side enrolment of your device key persists.')) return;
            this.revokingSelf = true;
            try {
                await api.request('DELETE', '/token');
                notify('Token revoked server-side — call api.* will now 401', 'success');
                // After a beat, drop local state and go back to enrol.
                setTimeout(() => this.forget(), 1500);
            } catch (e) {
                notify(e.message || 'self-revoke failed', 'error');
            } finally {
                this.revokingSelf = false;
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

        // cmd / cmdJSON used to POST to /api/ble/cmd/{name} — that
        // route is gone (Thread A). Every command now goes through
        // _directDo + an action builder + the byte forwarder, with
        // crypto fully on the client.
    };
}
