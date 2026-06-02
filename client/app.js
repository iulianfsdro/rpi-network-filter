// airgap client — bearer-authed companion to the Pi's /api/ble surface.
//
// V4.4 Phase 2 → Thread C-3 → State store (this file).
//
// The Pi is now a byte-forwarder; every command's crypto lives on
// the client. This file is the Alpine model that drives the UI and
// orchestrates per-command flow through three pieces:
//
//   1. The per-VIN serialization queue (state.js) — every BLE
//      operation enqueues, single in-flight at a time. Closes the
//      read-after-command-write race.
//   2. Optimistic state updates (state.js) — successful commands
//      write the intended slice locally and (for Infotainment) mark
//      it dirty until next awake sync.
//   3. Piggyback sync scheduler (state.js) — after a successful
//      command we debounce-schedule a follow-up sync: 'awake' for
//      Infotainment+wake, 'vcsec' for cheap VCSEC commands.
//
// The Pi's /state and /pair endpoints are still consulted for
// nickname/VIN bootstrap; the per-slice state itself now lives in
// the VehicleState store, backed by localStorage so it survives
// reload.

const CFG_KEY = 'airgap-cfg';

// ─── Bearer-aware fetch wrapper ───────────────────────────────────
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

        // Per-path fetch timeout. The first cut was a flat 12s which
        // was strangling legitimate slow BLE handshakes on
        // POST /sessions (Pi-side scan+connect+pair can easily take
        // 8-15s on a cold radio, well within normal). Now:
        //   • /sessions (session open): 45s. Covers worst-case BLE
        //     handshake + a buffer. Anything past that really IS
        //     stuck.
        //   • everything else: 15s. Plenty for an already-warm
        //     /exchange round-trip (Pi-side already caps SessionInfo
        //     exchange at 4s and command exchange at 6s).
        const isSessionOpen = method === 'POST' && /^\/sessions\/?$/.test(path);
        const timeoutMs = isSessionOpen ? 45_000 : 15_000;
        const ctrl = new AbortController();
        const timeoutId = setTimeout(() => ctrl.abort(), timeoutMs);
        const startedAt = Date.now();

        let res;
        try {
            res = await fetch(url, {
                method, headers, signal: ctrl.signal,
                body: body !== undefined ? JSON.stringify(body) : undefined,
            });
        } catch (e) {
            clearTimeout(timeoutId);
            const elapsed = Date.now() - startedAt;
            if (e.name === 'AbortError') {
                console.warn('[airgap] fetch timeout', method, path, 'after', elapsed, 'ms');
                throw new Error(`Pi did not respond within ${timeoutMs/1000}s — ${method} ${path}`);
            }
            throw new Error('network error — wrong URL, cert not trusted, or Pi unreachable');
        }
        clearTimeout(timeoutId);
        // Log slow successes too — anything > 1s is interesting.
        const elapsed = Date.now() - startedAt;
        if (elapsed > 1000) {
            console.log('[airgap] slow', method, path, elapsed + 'ms', 'status=' + res.status);
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

// ─── Toast helper ─────────────────────────────────────────────────
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

// _humanAgo formats a "X ago" string for slice timestamps. Pure
// presentation; lives in app.js so state.js stays UI-agnostic.
function humanAgo(ts) {
    if (!ts) return '—';
    const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
    if (s < 5)    return 'just now';
    if (s < 60)   return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    return Math.floor(s / 3600) + 'h ago';
}

// ─── Alpine model ─────────────────────────────────────────────────
function clientApp() {
    return {
        screen: 'enrol',
        cfg: { api: '', token: '', nickname: '' },

        vinInput: '',
        savingVin: false,
        busy: false,
        enrolError: '',

        // The state store — VehicleState instance, populated when we
        // know the VIN. Alpine binds against vs.charge, vs.climate,
        // vs.drive, vs.vcsec directly.
        vs: null,

        // Tick counter to force Alpine to re-render the "as of X ago"
        // labels every second without rebuilding the whole tree.
        _agoTick: 0,
        _agoInterval: null,

        log: [],
        vin: '',

        climateTarget: 22,
        chargeLimit: 80,

        valetDialogOpen: false,
        valetPin: '',
        speedLimitDialogOpen: false,
        speedLimitPin: '',
        speedLimitMph: 70,

        navDialogOpen: false,
        navMode: 'gps',
        navLat: 0,
        navLon: 0,
        navLabel: '',
        navQuery: '',
        navWaypoints: '',

        boomboxId: 9,

        airgap,

        // Stable reference for the closure-chip x-for. Defined here
        // (not inline in the template) so Alpine doesn't see a new
        // array per render.
        closureChips: [
            ['frunk','frontTrunk'],
            ['trunk','rearTrunk'],
            ['charge port','chargePort'],
            ['driver door','frontDriverDoor'],
            ['passenger door','frontPassengerDoor'],
        ],

        hasKey: false,
        keyFp: '',
        enrolling: false,
        keyError: '',

        directBusy: false,
        directStatus: '',

        tokenInfo: null,
        revokingSelf: false,

        // Convenience getters used by the template — keep the existing
        // simple expressions in index.html readable rather than
        // sprawling ternaries.
        get locked()    { return this.vs?.vcsec?.lockState === 'LOCKED'; },
        get isAwake()   { return this.vs?.vcsec?.sleepStatus === 'AWAKE'; },
        get isAsleep()  { return this.vs?.vcsec?.sleepStatus === 'ASLEEP'; },

        // ── Lifecycle ──────────────────────────────────────────

        async init() {
            // On unload: release in-memory cache + tell the Pi to
            // free its BLE mutex, but DO NOT wipe IDB-persisted
            // session metadata — we want the next page load to
            // hydrate without a full handshake.
            window.addEventListener('beforeunload', () => {
                airgap.closeAllInMemoryOnly();
            });

            // Re-render "as of X ago" labels every 30 seconds. The
            // previous 1s tick was forcing every timestamp binding
            // (multiple per page) to re-evaluate every second, which
            // Alpine pays for whether the result changed or not.
            // 30s is plenty for "X minutes ago"-grade staleness.
            this._agoInterval = setInterval(() => { this._agoTick++; }, 30_000);

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

        _autoParseEnrolUrl() {
            const v = (this.cfg.api || '').trim();
            if (!v.startsWith('airgap://enrol?')) return;
            try {
                const u = new URL(v.replace('airgap://', 'http://airgap-internal/'));
                const apiUrl = u.searchParams.get('api');
                const token = u.searchParams.get('token');
                const nickname = u.searchParams.get('nickname');
                if (apiUrl && token) {
                    this.cfg.api = apiUrl;
                    this.cfg.token = token;
                    if (nickname) this.cfg.nickname = nickname;
                    notify('Enrolment URL parsed', 'success');
                }
            } catch (e) {
                console.warn('[airgap] failed to parse enrolment URL:', e.message || e);
            }
        },

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
                this.vs = airgap.VehicleState.load(v);
                this._postVinSetup();
                this.vinInput = '';
                notify('VIN saved ✓', 'success');
            } catch (e) {
                notify(e.message || 'save VIN failed', 'error');
            } finally {
                this.savingVin = false;
            }
        },

        async connect(silent) {
            this.enrolError = '';
            this.busy = true;
            try {
                api.use(this.cfg);
                await api.get('/state'); // health check only — state lives in vs now
                const pairInfo = await api.get('/pair');
                this.vin = pairInfo?.vin || '';
                // Load device key BEFORE wiring the background reader,
                // so the first cold-start sync has a non-null ctx and
                // actually fires. Without this the first sync no-ops
                // and we wait 25s for the next tick.
                await this.loadKeyState();
                if (this.vin) {
                    this.vs = airgap.VehicleState.load(this.vin);
                    this._postVinSetup();
                }
                localStorage.setItem(CFG_KEY, JSON.stringify(this.cfg));
                this.screen = 'garage';
                if (!silent) notify('Connected ✓', 'success');
                await this.loadTokenInfo();
                await this.loadLog();
                airgap.logActivity({ label: silent ? 'reload-connect' : 'connect', result: 'ok', vin: this.vin });
            } catch (e) {
                this.enrolError = e.message || 'connect failed';
                this.screen = 'enrol';
                airgap.logActivity({ label: 'connect', result: 'error', note: this.enrolError });
            } finally {
                this.busy = false;
            }
        },

        // _postVinSetup is intentionally empty — Tesla's own Android
        // app does NOT fire any state fetch on BLE connect (Codex
        // confirmed: only auth + device-info; state is populated
        // from the Redux/cloud-backed local store, lazy-loaded per
        // UI screen, never automatically pulled via BLE on connect).
        //
        // Why we match that:
        //   • The earlier cold-start awake sync was an attempt to
        //     compensate for not having Tesla's cloud-backed cache.
        //     It put a multi-second BLE round-trip on the path of
        //     every page load, and any user click during it queued
        //     behind it.
        //   • Periodic polling had the same problem on a 20s tick.
        //   • Both turned the page open into a 20s lottery instead
        //     of an instant render.
        //
        // The model now: localStorage IS our local cache (the
        // equivalent of Tesla's Redux store, minus the cloud sync).
        // It's shown immediately on open with "as of X ago"
        // timestamps. State refreshes happen only when the user
        // pulls them — Refresh button (full awake), Verify button
        // (closures-only), or as the in-session piggyback after
        // VCSEC commands. Reactive session refetch (in _directDo)
        // recovers from car-side key rotation without the user
        // seeing it.
        _postVinSetup() { /* intentionally empty — see Tesla parallel above */ },

        // _buildSyncCtx synthesises the ctx object the sync primitives
        // need. Returns null if we can't currently do BLE (no key, no
        // VIN, etc.) — the sync primitives interpret null as "skip".
        _buildSyncCtx() {
            if (!this.vin || !this.vs) return null;
            const kp = this._cachedKeyPair;
            if (!kp) {
                // Try to (re)load lazily — but don't block. Background
                // reader will retry on the next interval.
                this._refreshKeyPair();
                return null;
            }
            return { api, vin: this.vin, deviceKeyPair: kp, state: this.vs };
        },

        _cachedKeyPair: null,
        async _refreshKeyPair() {
            try { this._cachedKeyPair = await airgap.loadDeviceKey(); }
            catch { this._cachedKeyPair = null; }
        },

        async forget() {
            if (!confirm('Forget this Pi? You\'ll need to paste the URL and token again. The bearer stays valid on the Pi — revoke it from /settings if you want it dead. The device key in IndexedDB will also be wiped — the car-side enrolment of its pubkey persists until you remove it manually from the Tesla mobile app.')) return;
            airgap.logActivity({ label: 'forget', result: 'event', vin: this.vin });
            airgap.closeAllCachedSessions();
            if (this.vin) airgap.resetVehicle(this.vin);
            localStorage.removeItem(CFG_KEY);
            try { await airgap.deleteDeviceKey(); } catch (e) { /* nothing to wipe */ }
            this.cfg = { api: '', token: '', nickname: '' };
            this.vs = null;
            this.log = [];
            this.hasKey = false;
            this.keyFp = '';
            this.vin = '';
            this._cachedKeyPair = null;
            this.tokenInfo = null;
            this.screen = 'enrol';
        },

        // ── Device key (Phase 3a) ──────────────────────────────

        async loadKeyState() {
            try {
                const kp = await airgap.loadDeviceKey();
                if (!kp) {
                    this.hasKey = false;
                    this.keyFp = '';
                    this._cachedKeyPair = null;
                    return;
                }
                this._cachedKeyPair = kp;
                const raw = await airgap.exportPubkeyRaw(kp.publicKey);
                this.hasKey = true;
                this.keyFp = await airgap.fingerprintHex(raw);
            } catch (e) {
                this.hasKey = false;
                this.keyFp = '';
                this._cachedKeyPair = null;
                this.keyError = 'key load failed: ' + (e.message || e);
            }
        },

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

        // ── _directDo — the single funnel for every command ────
        //
        // Signature: _directDo(actionBuilder, label, opts?)
        //   opts.optimistic: { slice, fields } — applied locally
        //     immediately on a successful command. For Infotainment
        //     slices the fields are marked dirty; cleared by the
        //     piggyback awake sync. For VCSEC slices no dirty flag;
        //     the background reader will reconcile.
        //   opts.piggyback: 'awake' | 'vcsec' | 'none' — override the
        //     domain-inferred default. Use 'awake' for wake-the-car
        //     commands that happen to be VCSEC-domain.
        //
        // Flow:
        //   1. Resolve key + VIN.
        //   2. Enqueue through the per-VIN serialization queue:
        //        a. Build the action.
        //        b. Open session via withCachedSession.
        //        c. Encrypt + send via sendDirectCommandWithApi.
        //        d. Decode response status; if signedMessageStatus
        //           reports failure, throw (no optimistic apply).
        //        e. If decryptedPayload present, decode it. For
        //           CarServer.Response → state.applyCarServerResponse
        //           (clears dirty). For FromVCSECMessage with
        //           vehicleStatus → state.applyVcsecStatus.
        //        f. Apply optimistic update (success path).
        //   3. Outside the queue: schedule piggyback sync.
        //
        // The optimistic apply happens AFTER the response landed so it
        // doesn't overwrite a richer applyCarServerResponse result.
        // For failed commands we skip the optimistic apply entirely.

        async _directDo(actionBuilder, label, opts) {
            if (this.directBusy) return;
            this.directBusy = true;
            this.directStatus = `[${label}] preparing…`;
            const optimistic       = opts?.optimistic;
            const piggybackOverride = opts?.piggyback;
            // opts.quiet suppresses the success toast (the status
            // line still updates). Used by per-card refresh icons
            // where the visible state update IS the user feedback —
            // a toast on top would be noisy.
            const quiet            = !!opts?.quiet;
            try {
                const kp = await airgap.loadDeviceKey();
                if (!kp) throw new Error('no device key — generate one first');
                this._cachedKeyPair = kp;

                let vin = this.vin;
                if (!vin) {
                    const pairInfo = await api.get('/pair');
                    vin = pairInfo?.vin;
                    if (!vin) throw new Error('Pi has no VIN configured — enter one in the VIN card above');
                    this.vin = vin;
                    this.vs = airgap.VehicleState.load(vin);
                    this._postVinSetup();
                }
                if (!this.vs) {
                    this.vs = airgap.VehicleState.load(vin);
                }

                const action = await actionBuilder();
                const queue  = airgap.queueFor(vin);

                // Retry loop — Tesla Android allows up to 10 attempts
                // per BLE command (`m99481a(TRANSPORT_BLUETOOTH) =
                // 10`). Each attempt sends the command on the cached
                // session and, on fault, either:
                //   • refreshes the session via in-place
                //     SessionInfoRequest (session-stale faults)
                //   • waits 100ms (transient faults)
                //   • bails immediately (semantic faults)
                // Re-encryption happens automatically — the action
                // bytes are re-fed through sendDirectCommandWithApi
                // which always derives fresh AAD from the current
                // session.counter / .epoch / .clockBase.
                let result, statusResult, status, opStatus, fault, faultName;
                let policy = null;
                let attempt = 0;
                while (attempt < airgap.MAX_BLE_ATTEMPTS) {
                    attempt += 1;
                    if (attempt > 1) {
                        this.directStatus = `[${label}] retry ${attempt}/${airgap.MAX_BLE_ATTEMPTS} · ${policy?.category || ''}`;
                    }
                    const attemptStart = Date.now();
                    let queueResult;
                    try {
                        queueResult = await queue.enqueue(async () => {
                            return await airgap.withCachedSession(
                            { api, vin, deviceKeyPair: kp, domain: action.domain },
                            async (session, cached) => {
                                this.directStatus = cached
                                    ? `[${label}]${attempt > 1 ? ' [retry ' + attempt + ']' : ''} cached · counter=${session.counter} · sending…`
                                    : `[${label}]${attempt > 1 ? ' [retry ' + attempt + ']' : ''} new session · counter=${session.counter} · sending…`;
                                const cmdResult = await airgap.sendDirectCommandWithApi({
                                    api, session, payloadBytes: action.bytes,
                                    flags: action.flags || 0,
                                });

                                // In-session piggyback — one extra
                                // round-trip on the same warm session
                                // to refresh the state slice that the
                                // command just changed. Two flavours:
                                //
                                //   • VCSEC commands always piggyback
                                //     vcsecGetStatusAction (closures,
                                //     locks, sleep flag).
                                //   • Infotainment commands opt in via
                                //     opts.piggybackState, which is an
                                //     action builder (e.g.
                                //     getClimateStateAction after a
                                //     climate-on).
                                //
                                // Only fires on the command's success
                                // path — if the car rejected it, the
                                // state hasn't changed so the read
                                // would just confirm the old state.
                                let statusResult = null;
                                const cmdOk = cmdResult.routable?.signedMessageStatus?.operationStatus !== 1;

                                let piggybackAction = null;
                                if (cmdOk && action.domain === airgap.DOMAIN_VEHICLE_SECURITY) {
                                    piggybackAction = airgap.vcsecGetStatusAction;
                                } else if (cmdOk && action.domain === airgap.DOMAIN_INFOTAINMENT && opts?.piggybackState) {
                                    piggybackAction = opts.piggybackState;
                                }

                                if (piggybackAction) {
                                    try {
                                        const stateAction = await piggybackAction();
                                        statusResult = await airgap.sendDirectCommandWithApi({
                                            api, session, payloadBytes: stateAction.bytes,
                                            flags: stateAction.flags || 0,
                                        });
                                    } catch (e) {
                                        console.warn('[airgap] in-session piggyback read failed:', e.message || e);
                                    }
                                }
                                return { cmdResult, statusResult };
                            },
                        );
                        });
                    } catch (transportErr) {
                        // The Pi returned a transport-level error
                        // ("BLE send: closed pipe", "session not
                        // found", etc.). This means our cached
                        // session (in-memory or IDB-hydrated) has a
                        // sessionId whose underlying BLE link is dead
                        // — usually because the Pi was rebooted, the
                        // car dropped the link, or the Pi's idle
                        // reaper closed the session.
                        //
                        // A SessionInfoRequest on the same dead link
                        // would just hit the same error, so the
                        // refreshCachedSession path is wrong here.
                        // Evict both memory and IDB and let the next
                        // attempt do a full handshake against a fresh
                        // Pi-side session.
                        if (airgap.isTransportDeadError(transportErr) && attempt < airgap.MAX_BLE_ATTEMPTS) {
                            console.warn('[airgap] transport dead (attempt', attempt + ') — full evict + retry:', transportErr.message);
                            this.directStatus = `[${label}] reconnecting…`;
                            airgap.logActivity({ label, result: 'evict', domain: action.domain, attempt, vin, note: transportErr.message });
                            await airgap.evictSession(vin, action.domain).catch(() => {});
                            policy = { category: 'transport-dead', retryable: true, delayMs: 0 };
                            continue;
                        }
                        // Pi-side BLE frame race: Pi returned the
                        // response to an earlier command (or an
                        // unsolicited car notification). The session
                        // is fine — we just re-send our command with
                        // a fresh counter+uuid. Pi's pre-send drain
                        // on the next Exchange pops the stale frame.
                        if (airgap.isStaleFrameError(transportErr) && attempt < airgap.MAX_BLE_ATTEMPTS) {
                            console.warn('[airgap] stale Pi frame (attempt', attempt + ') — retrying:', transportErr.message);
                            this.directStatus = `[${label}] retrying (stale frame)…`;
                            airgap.logActivity({ label, result: 'retry', domain: action.domain, attempt, vin, note: 'stale-frame' });
                            policy = { category: 'stale-frame', retryable: true, delayMs: airgap.TRANSIENT_DELAY_MS };
                            await new Promise(r => setTimeout(r, policy.delayMs));
                            continue;
                        }
                        // Anything else (true network failure, bad
                        // bearer, etc.) bubbles to the outer handler.
                        throw transportErr;
                    }

                    result       = queueResult.cmdResult;
                    statusResult = queueResult.statusResult;
                    const routable = result.routable;
                    status   = routable.signedMessageStatus;
                    opStatus = status?.operationStatus;
                    fault    = status?.signedMessageFault
                            ?? status?.signed_message_fault
                            ?? status?.fault;
                    faultName = _faultName(fault);

                    const durationMs = Date.now() - attemptStart;

                    if (opStatus === 0 || opStatus === undefined) {
                        // Success — fall through to side-effect block.
                        if (attempt > 1) console.log('[airgap] succeeded on attempt', attempt);
                        airgap.logActivity({ label, result: 'ok', domain: action.domain, attempt, durationMs, vin });
                        break;
                    }

                    policy = airgap.evaluateFault(fault);
                    if (!policy.retryable) {
                        // Semantic fault — surface and stop. No state
                        // writes, no piggyback.
                        const msg = `[${label}] status=${opStatus} fault=${fault}(${faultName})`;
                        this.directStatus = msg;
                        console.warn('[airgap]', msg);
                        notify(msg, 'error');
                        airgap.logActivity({ label, result: 'error', domain: action.domain, attempt, fault, durationMs, vin, note: faultName });
                        return;
                    }

                    if (policy.category === 'session-stale') {
                        console.warn('[airgap] session stale (attempt', attempt + ') —', faultName, '— refreshing in place');
                        this.directStatus = `[${label}] refreshing session…`;
                        airgap.logActivity({ label, result: 'refresh', domain: action.domain, attempt, fault, durationMs, vin, note: faultName });
                        await airgap.refreshCachedSession({
                            api, vin, domain: action.domain, deviceKeyPair: kp,
                        }).catch(e => {
                            console.warn('[airgap] refresh threw:', e.message || e);
                            return false;
                        });
                    } else {
                        airgap.logActivity({ label, result: 'retry', domain: action.domain, attempt, fault, durationMs, vin, note: faultName });
                    }

                    if (policy.delayMs > 0) {
                        await new Promise(r => setTimeout(r, policy.delayMs));
                    }
                    // loop continues with another attempt
                }

                if (attempt >= airgap.MAX_BLE_ATTEMPTS && opStatus !== 0 && opStatus !== undefined) {
                    const msg = `[${label}] exhausted ${airgap.MAX_BLE_ATTEMPTS} retries · last fault=${fault}(${faultName})`;
                    this.directStatus = msg;
                    console.warn('[airgap]', msg);
                    notify(msg, 'error');
                    airgap.logActivity({ label, result: 'error', domain: action.domain, attempt, fault, vin, note: 'retries-exhausted: ' + faultName });
                    return;
                }

                // No result at all → every attempt threw before we
                // could read the response (stale-frame loop, transport
                // dead, etc.). Surface a clear error rather than
                // crashing on `result.decryptedPayload` below.
                if (!result) {
                    const msg = `[${label}] exhausted ${airgap.MAX_BLE_ATTEMPTS} retries · ${policy?.category || 'transport'} — no clean response from Pi`;
                    this.directStatus = msg;
                    console.warn('[airgap]', msg);
                    notify(msg, 'error');
                    airgap.logActivity({ label, result: 'error', domain: action.domain, attempt, vin, note: 'no-result: ' + (policy?.category || 'unknown') });
                    return;
                }

                // Success path: decode the command response payload
                // if it carried one. For VCSEC commands this is
                // typically a CommandStatus ACK (no state), and the
                // fresh closure/lock state comes from the in-session
                // statusResult below instead.
                if (result.decryptedPayload) {
                    try {
                        const proto = await airgap.loadProto();
                        if (action.domain === airgap.DOMAIN_INFOTAINMENT) {
                            const carResp = airgap.decodeMessage(proto.Response, result.decryptedPayload);
                            this.vs.applyCarServerResponse(carResp);
                        } else if (action.domain === airgap.DOMAIN_VEHICLE_SECURITY) {
                            const fromVcsec = airgap.decodeMessage(proto.FromVCSECMessage, result.decryptedPayload);
                            if (fromVcsec.vehicleStatus) {
                                this.vs.applyVcsecStatus(fromVcsec.vehicleStatus);
                            }
                        }
                    } catch (e) {
                        console.warn('[airgap] response decode failed:', e.message || e);
                    }
                }

                // In-session piggyback state — the state-read we
                // sent right after the command on the same warm
                // session. Decoded based on which domain we're on:
                //   • VCSEC → FromVCSECMessage with VehicleStatus
                //   • Infotainment → CarServer.Response with one
                //     state slice (charge / climate / drive)
                // Applied AFTER the command-response decode so a
                // real status result overrides any stale field from
                // the command response.
                if (statusResult?.decryptedPayload) {
                    try {
                        const proto = await airgap.loadProto();
                        if (action.domain === airgap.DOMAIN_VEHICLE_SECURITY) {
                            const fromVcsec = airgap.decodeMessage(proto.FromVCSECMessage, statusResult.decryptedPayload);
                            if (fromVcsec.vehicleStatus) {
                                this.vs.applyVcsecStatus(fromVcsec.vehicleStatus);
                            }
                        } else if (action.domain === airgap.DOMAIN_INFOTAINMENT) {
                            const carResp = airgap.decodeMessage(proto.Response, statusResult.decryptedPayload);
                            this.vs.applyCarServerResponse(carResp);
                        }
                    } catch (e) {
                        console.warn('[airgap] in-session piggyback decode failed:', e.message || e);
                    }
                }

                // Optimistic apply LAST — fills in fields neither
                // the command response nor the VCSEC status carried
                // (e.g. Infotainment commands rarely return state).
                // It also re-stamps closuresIntent so a subsequent
                // background read can't immediately stomp the user's
                // visible intent.
                if (optimistic?.slice && optimistic?.fields) {
                    this.vs.applyOptimistic(optimistic.slice, optimistic.fields);
                }

                this.directStatus = `[${label}] ✓ accepted by car`;
                if (!quiet) notify(`${label} ✓`, 'success');
                await this.loadLog();

                // The old debounced schedulePiggyback path is gone.
                // VCSEC state refresh now happens in-session above
                // (no second handshake, no 500ms debounce, no extra
                // queue trip). Infotainment state refresh is
                // user-initiated via the Refresh button.
                //
                // opts.piggyback is still honoured for explicit
                // overrides — directWake passes 'awake' because the
                // whole point is to grab fresh state while the
                // console is freshly woken.
                if (piggybackOverride && piggybackOverride !== 'none') {
                    airgap.schedulePiggyback(this.vin, piggybackOverride, () => this._buildSyncCtx());
                }
            } catch (e) {
                console.error('[airgap] direct command failed:', e);
                this.directStatus = `[${label}] ✗ ${e.message || e}`;
                notify(`${label}: ${e.message || e}`, 'error');
            } finally {
                this.directBusy = false;
            }
        },

        // ── Direct action methods ──────────────────────────────
        //
        // Each method wires a label, an action builder, and (where
        // there's a meaningful local-state effect) an optimistic
        // intent. Pure "fire-and-forget" commands (honk, flash, wake)
        // skip the optimistic field — they don't change displayed
        // state. wake is special-cased to schedule 'awake' piggyback
        // since it leaves the centre console up.

        directHonk()             { return this._directDo(airgap.honkAction,        'honk'); },
        directFlashLights()      { return this._directDo(airgap.flashLightsAction, 'flash-lights'); },

        directLock() {
            return this._directDo(airgap.lockAction, 'lock', {
                optimistic: { slice: 'vcsec.lockState', fields: { value: 'LOCKED' } },
            });
        },
        directUnlock() {
            return this._directDo(airgap.unlockAction, 'unlock', {
                optimistic: { slice: 'vcsec.lockState', fields: { value: 'UNLOCKED' } },
            });
        },
        directWake() {
            // Wake explicitly powers up the centre console — piggyback
            // an awake sync so we grab fresh Infotainment state in the
            // window the wake created.
            return this._directDo(airgap.wakeAction, 'wake', { piggyback: 'awake' });
        },

        directOpenFrunk() {
            return this._directDo(airgap.openFrunkAction, 'open-frunk', {
                optimistic: { slice: 'vcsec.closures', fields: { frontTrunk: 'OPEN' } },
            });
        },
        directOpenTrunk() {
            return this._directDo(airgap.openTrunkAction, 'open-trunk', {
                optimistic: { slice: 'vcsec.closures', fields: { rearTrunk: 'OPEN' } },
            });
        },
        directCloseTrunk() {
            return this._directDo(airgap.closeTrunkAction, 'close-trunk', {
                optimistic: { slice: 'vcsec.closures', fields: { rearTrunk: 'CLOSED' } },
            });
        },
        directOpenChargePort() {
            return this._directDo(airgap.openChargePortAction, 'open-charge-port', {
                optimistic: { slice: 'vcsec.closures', fields: { chargePort: 'OPEN' } },
            });
        },
        directCloseChargePort() {
            return this._directDo(airgap.closeChargePortAction, 'close-charge-port', {
                optimistic: { slice: 'vcsec.closures', fields: { chargePort: 'CLOSED' } },
            });
        },

        directClimateOn() {
            return this._directDo(airgap.climateOnAction, 'climate-on', {
                optimistic:     { slice: 'climate', fields: { is_on: true } },
                piggybackState: airgap.getClimateStateAction,
            });
        },
        directClimateOff() {
            return this._directDo(airgap.climateOffAction, 'climate-off', {
                optimistic:     { slice: 'climate', fields: { is_on: false } },
                piggybackState: airgap.getClimateStateAction,
            });
        },
        directSentryOn() {
            return this._directDo(airgap.sentryOnAction, 'sentry-on', {
                optimistic: { slice: 'sentry', fields: { is_on: true } },
            });
        },
        directSentryOff() {
            return this._directDo(airgap.sentryOffAction, 'sentry-off', {
                optimistic: { slice: 'sentry', fields: { is_on: false } },
            });
        },
        directStartCharging() {
            return this._directDo(airgap.startChargingAction, 'start-charging', {
                optimistic:     { slice: 'charge', fields: { charging_state: 'Charging' } },
                piggybackState: airgap.getChargeStateAction,
            });
        },
        directStopCharging() {
            return this._directDo(airgap.stopChargingAction, 'stop-charging', {
                optimistic:     { slice: 'charge', fields: { charging_state: 'Disconnected' } },
                piggybackState: airgap.getChargeStateAction,
            });
        },
        directChargeMaxRange()      { return this._directDo(airgap.chargeMaxRangeAction,      'charge-max-range',      { piggybackState: airgap.getChargeStateAction }); },
        directChargeStandardRange() { return this._directDo(airgap.chargeStandardRangeAction, 'charge-standard-range', { piggybackState: airgap.getChargeStateAction }); },
        directSetChargeLimit() {
            const p = Number(this.chargeLimit);
            return this._directDo(() => airgap.setChargeLimitAction(p), `set-charge-limit:${p}`, {
                optimistic:     { slice: 'charge', fields: { charge_limit_soc: p } },
                piggybackState: airgap.getChargeStateAction,
            });
        },
        directDefrostOn()  { return this._directDo(airgap.defrostOnAction,  'defrost-on',  { piggybackState: airgap.getClimateStateAction }); },
        directDefrostOff() { return this._directDo(airgap.defrostOffAction, 'defrost-off', { piggybackState: airgap.getClimateStateAction }); },
        directSetClimateTemp() {
            const c = Number(this.climateTarget);
            return this._directDo(() => airgap.setClimateTempAction(c), `set-climate-temp:${c}`, {
                optimistic:     { slice: 'climate', fields: { target_temp_c: c } },
                piggybackState: airgap.getClimateStateAction,
            });
        },

        // ── Per-card state refresh ──────────────────────────────
        //
        // Tesla's Android app lazy-loads state per UI screen rather
        // than fetching everything on connect (Codex Q5 confirmed).
        // Each of these methods drives one slice's getVehicleData
        // read through the same _directDo retry/refresh machinery
        // as a command. They're QUIET — success toast suppressed —
        // because the slice update IS the user feedback.
        //
        // Cost: one BLE round-trip per call on the warm Infotainment
        // session (~200ms). Triggers in-place session refresh if
        // car-side keys have rotated, transparent to the user.

        directReadCharge()  { return this._directDo(airgap.getChargeStateAction,  'read-charge',  { quiet: true }); },
        directReadClimate() { return this._directDo(airgap.getClimateStateAction, 'read-climate', { quiet: true }); },
        directReadDrive()   { return this._directDo(airgap.getDriveStateAction,   'read-drive',   { quiet: true }); },

        // ── Global refresh (button on the top bar) ─────────────
        //
        // The Refresh button on the garage bar wakes the car and pulls
        // full vehicle data — matches the Tesla app's behaviour.
        // Goes through the queue so a refresh that lands mid-command
        // is serialized after the in-flight command.
        async directRefreshState() {
            if (!this.vin) { notify('VIN not set', 'error'); return; }
            const ctx = this._buildSyncCtx();
            if (!ctx) { notify('No device key — generate one first', 'error'); return; }
            this.directBusy = true;
            this.directStatus = '[refresh] waking car…';
            const refreshStart = Date.now();
            try {
                const r = await airgap.queueFor(this.vin).enqueue(async () => {
                    return await airgap.awakeSync(ctx);
                });
                // After a manual refresh we also want fresh VCSEC
                // closures/lock/sleep.
                airgap.schedulePiggyback(this.vin, 'vcsec', () => this._buildSyncCtx());

                // Surface the per-slice outcome. If every slice came
                // back "no-payload" or errored, toasting "✓ state
                // synced" would be a lie — show the truth so we know
                // to dig into the car-side reason.
                const okSlices    = Object.entries(r.results || {}).filter(([_,s]) => s === 'ok').map(([n]) => n);
                const failSlices  = Object.entries(r.results || {}).filter(([_,s]) => s && s !== 'ok');
                const durationMs = Date.now() - refreshStart;
                if (!r.ok) {
                    const detail = failSlices.map(([n,s]) => `${n}: ${s}`).join(' · ');
                    this.directStatus = `[refresh] ✗ no slices populated — ${detail}`;
                    notify('Refresh: nothing came back (check console)', 'error');
                    airgap.logActivity({ label: 'refresh-state', result: 'error', durationMs, vin: this.vin, note: detail });
                } else if (failSlices.length === 0) {
                    this.directStatus = `[refresh] ✓ ${okSlices.join(', ')}`;
                    notify('State refreshed ✓', 'success');
                    airgap.logActivity({ label: 'refresh-state', result: 'ok', durationMs, vin: this.vin, note: okSlices.join(',') });
                } else {
                    this.directStatus = `[refresh] partial — ok: ${okSlices.join(',')}; failed: ${failSlices.map(([n]) => n).join(',')}`;
                    notify(`Refresh: partial (${okSlices.length}/3 slices)`, 'success');
                    airgap.logActivity({ label: 'refresh-state', result: 'retry', durationMs, vin: this.vin, note: `partial: ${okSlices.length}/3` });
                }
            } catch (e) {
                console.error('[airgap] refresh failed:', e);
                this.directStatus = `[refresh] ✗ ${e.message || e}`;
                notify(`Refresh: ${e.message || e}`, 'error');
                airgap.logActivity({ label: 'refresh-state', result: 'error', vin: this.vin, note: e.message || String(e) });
            } finally {
                this.directBusy = false;
            }
        },

        // resetBle drops every cached BLE session and clears the
        // per-VIN serialization queue, then unblocks the busy flag.
        // Use when the UI feels stuck — e.g. a click did nothing for
        // a long time. Forces the NEXT command to open a fresh
        // session against the car.
        resetBle() {
            try { airgap.closeAllCachedSessions(); } catch {}
            if (this.vin) {
                try { airgap.cancelPiggyback(this.vin); } catch {}
            }
            try { airgap.resetQueues(); } catch {}
            this.directBusy = false;
            this.directStatus = '[reset] BLE state cleared — next command opens a fresh session';
            notify('BLE state reset', 'success');
            airgap.logActivity({ label: 'reset-ble', result: 'event', vin: this.vin });
        },

        // verifyClosures fires just a VCSEC GET_STATUS. Used by the
        // "Verify" button on stuck-stale closure fields — checks
        // VCSEC's current view without waking the centre console.
        // Does NOT promise truth if VCSEC's Hall sensor itself is
        // lagging; for that the user has to hit Refresh (wake).
        async verifyClosures() {
            if (!this.vin) return;
            const ctx = this._buildSyncCtx();
            if (!ctx) { notify('No device key', 'error'); return; }
            try {
                await airgap.queueFor(this.vin).enqueue(() => airgap.vcsecSync(ctx));
                notify('VCSEC re-read ✓', 'success');
            } catch (e) {
                notify(`Verify: ${e.message || e}`, 'error');
            }
        },

        // ── Thread C-3 extras ──────────────────────────────────

        directSetClimateKeeper(mode) { return this._directDo(() => airgap.setClimateKeeperAction(mode), `climate-keeper:${mode}`); },
        directSetCabinOverheat(on)   { return this._directDo(() => airgap.setCabinOverheatAction(on),   `cabin-overheat:${on}`); },
        directKeepAccPowerOn()       { return this._directDo(() => airgap.setKeepAccPowerAction(true),  'keep-acc-power-on'); },
        directKeepAccPowerOff()      { return this._directDo(() => airgap.setKeepAccPowerAction(false), 'keep-acc-power-off'); },
        directWheelHeaterOn()        { return this._directDo(() => airgap.setSteeringWheelHeaterAction(true),  'wheel-heater-on'); },
        directWheelHeaterOff()       { return this._directDo(() => airgap.setSteeringWheelHeaterAction(false), 'wheel-heater-off'); },

        directVentWindows() {
            return this._directDo(airgap.ventWindowsAction, 'vent-windows', {
                optimistic: { slice: 'windows', fields: { any_open: true } },
            });
        },
        directCloseWindows() {
            return this._directDo(airgap.closeWindowsAction, 'close-windows', {
                optimistic: { slice: 'windows', fields: { any_open: false } },
            });
        },

        directSeatHeater(position, level)  { return this._directDo(() => airgap.setSeatHeaterAction(position, level), `seat-heater:${position}=${level}`); },
        directSeatCooler(position, level)  { return this._directDo(() => airgap.setSeatCoolerAction(position, level), `seat-cooler:${position}=${level}`); },

        directHomelink() {
            // Car location is in LocationState (vs.location), NOT
            // DriveState — DriveState only carries shift/speed/route.
            const lat = this.vs?.location?.latitude;
            const lon = this.vs?.location?.longitude;
            if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
                notify('Homelink needs car location — hit Refresh first', 'error');
                return;
            }
            return this._directDo(
                () => airgap.homelinkAction({ latitude: lat, longitude: lon }),
                'homelink',
            );
        },
        directRemoteDrive()          { return this._directDo(airgap.remoteDriveAction, 'remote-drive'); },

        directValetOn()              { return this._directDo(() => airgap.setValetModeAction(true,  this.valetPin), 'valet-on');  },
        directValetOff()             { return this._directDo(() => airgap.setValetModeAction(false, this.valetPin), 'valet-off'); },
        directSpeedLimitActivate()   { return this._directDo(() => airgap.activateSpeedLimitAction(this.speedLimitPin),   'speed-limit-activate');   },
        directSpeedLimitDeactivate() { return this._directDo(() => airgap.deactivateSpeedLimitAction(this.speedLimitPin), 'speed-limit-deactivate'); },
        directSpeedLimitClearPin()   { return this._directDo(() => airgap.clearSpeedLimitPinAction(this.speedLimitPin),   'speed-limit-clear-pin');  },
        directSpeedLimitSet()        { return this._directDo(() => airgap.setSpeedLimitMphAction(Number(this.speedLimitMph)), `speed-limit-set:${this.speedLimitMph}mph`); },

        directNavigateGps() {
            return this._directDo(() => {
                const label = (this.navLabel || '').trim();
                if (label) {
                    return airgap.navigateGpsWithLabelAction({ lat: Number(this.navLat), lon: Number(this.navLon), label, order: airgap.NAV_ORDER.REPLACE });
                }
                return airgap.navigateGpsAction({ lat: Number(this.navLat), lon: Number(this.navLon), order: airgap.NAV_ORDER.REPLACE });
            }, 'navigate-gps');
        },
        directNavigateSearch()    { return this._directDo(() => airgap.navigateSearchAction({ query: (this.navQuery||'').trim(), order: airgap.NAV_ORDER.REPLACE }), 'navigate-search'); },
        directNavigateWaypoints() { return this._directDo(() => airgap.navigateWaypointsAction({ waypoints: (this.navWaypoints||'').trim() }), 'navigate-waypoints'); },

        directBoombox(sound)      { return this._directDo(() => airgap.boomboxAction(sound), `boombox:${sound}`); },
        directBoomboxFromInput()  { return this._directDo(() => airgap.boomboxAction(Number(this.boomboxId)), `boombox:${this.boomboxId}`); },

        // ── Enrolment ──────────────────────────────────────────

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

        // ── Token self-management (Thread E) ───────────────────

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
                setTimeout(() => this.forget(), 1500);
            } catch (e) {
                notify(e.message || 'self-revoke failed', 'error');
            } finally {
                this.revokingSelf = false;
            }
        },

        // ── Log + audit ────────────────────────────────────────
        async loadLog() {
            try {
                this.log = (await api.get('/log')) || [];
            } catch (e) { /* api wrapper toasted */ }
        },

        // Used by the "Refresh" button on the activity strip — just
        // reloads the log; state refresh is separate.
        async refresh() { return this.loadLog(); },

        // ── Display helpers (templates call these) ─────────────
        humanAgo,
    };
}

// _faultName lifts the fault code to a friendly string for the toast
// + console line. Mirrors the enum table the old _directDo carried.
function _faultName(fault) {
    return ({
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
}

// evaluateFault + MAX_BLE_ATTEMPTS live in session.js — they belong
// with the other session/protocol primitives, no Alpine deps. The
// retry loop in _directDo above calls them directly through the
// airgap.* namespace.
