// state.js — client-side state store + sync primitives + serialization
//                queue + piggyback scheduler + background reader.
//
// The model, in one paragraph:
//
//   Every field the car owns is mirrored in C (this store). The mirror
//   is split by domain. VCSEC fields (lock / closures / sleep flag /
//   presence) are kept LIVE by a cheap background reader that polls
//   VCSEC GET_STATUS while the tab is foregrounded — no dirty flags,
//   VCSEC just IS the source of truth (with the known closure-sensor
//   lag surfaced via timestamps). Infotainment fields (charge / climate
//   / drive) are EVENTUALLY consistent: a successful command updates
//   them optimistically and marks them dirty, and dirty only clears on
//   the next awake sync (full GetVehicleData read). Awake sync wakes
//   the centre console if asleep, so it only fires deliberately — after
//   an Infotainment command, after a wake, when VCSEC reports AWAKE, or
//   on manual Refresh.
//
// Tesla's own Android app does almost exactly this — confirmed via
// JADX decompile (see VCSEC_findings/): cached BLE status with a
// timestamp + isUpdated flag, command success decoupled from state
// freshness, explicit GET_STATUS primitive, no hidden polling loop.
//
// References:
//   • Codex evidence: VCSEC_findings/tesla-vcsec-state-sync-summary.md
//   • Design discussion: in-conversation, locked in by user.

window.airgap = window.airgap || {};

// ── Persistence ──
//
// localStorage holds the last-known C state, keyed by VIN. ~10KB per
// car is well under the ~5MB localStorage cap, and JSON.stringify is
// fast enough that we can resave on every change. IndexedDB would be
// nicer but adds async complexity we don't currently need.

const STATE_PREFIX = 'airgap-vehicle-state-';

function _storageKey(vin) { return STATE_PREFIX + vin; }

// ── Slice shape ──
//
// Each slice has:
//   • value fields (specific to the slice)
//   • dirty: { [field]: true }  — field names with un-confirmed local
//                            writes (always empty for VCSEC slice;
//                            awake sync clears Infotainment slices).
//                            Plain object rather than Set so Alpine
//                            tracks add/delete reactively — Sets are
//                            opaque to its Proxy-based reactivity.
//   • lastUpdatedAt: ms   — when the slice was last written by a sync
//   • isUpdated: bool     — transient pulse flag (NOT persisted),
//                            true for ~1.5s after a fresh sync writes
//                            the slice, so the UI can highlight changes
//
// Field values use the friendly shape the existing UI expects (battery
// has soc / range_km / charging_state / charge_limit_soc; climate has
// inside_temp_c / outside_temp_c / target_temp_c / is_on). The mapping
// from raw proto to this shape lives in the apply*Response helpers.

function _emptySlice() {
    return {
        dirty: {},
        lastUpdatedAt: 0,
        isUpdated: false,
    };
}

// ── VehicleState ──
//
// One instance per VIN. Alpine binds against the public slice
// properties (vcsec, charge, climate, drive). Mutations go through
// applyXxx() methods so dirty/isUpdated bookkeeping stays consistent.
//
// All public state lives directly on `this` (rather than on a nested
// _state) so Alpine reactivity works without explicit accessor wiring.

// Grace window for optimistic closure intent. The VCSEC Hall sensor
// can take minutes to repoll, and if our optimistic "trunk=open" gets
// blindly overwritten by a stale "trunk=closed" reading 1s later the
// UI flip-flops badly. Within this window, VCSEC sync writes every
// other closure field but leaves recently-intended ones alone.
//
// Tuned long enough for the sensor to plausibly catch up (~tens of
// seconds) but short enough that a stuck-stale value gets corrected
// soon. After the window expires, VCSEC reasserts itself — and the
// "Verify" button always re-reads if the user wants confirmation
// faster.
const CLOSURE_INTENT_GRACE_MS = 30_000;

class VehicleState {
    constructor(vin) {
        this.vin = vin;
        this.vcsec    = { lockState: null, sleepStatus: null, userPresence: null,
                          closures: {}, closuresIntent: {}, ..._emptySlice() };
        this.charge   = { ..._emptySlice() };
        this.climate  = { ..._emptySlice() };
        this.drive    = { ..._emptySlice() };
        this.location = { ..._emptySlice() }; // latitude/longitude from LocationState
        // sentry / windows come from Infotainment ClosuresState — same
        // sub-message that carries door/trunk live truth. Keep them on
        // dedicated slices so UI bindings don't need to dig into
        // vcsec.closures.
        this.sentry   = { ..._emptySlice() }; // is_on + raw mode name
        this.windows  = { ..._emptySlice() }; // per-window bool open flags
    }

    // isAwake — small convenience for the awake-sync gating logic.
    // Treat anything other than confirmed AWAKE (including UNKNOWN) as
    // not-awake; safer when in doubt.
    get isAwake() { return this.vcsec.sleepStatus === 'AWAKE'; }

    // ── Persistence ──

    save() {
        try {
            localStorage.setItem(_storageKey(this.vin), JSON.stringify(this._serialize()));
        } catch (e) {
            console.warn('[airgap] state save failed:', e.message || e);
        }
    }

    _serialize() {
        return {
            vin: this.vin,
            vcsec:    _serializeSlice(this.vcsec),
            charge:   _serializeSlice(this.charge),
            climate:  _serializeSlice(this.climate),
            drive:    _serializeSlice(this.drive),
            location: _serializeSlice(this.location),
            sentry:   _serializeSlice(this.sentry),
            windows:  _serializeSlice(this.windows),
        };
    }

    static load(vin) {
        const s = new VehicleState(vin);
        try {
            const raw = localStorage.getItem(_storageKey(vin));
            if (!raw) return s;
            const obj = JSON.parse(raw);
            if (obj.vcsec)    Object.assign(s.vcsec,    _deserializeSlice(obj.vcsec));
            if (obj.charge)   Object.assign(s.charge,   _deserializeSlice(obj.charge));
            if (obj.climate)  Object.assign(s.climate,  _deserializeSlice(obj.climate));
            if (obj.drive)    Object.assign(s.drive,    _deserializeSlice(obj.drive));
            if (obj.location) Object.assign(s.location, _deserializeSlice(obj.location));
            if (obj.sentry)   Object.assign(s.sentry,   _deserializeSlice(obj.sentry));
            if (obj.windows)  Object.assign(s.windows,  _deserializeSlice(obj.windows));
        } catch (e) {
            console.warn('[airgap] state load failed:', e.message || e);
        }
        return s;
    }

    // ── Writer rules ──
    //
    // applyVcsecStatus — overwrites the VCSEC slice from a decoded
    // VCSEC.VehicleStatus. No dirty tracking here; VCSEC is the
    // authoritative source for these fields, so any incoming value
    // replaces what we had.

    applyVcsecStatus(vehicleStatus) {
        if (!vehicleStatus) return;
        const lock     = _enumName(vehicleStatus.vehicleLockState, _LOCK_NAMES);
        const sleep    = _enumName(vehicleStatus.vehicleSleepStatus, _SLEEP_NAMES);
        const presence = _enumName(vehicleStatus.userPresence,       _PRESENCE_NAMES);

        // Closure update respects the intent grace window: VCSEC may
        // be carrying a stale Hall-sensor reading that contradicts a
        // closure command we just issued. Within CLOSURE_INTENT_GRACE_MS
        // of an optimistic write we keep our intent; after that we
        // trust VCSEC's view.
        const now = Date.now();
        const incoming = {};
        const cs = vehicleStatus.closureStatuses;
        if (cs) {
            incoming.frontDriverDoor    = _enumName(cs.frontDriverDoor,    _CLOSURE_NAMES);
            incoming.frontPassengerDoor = _enumName(cs.frontPassengerDoor, _CLOSURE_NAMES);
            incoming.rearDriverDoor     = _enumName(cs.rearDriverDoor,     _CLOSURE_NAMES);
            incoming.rearPassengerDoor  = _enumName(cs.rearPassengerDoor,  _CLOSURE_NAMES);
            incoming.rearTrunk          = _enumName(cs.rearTrunk,          _CLOSURE_NAMES);
            incoming.frontTrunk         = _enumName(cs.frontTrunk,         _CLOSURE_NAMES);
            incoming.chargePort         = _enumName(cs.chargePort,         _CLOSURE_NAMES);
            incoming.tonneau            = _enumName(cs.tonneau,            _CLOSURE_NAMES);
        }
        // Merge field-by-field with intent grace.
        const merged = { ...this.vcsec.closures };
        const newIntent = {};
        for (const [k, v] of Object.entries(incoming)) {
            const intentExpiresAt = this.vcsec.closuresIntent?.[k];
            if (intentExpiresAt && intentExpiresAt > now) {
                // Keep our optimistic value; carry the intent forward.
                newIntent[k] = intentExpiresAt;
            } else {
                merged[k] = v;
            }
        }

        this.vcsec.lockState      = lock;
        this.vcsec.sleepStatus    = sleep;
        this.vcsec.userPresence   = presence;
        this.vcsec.closures       = merged;
        this.vcsec.closuresIntent = newIntent;
        _touchSlice(this.vcsec);
        this.save();
    }

    // applyCarServerResponse — extracts charge / climate / drive slices
    // from a decoded CarServer.Response and writes them with dirty
    // clearing semantics. A field that arrives in the response gets
    // its value updated AND its dirty entry removed — the car just
    // told us the truth.

    applyCarServerResponse(carResp) {
        if (!carResp) return;

        const cs = carResp.vehicleData?.chargeState  || carResp.chargeState;
        if (cs) {
            const fields = {
                soc:              cs.batteryLevel,
                range_km:         cs.batteryRange != null
                                  ? Math.round(cs.batteryRange * 1.60934)
                                  : null,
                // chargingState is a protobuf oneof — protobuf.js
                // returns it as { Charging: {} } / { Disconnected: {} }
                // etc. Normalise to its case name so the UI gets a
                // plain string and existing bindings keep working.
                charging_state:   _oneofName(cs.chargingState),
                charge_limit_soc: cs.chargeLimitSoc,
            };
            this._applySliceFromSync(this.charge, fields);
        }

        const cl = carResp.vehicleData?.climateState || carResp.climateState;
        if (cl) {
            const fields = {
                inside_temp_c:  cl.insideTempCelsius,
                outside_temp_c: cl.outsideTempCelsius,
                target_temp_c:  cl.driverTempSetting,
                is_on:          cl.isClimateOn,
            };
            this._applySliceFromSync(this.climate, fields);
        }

        const dr = carResp.vehicleData?.driveState  || carResp.driveState;
        if (dr) {
            const fields = {
                speed: dr.speed,
                // shiftState is a oneof like chargingState; normalise.
                gear:  _oneofName(dr.shiftState),
            };
            this._applySliceFromSync(this.drive, fields);
        }

        // LocationState (lat/lon/heading) is a separate sub-message —
        // VehicleData.locationState, NOT VehicleData.driveState. The
        // proto uses synthetic oneofs for "explicit optional" fields,
        // but protobuf.js exposes the values directly on the parent.
        const loc = carResp.vehicleData?.locationState || carResp.locationState;
        if (loc) {
            const fields = {
                latitude:  loc.latitude,
                longitude: loc.longitude,
                heading:   loc.heading,
            };
            this._applySliceFromSync(this.location, fields);
        }

        // ClosuresState — when Infotainment reports closure bools we
        // trust them as live truth (no Hall-sensor lag), AND we clear
        // any matching VCSEC closure intent. Bool semantics: true =
        // OPEN, false = CLOSED. Mapping back to the same enum the
        // VCSEC slice uses keeps the UI binding uniform.
        const cls = carResp.vehicleData?.closuresState || carResp.closuresState;
        if (cls) {
            const m = {};
            const apply = (key, val) => {
                if (val === undefined) return;
                m[key] = val ? 'OPEN' : 'CLOSED';
            };
            apply('frontDriverDoor',    cls.doorOpenDriverFront);
            apply('frontPassengerDoor', cls.doorOpenPassengerFront);
            apply('rearDriverDoor',     cls.doorOpenDriverRear);
            apply('rearPassengerDoor',  cls.doorOpenPassengerRear);
            apply('frontTrunk',         cls.doorOpenTrunkFront);
            apply('rearTrunk',          cls.doorOpenTrunkRear);
            if (Object.keys(m).length) {
                Object.assign(this.vcsec.closures, m);
                // Clear matching intent — Infotainment told us truth.
                for (const k of Object.keys(m)) {
                    delete this.vcsec.closuresIntent[k];
                }
                _touchSlice(this.vcsec);
            }

            // Windows — four bool flags. Map to vs.windows; UI binds
            // against vs.windows.any_open to render a "some vented"
            // hint near the Vent/Close buttons.
            const w = {};
            const setW = (k, v) => { if (v !== undefined) w[k] = !!v; };
            setW('driver_front',    cls.windowOpenDriverFront);
            setW('passenger_front', cls.windowOpenPassengerFront);
            setW('driver_rear',     cls.windowOpenDriverRear);
            setW('passenger_rear',  cls.windowOpenPassengerRear);
            if (Object.keys(w).length) {
                Object.assign(this.windows, w);
                this.windows.any_open = Object.values(w).some(v => v);
                _touchSlice(this.windows);
            }

            // Sentry — sentry_mode_state is a oneof (Off / Idle /
            // Armed / Aware / Panic / Quiet). Surface both the raw
            // mode name and a derived is_on flag for the existing
            // "Armed / Idle" UI binding.
            if (cls.sentryModeState) {
                const mode = _oneofName(cls.sentryModeState);
                this.sentry.mode  = mode;
                this.sentry.is_on = !(mode === 'Off' || mode == null);
                _touchSlice(this.sentry);
            }
        }

        this.save();
    }

    // applyOptimistic — a successful command's effect on the slice.
    // For Infotainment slices, every named field is marked dirty (we
    // applied our intent, awaiting confirmation). For VCSEC, we just
    // write — the background reader will reconcile, and there's no
    // intent-vs-truth gap to model since VCSEC IS truth for its
    // fields.
    //
    // sliceName ∈ {'charge', 'climate', 'drive', 'vcsec.closures',
    //              'vcsec.lockState'} etc. The dotted form lets
    // closure-domain commands write into the VCSEC slice without
    // collapsing it to a single field.

    applyOptimistic(sliceName, fields) {
        if (!fields) return;
        switch (sliceName) {
            case 'charge':
                Object.assign(this.charge, fields);
                for (const k of Object.keys(fields)) this.charge.dirty[k] = true;
                _touchSlice(this.charge);
                break;
            case 'climate':
                Object.assign(this.climate, fields);
                for (const k of Object.keys(fields)) this.climate.dirty[k] = true;
                _touchSlice(this.climate);
                break;
            case 'drive':
                Object.assign(this.drive, fields);
                for (const k of Object.keys(fields)) this.drive.dirty[k] = true;
                _touchSlice(this.drive);
                break;
            case 'sentry':
                Object.assign(this.sentry, fields);
                for (const k of Object.keys(fields)) this.sentry.dirty[k] = true;
                _touchSlice(this.sentry);
                break;
            case 'windows':
                Object.assign(this.windows, fields);
                for (const k of Object.keys(fields)) this.windows.dirty[k] = true;
                _touchSlice(this.windows);
                break;
            case 'vcsec.lockState':
                this.vcsec.lockState = fields.value;
                _touchSlice(this.vcsec);
                break;
            case 'vcsec.closures': {
                Object.assign(this.vcsec.closures, fields);
                // Stamp the intent so the next VCSEC sync respects it
                // for CLOSURE_INTENT_GRACE_MS — avoids the stale-
                // Hall-sensor flip-flop.
                const until = Date.now() + CLOSURE_INTENT_GRACE_MS;
                for (const k of Object.keys(fields)) {
                    this.vcsec.closuresIntent[k] = until;
                }
                _touchSlice(this.vcsec);
                break;
            }
            default:
                console.warn('[airgap] applyOptimistic: unknown slice', sliceName);
                return;
        }
        this.save();
    }

    // _applySliceFromSync writes confirmed values from a sync into a
    // slice and clears matching dirty entries. Used by both
    // applyCarServerResponse and the (future) per-command response
    // hooks that piggyback state in their replies.

    _applySliceFromSync(slice, fields) {
        for (const [k, v] of Object.entries(fields)) {
            if (v !== undefined) {
                slice[k] = v;
                delete slice.dirty[k];
            }
        }
        _touchSlice(slice);
    }
}

// ── Slice serialization helpers ──

function _serializeSlice(slice) {
    const out = { ...slice };
    // Serialise dirty as an array (smaller JSON; deserialise back to
    // a plain object). Accept both shapes on load for tolerance.
    out.dirty = Object.keys(slice.dirty || {});
    delete out.isUpdated; // pulse flag is transient, not persisted
    return out;
}

function _deserializeSlice(obj) {
    const out = { ...obj };
    const d = {};
    const src = obj.dirty;
    if (Array.isArray(src))      for (const k of src) d[k] = true;
    else if (src && typeof src === 'object') Object.assign(d, src);
    out.dirty = d;
    out.isUpdated = false;
    return out;
}

// _touchSlice — bump the timestamp AND raise the isUpdated pulse for
// ~1.5s so the UI can highlight the freshly-changed slice. Pulse
// timers are kept per slice via a private symbol so multiple slices
// can pulse independently.

const _pulseTimer = Symbol('airgap.pulseTimer');
const PULSE_MS = 1500;

function _touchSlice(slice) {
    slice.lastUpdatedAt = Date.now();
    slice.isUpdated = true;
    if (slice[_pulseTimer]) clearTimeout(slice[_pulseTimer]);
    slice[_pulseTimer] = setTimeout(() => { slice.isUpdated = false; }, PULSE_MS);
}

// ── Enum name lookup ──
//
// protobuf.js returns enum values as numbers. We map them back to
// names so the UI can compare against 'AWAKE' / 'LOCKED' etc rather
// than magic ints. Names come from the .proto definitions.

const _LOCK_NAMES = ['UNLOCKED','LOCKED','INTERNAL_LOCKED','SELECTIVE_UNLOCKED'];
const _SLEEP_NAMES = ['UNKNOWN','AWAKE','ASLEEP'];
const _PRESENCE_NAMES = ['UNKNOWN','NOT_PRESENT','PRESENT'];
// Index → name, matching ClosureState_E in vcsec.proto:
//   0 CLOSED, 1 OPEN, 2 AJAR, 3 UNKNOWN, 4 FAILED_UNLATCH,
//   5 OPENING, 6 CLOSING
// (Earlier table had a wrong order that made CLOSED render as
// UNKNOWN and AJAR render as OPEN — frunk reading AJAR from the
// hall sensor would forever show "Open" in the UI.)
const _CLOSURE_NAMES = ['CLOSED','OPEN','AJAR','UNKNOWN','FAILED_UNLATCH','OPENING','CLOSING'];

function _enumName(val, table) {
    if (val == null) return null;
    if (typeof val === 'string') return val;
    return table[val] || `unknown(${val})`;
}

// _oneofName extracts the active case name from a protobuf oneof.
// protobuf.js decodes `oneof type { Void Charging = 5; ... }` into an
// object with exactly one key (the active case) whose value is the
// sub-message (often {} for Void cases). Accept strings, null, and
// already-extracted values pass through unchanged.
function _oneofName(val) {
    if (val == null) return null;
    if (typeof val === 'string') return val;
    if (typeof val === 'object') {
        const keys = Object.keys(val);
        if (keys.length === 1) return keys[0];
        if (keys.length === 0) return null;
        // Multiple keys: shouldn't happen for a oneof but be resilient.
        return keys[0];
    }
    return String(val);
}

// ── Per-VIN serialization queue ──
//
// BLE is single-channel and the session counter is monotonic — two
// commands in flight at once will corrupt each other. The queue
// guarantees a single in-flight operation per VIN. enqueue() returns
// a promise that resolves to fn()'s return value; the chain survives
// errors so a failed command doesn't poison the queue.

class SessionQueue {
    constructor() { this.tail = Promise.resolve(); }
    enqueue(fn) {
        const run = this.tail.then(() => fn(), () => fn());
        this.tail = run.catch(() => {});
        return run;
    }
}

// ── Sync primitives ──
//
// Each sync mode is a thin orchestration around action builders + the
// existing withCachedSession + sendDirectCommandWithApi pipeline.
// They DON'T enqueue themselves — the caller (or the piggyback
// scheduler) does that. This keeps the queue policy single-source.
//
// ctx: { api, vin, deviceKeyPair, state: VehicleState }

async function vcsecSync(ctx) {
    const { api, vin, deviceKeyPair, state } = ctx;
    const action = await airgap.vcsecGetStatusAction();
    const proto  = await airgap.loadProto();

    const resp = await airgap.withCachedSession(
        { api, vin, deviceKeyPair, domain: action.domain },
        async (session) => airgap.sendDirectCommandWithApi({
            api, session, payloadBytes: action.bytes, flags: action.flags || 0,
        }),
    );

    if (!resp.decryptedPayload) {
        throw new Error('vcsecSync: car returned no decrypted payload');
    }

    let fromVcsec;
    try {
        fromVcsec = airgap.decodeMessage(proto.FromVCSECMessage, resp.decryptedPayload);
    } catch (e) {
        throw new Error(`vcsecSync: decode FromVCSECMessage failed — ${e.message}`);
    }
    if (!fromVcsec.vehicleStatus) {
        throw new Error('vcsecSync: response carried no vehicleStatus');
    }

    state.applyVcsecStatus(fromVcsec.vehicleStatus);
    return { isAwake: state.isAwake };
}

async function awakeSync(ctx) {
    const { api, vin, deviceKeyPair, state } = ctx;
    const proto = await airgap.loadProto();

    // Three SEPARATE single-field reads on the SAME cached session.
    //
    // The earlier "combined GetVehicleData with all 5 sub-fields set
    // in one request" path was never proven at the car — the user
    // reported that pressing Refresh never populated battery/climate.
    // Single-field reads are the path that Thread C-2 shipped and
    // that has worked end-to-end. Three round-trips on a warm session
    // add maybe 600ms vs the combined, but the code path is known
    // good.
    //
    // Per-slice success/failure is accumulated so we can surface an
    // honest result instead of silently returning ok=false.
    const results = await airgap.withCachedSession(
        { api, vin, deviceKeyPair, domain: airgap.DOMAIN_INFOTAINMENT },
        async (session) => {
            const out = { charge: null, climate: null, drive: null, location: null };
            const reads = [
                { name: 'charge',   builder: airgap.getChargeStateAction   },
                { name: 'climate',  builder: airgap.getClimateStateAction  },
                { name: 'drive',    builder: airgap.getDriveStateAction    },
                { name: 'location', builder: airgap.getLocationStateAction },
            ];
            for (const { name, builder } of reads) {
                try {
                    const action = await builder();
                    const r = await airgap.sendDirectCommandWithApi({
                        api, session, payloadBytes: action.bytes, flags: action.flags || 0,
                    });
                    if (!r.decryptedPayload) {
                        out[name] = `no-payload (status=${JSON.stringify(r.routable?.signedMessageStatus || {})})`;
                        continue;
                    }
                    const carResp = airgap.decodeMessage(proto.Response, r.decryptedPayload);
                    state.applyCarServerResponse(carResp);
                    out[name] = 'ok';
                } catch (e) {
                    // Transport-level errors (BLE link dead, Pi
                    // reaped the session, etc.) need to escape THIS
                    // body so the outer withCachedSession can do its
                    // eviction + cold-start dance. Swallowing them
                    // per-slice is what made global Refresh stay
                    // broken when per-card refresh recovered fine:
                    // the dead session stayed cached because the
                    // body returned without ever throwing, and every
                    // subsequent slice (and every subsequent click)
                    // hit the same dead Pi sessionId.
                    if (airgap.isTransportDeadError(e)) throw e;
                    out[name] = 'error: ' + (e.message || e);
                }
            }
            return out;
        },
    );

    // Bubble per-slice errors to the console — without this a Refresh
    // that quietly fails on every slice still toasts "✓ state synced".
    for (const [name, status] of Object.entries(results)) {
        if (status !== 'ok') console.warn(`[airgap] awakeSync: ${name} → ${status}`);
    }

    const okCount = Object.values(results).filter(s => s === 'ok').length;
    return { ok: okCount > 0, results };
}

// ── Piggyback scheduler ──
//
// After a successful command we want to fire a follow-up sync, but
// not three of them if the user fires three commands in a row. The
// scheduler debounces (~500ms) and coalesces kinds: 'awake' supersedes
// 'vcsec' (an awake sync gives us everything the cheap sync would,
// plus more). One slot per VIN.

const PIGGYBACK_DELAY_MS = 500;
const _piggyback = new Map(); // vin → { kind, timer, ctxRef }

function schedulePiggyback(vin, kind, ctxBuilder) {
    if (kind !== 'vcsec' && kind !== 'awake') {
        throw new Error(`schedulePiggyback: bad kind ${kind}`);
    }
    const existing = _piggyback.get(vin);
    if (existing) {
        // 'awake' wins over 'vcsec' — strictly stronger sync.
        if (existing.kind === 'awake' && kind === 'vcsec') {
            // Already scheduled stronger sync; nothing to do.
            return;
        }
        clearTimeout(existing.timer);
    }
    const entry = { kind, timer: null, ctxBuilder };
    entry.timer = setTimeout(async () => {
        _piggyback.delete(vin);
        const ctx = ctxBuilder();
        if (!ctx) return; // caller invalidated the ctx (e.g. forgot)
        const queue = _queueFor(vin);
        try {
            await queue.enqueue(async () => {
                // Dispatch through the namespace so tests can stub
                // airgap.vcsecSync / airgap.awakeSync. Local function
                // bindings would bypass any reassignment.
                //
                // Run ONLY the requested kind — no automatic
                // "free upgrade" from vcsec to awake. That upgrade
                // was firing a full GetVehicleData (5 sub-reads,
                // multi-second on the car) every time we noticed
                // AWAKE, which then queued up behind user button
                // presses. If the caller wants an awake sync, they
                // schedule one explicitly.
                if (entry.kind === 'awake') {
                    await airgap.awakeSync(ctx);
                } else {
                    await airgap.vcsecSync(ctx);
                }
            });
        } catch (e) {
            console.warn('[airgap] piggyback', entry.kind, 'failed:', e.message || e);
        }
    }, PIGGYBACK_DELAY_MS);
    _piggyback.set(vin, entry);
}

function cancelPiggyback(vin) {
    const e = _piggyback.get(vin);
    if (!e) return;
    clearTimeout(e.timer);
    _piggyback.delete(vin);
}

// ── Per-VIN queue registry ──
//
// Lazy: one queue per VIN, created on first use. Cleared on
// stopBackgroundReader / forget. The same queue serializes
// commands AND piggybacks AND background reads — guaranteeing the
// "read-after-command-write" race we worried about cannot fire.

const _queues = new Map(); // vin → SessionQueue

function _queueFor(vin) {
    let q = _queues.get(vin);
    if (!q) { q = new SessionQueue(); _queues.set(vin, q); }
    return q;
}

function queueFor(vin) { return _queueFor(vin); }

// resetQueues drops every per-VIN queue and re-creates empty ones on
// demand. Use this as an escape hatch when a queue's tail promise is
// stuck on a never-resolving op (in theory impossible now that
// fetches have a 12s AbortController timeout, but a kill switch is
// always nice).
function resetQueues() {
    _queues.clear();
}

// ── Background reader ──
//
// While the tab is visible, poll VCSEC every BG_INTERVAL_MS. The
// session cache (25s idle TTL) keeps the BLE link warm so each poll
// is ~100ms once the first session is up. When the tab is hidden,
// stop polling. Cheap, no wakes, and gives us live VCSEC fields
// (closures-with-lag-caveat, locks, sleep flag).
//
// One reader per VIN; calling start twice is idempotent.
//
// Interval is 20s (less than SESSION_IDLE_TTL_MS = 25s in session.js)
// so each tick refreshes the cached session's TTL before it can
// evict. THIS IS WHAT MAKES SUBSEQUENT USER CLICKS FAST — without it,
// a 25s idle pause causes the next click to pay a full BLE handshake
// (~10-20s). With it, the VCSEC session stays warm continuously.
//
// Critically: the tick does ONLY a cheap VCSEC GET_STATUS (~200-500ms
// on a warm session). It does NOT auto-upgrade to awake sync. The
// auto-upgrade was the source of the earlier latency complaint —
// every 20s it queued a multi-second Infotainment read behind user
// clicks. With it gone, ticks finish in well under a second and
// barely touch the queue.

const BG_INTERVAL_MS = 20_000;
const _readers = new Map(); // vin → { ctxBuilder, timer, visListener }

function startBackgroundReader(vin, ctxBuilder) {
    if (_readers.has(vin)) return; // idempotent

    const entry = { ctxBuilder, timer: null, visListener: null };

    const tick = () => {
        if (document.hidden) return;
        const ctx = ctxBuilder();
        if (!ctx) return;
        _queueFor(vin).enqueue(async () => {
            try {
                // Cheap VCSEC GET_STATUS only. No awake-upgrade —
                // that was what made the queue feel slow before.
                await airgap.vcsecSync(ctx);
            } catch (e) {
                console.warn('[airgap] background vcsec sync failed:', e.message || e);
            }
        });
    };

    const startTimer = () => {
        if (entry.timer) return;
        entry.timer = setInterval(tick, BG_INTERVAL_MS);
    };
    const stopTimer = () => {
        if (!entry.timer) return;
        clearInterval(entry.timer);
        entry.timer = null;
    };

    entry.visListener = () => {
        if (document.hidden) stopTimer();
        else startTimer();
    };
    document.addEventListener('visibilitychange', entry.visListener);

    if (!document.hidden) startTimer();
    _readers.set(vin, entry);
}

function stopBackgroundReader(vin) {
    const entry = _readers.get(vin);
    if (!entry) return;
    if (entry.timer) clearInterval(entry.timer);
    if (entry.visListener) document.removeEventListener('visibilitychange', entry.visListener);
    _readers.delete(vin);
}

// ── Cold-start sync ──
//
// On app foreground (after enrol or page reload with valid cfg), fire
// one VCSEC GET_STATUS to populate the cache before the user even
// looks. Cheap, no wake; matches Tesla app's behaviour of issuing a
// status request on connect. Does NOT fire awake sync automatically —
// the user has to press Refresh (or send a command) for that.

async function coldStartSync(vin, ctxBuilder) {
    const ctx = ctxBuilder();
    if (!ctx) return;
    try {
        await _queueFor(vin).enqueue(() => airgap.vcsecSync(ctx));
    } catch (e) {
        console.warn('[airgap] cold-start vcsec sync failed:', e.message || e);
    }
}

// ── Reset (used on forget) ──

function resetVehicle(vin) {
    cancelPiggyback(vin);
    stopBackgroundReader(vin);
    _queues.delete(vin);
    try { localStorage.removeItem(_storageKey(vin)); } catch {}
}

Object.assign(window.airgap, {
    VehicleState,
    SessionQueue,
    vcsecSync, awakeSync,
    schedulePiggyback, cancelPiggyback,
    queueFor,
    startBackgroundReader, stopBackgroundReader,
    coldStartSync,
    resetVehicle,
    resetQueues,
});
