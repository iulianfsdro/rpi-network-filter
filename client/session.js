// session.js — Tesla BLE session driven entirely by the client.
//
// V4.4 Phase 3c-4. The endgame for the rearchitecture: a command goes
// from client to car without the Pi ever seeing plaintext or a session
// key. The Pi's role is reduced to "forward these opaque bytes over
// BLE and bring the response back."
//
// The flow for one command:
//
//   1. POST /api/ble/sessions { vin }                    → open BLE link
//   2. RoutableMessage{ to=DOMAIN, from=<routing>,
//                       sessionInfoRequest={ pub=our_pub,
//                                            challenge=random } }
//      → /sessions/{id}/exchange → car returns SessionInfo + HMAC tag
//   3. car_eph_pub = SessionInfo.publicKey
//      session_key = SHA1( ECDH(our_priv, car_eph_pub) )[:16]
//      counter     = SessionInfo.counter         (per-session, monotonic)
//      epoch       = SessionInfo.epoch           (16 random bytes per
//                                                 car-side session)
//      clock_base  = SessionInfo.clockTime       (car's wall clock
//                                                 in seconds; we anchor
//                                                 local time against it)
//   4. Build inner Action protobuf for the command.
//      AAD = SHA-256( metadata block with
//                     SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
//                     DOMAIN, PERSONALIZATION=VIN, EPOCH,
//                     EXPIRES_AT=clock_base+elapsed+lifetime,
//                     COUNTER=++counter )
//      nonce = 12 random bytes
//      ciphertext, tag = AES-GCM-Encrypt(session_key, action_bytes,
//                                        AAD=metadata_digest,
//                                        nonce)
//      wire = RoutableMessage{
//          to=DOMAIN, from=<routing>,
//          protobufMessageAsBytes = ciphertext,
//          signatureData = AES_GCM_Personalized_data{
//              epoch, nonce, counter, expires_at, tag } }
//      → /sessions/{id}/exchange
//   5. Response is a RoutableMessage with signedMessageStatus
//      (unencrypted result code) or an encrypted payload. For honk
//      and the other "fire and forget" commands a successful status
//      is the proof the car accepted it.
//   6. DELETE /api/ble/sessions/{id} when done.
//
// Today's known TODOs (next pass):
//   • SessionInfo HMAC verification. With it, a compromised Pi
//     cannot MITM the session — without it, the Pi can substitute
//     its own pubkey for the car's and derive a key it knows.
//   • Decryption of encrypted response payloads (for state reads
//     and commands that return content). For status-only commands
//     like honk the MessageStatus is unencrypted and enough.
//   • Per-domain session caching across multiple commands. Today
//     each call opens and closes a fresh BLE session. Cheap and
//     safe but slow if you want to fire several commands in a row.

window.airgap = window.airgap || {};

// Tesla protocol constants —
//   COMMAND_LIFETIME_SEC: how far in the future the AAD's EXPIRES_AT
//     lands. The car rejects commands stamped past their lifetime,
//     making replay windows tight even if the bearer leaks.
//   ROUTING_ADDRESS_BYTES: the SDK uses 16 random bytes per session
//     so the car's responses route back to this client and not some
//     other concurrent caller. BLE is point-to-point per session so
//     this is mostly symbolic, but we follow the SDK's shape.
const COMMAND_LIFETIME_SEC   = 5;
const ROUTING_ADDRESS_BYTES  = 16;
const SESSION_INFO_TIMEOUT_MS = 4000;
const COMMAND_TIMEOUT_MS      = 6000;

// openDirectSession does the full handshake against `domain` over a
// fresh BLE session. Returns a session handle holding the AES-GCM
// CryptoKey, the counter, the epoch, and the clock baseline. The
// caller must call session.close() when done — the Pi's BLE adapter
// is single-tenant so leaving sessions open blocks every other BLE
// path on the Pi.
async function openDirectSession({ api, vin, deviceKeyPair, domain }) {
    if (!vin) throw new Error('openDirectSession: vin required');
    if (!deviceKeyPair?.publicKey || !deviceKeyPair?.privateKey) {
        throw new Error('openDirectSession: deviceKeyPair must hold both halves');
    }

    const proto = await airgap.loadProto();
    const myPubRaw = await airgap.exportPubkeyRaw(deviceKeyPair.publicKey);

    // 1. Open BLE link via the Pi byte forwarder.
    const open = await api.request('POST', '/sessions', { vin });
    const sessionId = open.session_id;
    const localBaselineMs = Date.now();

    try {
        // 2. Build a SessionInfoRequest wrapped in a RoutableMessage.
        //
        // The HMAC challenge value the car uses is the RoutableMessage's
        // `uuid` field, NOT a separate sessionInfoRequest.challenge
        // sub-field (which the SDK doesn't even set). The car copies our
        // uuid into the response's request_uuid AND uses that same
        // value as the HMAC challenge when signing the SessionInfo
        // reply. Same bytes have to be on both sides for verification
        // to pass.
        const routingAddress  = crypto.getRandomValues(new Uint8Array(ROUTING_ADDRESS_BYTES));
        const challenge       = crypto.getRandomValues(new Uint8Array(16));

        const reqBytes = airgap.encodeMessage(proto.RoutableMessage, {
            toDestination:   { domain },
            fromDestination: { routingAddress },
            sessionInfoRequest: {
                publicKey: myPubRaw,
            },
            uuid: challenge,   // ← doubles as the HMAC challenge
        });

        const reqResp = await api.request('POST', `/sessions/${sessionId}/exchange`, {
            payload_b64: airgap.bytesToBase64(reqBytes),
            timeout_ms:  SESSION_INFO_TIMEOUT_MS,
        });
        const respBytes = airgap.base64ToBytes(reqResp.response_b64);
        const respMsg   = airgap.decodeMessage(proto.RoutableMessage, respBytes);

        // 3. Extract SessionInfo from the response. Domain-aware
        // routing means the car may also surface session_info via
        // either the payload oneof or via an unencrypted status —
        // we expect the payload form for a clean handshake.
        if (!respMsg.sessionInfo || respMsg.sessionInfo.length === 0) {
            const keys = Object.keys(respMsg).join(', ');
            const status = respMsg.signedMessageStatus
                ? `signed_message_status=${JSON.stringify(respMsg.signedMessageStatus)}`
                : '';
            throw new Error(`expected session_info in response (keys: ${keys}) ${status}`);
        }
        const sessionInfoBytes = respMsg.sessionInfo;
        const sessionInfo = airgap.decodeMessage(proto.SessionInfo, sessionInfoBytes);

        if (!sessionInfo.publicKey || sessionInfo.publicKey.length !== 65) {
            throw new Error(`car returned malformed pubkey (len ${sessionInfo.publicKey?.length})`);
        }
        if (!sessionInfo.epoch || sessionInfo.epoch.length !== 16) {
            throw new Error(`car returned malformed epoch (len ${sessionInfo.epoch?.length})`);
        }

        // 4. Derive the AES-GCM session key. The intermediate raw
        // bytes are kept for HMAC subkey derivation (used by the
        // not-yet-wired session-info HMAC verification path).
        const carEphPub = await airgap.importPeerPubkey(sessionInfo.publicKey);
        const keyBytes  = await airgap.deriveSessionKeyMaterial(deviceKeyPair.privateKey, carEphPub);
        const sessionKey = await crypto.subtle.importKey(
            'raw', keyBytes,
            { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
        );

        // Verify the SessionInfo HMAC tag. The car HMAC'd the
        // SessionInfo bytes (which carry its ephemeral pubkey)
        // using subkey("session info"), derived from the SAME
        // shared secret only the car and we can derive. So tag
        // match proves three things at once: SessionInfo came from
        // the car (not a MITM byte-forwarder), our pubkey is in
        // the car's keychain, and the derived session key on both
        // sides matches.
        //
        // Without this check, a compromised Pi could substitute its
        // own ephemeral pubkey + a matching HMAC it computed under
        // a key it knows, and decrypt every subsequent command.
        const receivedTag =
            respMsg.signatureData?.sessionInfoTag?.tag ||
            respMsg.signatureData?.session_info_tag?.tag;
        if (!receivedTag || receivedTag.length === 0) {
            throw new Error('SessionInfo response missing signatureData.sessionInfoTag.tag — cannot verify');
        }
        const subkey = await airgap.hmacSubkey(keyBytes, 'session info');
        const verifyMeta = new airgap.MetadataBlockBuilder();
        verifyMeta.add(airgap.TAG.SIGNATURE_TYPE,  new Uint8Array([airgap.SIGNATURE_TYPE.HMAC]));
        verifyMeta.add(airgap.TAG.PERSONALIZATION, new TextEncoder().encode(vin));
        verifyMeta.add(airgap.TAG.CHALLENGE,       challenge);
        const expectedTag = await verifyMeta.hmac(subkey, sessionInfoBytes);

        if (expectedTag.length !== receivedTag.length) {
            throw new Error(`SessionInfo HMAC length mismatch: expected ${expectedTag.length}, received ${receivedTag.length}`);
        }
        // Branch-free comparison — both sides are 32 bytes of HMAC
        // output so timing leaks are bounded, but no reason not to
        // do it the right way.
        let diff = 0;
        for (let i = 0; i < expectedTag.length; i++) {
            diff |= expectedTag[i] ^ receivedTag[i];
        }
        if (diff !== 0) {
            console.error('[airgap] HMAC mismatch — expected:', airgap.bytesToHex(expectedTag));
            console.error('[airgap] HMAC mismatch — received:', airgap.bytesToHex(receivedTag));
            throw new Error('SessionInfo HMAC verification FAILED — possible MITM, refusing to continue');
        }
        console.log('[airgap] SessionInfo HMAC ✓ (car authenticated)');

        return {
            sessionId,
            domain,
            vin,
            routingAddress,
            sessionKey,
            keyBytes,
            // Our public key — the car uses this as the keychain
            // lookup ID inside signer_identity. Without it the car
            // can't find our key and returns BAD_PARAMETER even
            // though the signature itself is valid.
            myPubRaw,
            epoch:    sessionInfo.epoch,
            counter:  sessionInfo.counter || 0,
            clockBase: sessionInfo.clockTime || 0,
            localBaselineMs,
            close: async () => {
                try { await api.request('DELETE', `/sessions/${sessionId}`); }
                catch (e) { console.warn('[airgap] close failed:', e.message || e); }
            },
        };
    } catch (e) {
        // Best-effort cleanup; never let a cleanup error mask the
        // root cause.
        try { await api.request('DELETE', `/sessions/${sessionId}`); } catch {}
        throw e;
    }
}

// sendDirectCommand encrypts and ships one Action through the byte
// forwarder. Returns the decoded response RoutableMessage so the
// caller can inspect signedMessageStatus.
async function sendDirectCommand(session, action) {
    const proto = await airgap.loadProto();
    const actionBytes = airgap.encodeMessage(proto.Action, action);

    // Counter is per-message monotonic from the SessionInfo seed.
    // 0xFFFFFFFF is the SDK's rollover guard; we mirror it.
    if (session.counter >= 0xFFFFFFFE) {
        throw new Error('session counter rolled over — close and re-open');
    }
    session.counter += 1;
    const counter = session.counter;

    // Wall-clock-anchored expiry: car checks against its own
    // monotonic clock derived from the same SessionInfo.clockTime.
    const elapsedSec = Math.floor((Date.now() - session.localBaselineMs) / 1000);
    const expiresAt  = (session.clockBase + elapsedSec + COMMAND_LIFETIME_SEC) >>> 0;

    // Build the AAD digest the SDK uses for AES-GCM.
    const aadDigest = await airgap.buildAesGcmMetadata({
        domain:       session.domain,
        verifierName: session.vin,
        epoch:        session.epoch,
        expiresAt,
        counter,
        flags:        0,
    });

    // Encrypt the inner Action against the session key.
    const env = await airgap.aesGcmEncrypt(session.sessionKey, actionBytes, aadDigest);

    // Wrap in a RoutableMessage. The signatureData oneof carries
    // the AES_GCM envelope fields so the car can rebuild the same
    // AAD and decrypt.
    const cmdRoutable = airgap.encodeMessage(proto.RoutableMessage, {
        toDestination:   { domain: session.domain },
        fromDestination: { routingAddress: session.routingAddress },
        protobufMessageAsBytes: env.ciphertext,
        signatureData: {
            AES_GCM_PersonalizedData: {
                epoch:     session.epoch,
                nonce:     env.nonce,
                counter,
                expiresAt,
                tag:       env.tag,
            },
        },
        uuid: crypto.getRandomValues(new Uint8Array(16)),
    });

    const resp = await window.api?.request
        ? null
        : null; // (placeholder: api reference is on session)
    // The api object lives on the calling closure — we pulled it from
    // session.close which captured `api`. For sendDirectCommand we
    // need it passed in directly; restructured below.
    throw new Error('internal: sendDirectCommand needs api — call sendDirectCommandWithApi');
}

// sendDirectCommandWithApi is the practical entry point — exposes
// the `api` parameter so the calling layer can inject the
// bearer-aware fetch wrapper from app.js. The cleaner refactor is
// to put `api` on the session handle; we'll do that in a follow-up.
async function sendDirectCommandWithApi({ api, session, action }) {
    const proto = await airgap.loadProto();
    const actionBytes = airgap.encodeMessage(proto.Action, action);

    if (session.counter >= 0xFFFFFFFE) {
        throw new Error('session counter rolled over — close and re-open');
    }
    session.counter += 1;
    const counter = session.counter;

    const elapsedSec = Math.floor((Date.now() - session.localBaselineMs) / 1000);
    const expiresAt  = (session.clockBase + elapsedSec + COMMAND_LIFETIME_SEC) >>> 0;

    const aadDigest = await airgap.buildAesGcmMetadata({
        domain:       session.domain,
        verifierName: session.vin,
        epoch:        session.epoch,
        expiresAt,
        counter,
        flags:        0,
    });

    const env = await airgap.aesGcmEncrypt(session.sessionKey, actionBytes, aadDigest);

    const cmdRoutable = airgap.encodeMessage(proto.RoutableMessage, {
        toDestination:   { domain: session.domain },
        fromDestination: { routingAddress: session.routingAddress },
        protobufMessageAsBytes: env.ciphertext,
        signatureData: {
            // signer_identity tells the car which key in its
            // keychain signed this command. Without it the car
            // can't look us up. SDK uses the raw SEC1 pubkey here.
            signerIdentity: {
                publicKey: session.myPubRaw,
            },
            AES_GCM_PersonalizedData: {
                epoch:     session.epoch,
                nonce:     env.nonce,
                counter,
                expiresAt,
                tag:       env.tag,
            },
        },
        uuid: crypto.getRandomValues(new Uint8Array(16)),
    });

    const r = await api.request('POST', `/sessions/${session.sessionId}/exchange`, {
        payload_b64: airgap.bytesToBase64(cmdRoutable),
        timeout_ms:  COMMAND_TIMEOUT_MS,
    });

    const respBytes = airgap.base64ToBytes(r.response_b64);
    const respMsg   = airgap.decodeMessage(proto.RoutableMessage, respBytes);
    return respMsg;
}

// ── Session cache ────────────────────────────────────────────────
//
// Thread D: the SessionInfo handshake costs ~2 s round-trip over BLE.
// Closing and reopening per command makes a UX flow of "lock, then
// flash, then honk" feel sluggish. Cache the open session per domain
// for a short idle window; reuse it; close it when the operator
// leaves or the TTL expires.
//
// We DON'T cache across page reloads — a fresh tab opens a new
// session. IndexedDB persistence would also need to survive the BLE
// link surviving (which it doesn't — the car closes idle BLE links).

const SESSION_IDLE_TTL_MS = 25_000; // safer than Tesla's ~30s BLE close
const _domainCache = new Map(); // domain → { session, expiresAt, timer }

// withCachedSession opens a session for `domain` or reuses a cached
// one. The body runs with the session; if it throws, the cache is
// invalidated (because we don't know if the session is still good).
// Idle TTL resets after every successful body.
async function withCachedSession({ api, vin, deviceKeyPair, domain }, body) {
    let entry = _domainCache.get(domain);
    if (entry && entry.expiresAt > Date.now()) {
        try {
            const result = await body(entry.session, /*cached*/true);
            _refreshTtl(entry, domain);
            return result;
        } catch (e) {
            // Session might be dead — drop the cache and let the
            // caller retry with a fresh one (or surface the error).
            _evict(domain);
            throw e;
        }
    }
    // No live cache. Open fresh.
    const session = await openDirectSession({ api, vin, deviceKeyPair, domain });
    entry = { session, expiresAt: 0, timer: null };
    _domainCache.set(domain, entry);
    _refreshTtl(entry, domain);
    try {
        return await body(session, /*cached*/false);
    } catch (e) {
        _evict(domain);
        throw e;
    }
}

function _refreshTtl(entry, domain) {
    if (entry.timer) clearTimeout(entry.timer);
    entry.expiresAt = Date.now() + SESSION_IDLE_TTL_MS;
    entry.timer = setTimeout(() => _evict(domain), SESSION_IDLE_TTL_MS);
}

function _evict(domain) {
    const entry = _domainCache.get(domain);
    if (!entry) return;
    if (entry.timer) clearTimeout(entry.timer);
    _domainCache.delete(domain);
    // Best-effort close. The session object holds its own close()
    // closure that captures its api/sessionId — fire and forget.
    entry.session.close().catch(() => {});
}

// closeAllCachedSessions drops every domain's cached session. Called
// on page unload + on explicit "forget this Pi".
function closeAllCachedSessions() {
    for (const domain of [..._domainCache.keys()]) {
        _evict(domain);
    }
}

// honkAction returns the Action protobuf for an Infotainment honk.
// Inner shape: Action{ VehicleAction{ VehicleControlHonkHornAction{} } }.
// VehicleControlHonkHornAction has no fields; the very fact of it
// being the oneof case carries the command.
function honkAction() {
    return {
        vehicleAction: {
            vehicleControlHonkHornAction: {},
        },
    };
}

// flashLightsAction — another zero-field Infotainment action. Quick
// alternative to honk for testing without making noise.
function flashLightsAction() {
    return {
        vehicleAction: {
            vehicleControlFlashLightsAction: {},
        },
    };
}

Object.assign(window.airgap, {
    openDirectSession,
    sendDirectCommandWithApi,
    withCachedSession,
    closeAllCachedSessions,
    honkAction,
    flashLightsAction,
    DOMAIN_INFOTAINMENT:     3,
    DOMAIN_VEHICLE_SECURITY: 2,
});
