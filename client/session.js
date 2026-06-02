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

// Retry policy constants. Match Tesla Android's `nb0/C24292a.java`:
// `m99481a(TRANSPORT_BLUETOOTH) = 10` attempts, `m99482b(BLE) = 100`
// ms delay for transients. Their semantic faults aren't retried at
// all, ours match.
const MAX_BLE_ATTEMPTS  = 10;
const TRANSIENT_DELAY_MS = 100;

// evaluateFault classifies a car-side fault into a retry policy.
// Mirrors Tesla Android's `nb0/C24292a.java` table per Codex's
// follow-up findings:
//
//   sessionStale: car's view of session is out of sync. Send a
//     fresh SessionInfoRequest on the same BLE link to refresh
//     keying material, then retry. ~1 round-trip recovery,
//     invisible to the user.
//   transient:    car is busy or had a transient internal error.
//     Retry directly with a short delay (100ms over BLE per Tesla's
//     constant) to give the car a moment.
//   semantic:     command-specific failure that no amount of
//     retrying will fix (bad parameter, insufficient privileges,
//     requires encryption that we forgot to ask for, etc.).
//     Surface to user immediately.
function evaluateFault(fault) {
    // Session-stale family. Per Codex's evaluator-table answer:
    // INVALID_SIGNATURE, INVALID_TOKEN_OR_COUNTER, INCORRECT_EPOCH,
    // INACTIVE_KEY all flow through Tesla's validation handler and
    // trigger session-info refresh + retry. TIME_EXPIRED is clock
    // skew; recoverable by refresh because the refresh restamps
    // localBaselineMs.
    if (fault === 4 || fault === 5 || fault === 6 || fault === 15 || fault === 17) {
        return { category: 'session-stale', retryable: true, delayMs: 0 };
    }
    // Transient. BUSY=1 and TIMEOUT=2 are explicit "try again";
    // INTERNAL=11 is opaque but Tesla retries it too with no
    // session action.
    if (fault === 1 || fault === 2 || fault === 11) {
        return { category: 'transient', retryable: true, delayMs: TRANSIENT_DELAY_MS };
    }
    // Semantic — everything else. UNKNOWN_KEY_ID,
    // INSUFFICIENT_PRIVILEGES, BAD_PARAMETER, INVALID_DOMAINS,
    // INVALID_COMMAND, DECODING, WRONG_PERSONALIZATION,
    // KEYCHAIN_IS_FULL, IV_INCORRECT_LENGTH, NOT_PROVISIONED,
    // COULD_NOT_HASH_METADATA, and REQUIRES_RESPONSE_ENCRYPTION.
    return { category: 'semantic', retryable: false, delayMs: 0 };
}

// openDirectSession does the full handshake against `domain` over a
// fresh BLE session. Returns a session handle holding the AES-GCM
// CryptoKey, the counter, the epoch, and the clock baseline. The
// caller must call session.close() when done — the Pi's BLE adapter
// is single-tenant so leaving sessions open blocks every other BLE
// path on the Pi.
// Pi-side BLE sessionId is shared across both domains for a given
// VIN. Refcount = number of in-memory cached domain sessions
// referencing that sessionId. The Pi-side DELETE only fires when
// the LAST reference releases.
//
// Why we can do this now: the Pi-side uuid demux (see
// internal/services/tesla_session.go Exchange) means a shared BLE
// link is no longer subject to cross-domain frame interleaving —
// each domain's responses are routed back by request_uuid match.
// The earlier broken attempt at sharing pre-dated that demux; it
// failed because a VCSEC unsolicited broadcast could crowd out the
// Infotainment SessionInfo reply on a shared link. With Pi demux in
// place, that broadcast is silently skipped on the Pi and the
// matching frame is delivered.
//
// What this buys us: no more sequential close+reopen on every VCSEC
// ↔ Infotainment domain switch (was ~3-8s per switch), no more 45s
// POST /sessions blocking on the Pi's per-VIN BLE mutex, both
// domain sessions ride the same warm BLE link.
const _piSessionRefcounts = new Map();

function _piSessionAcquire(sessionId) {
    const rc = (_piSessionRefcounts.get(sessionId) || 0) + 1;
    _piSessionRefcounts.set(sessionId, rc);
    return rc;
}

async function _piSessionRelease(api, sessionId) {
    const rc = (_piSessionRefcounts.get(sessionId) || 1) - 1;
    if (rc > 0) {
        _piSessionRefcounts.set(sessionId, rc);
        return false; // another domain still holds this Pi session
    }
    _piSessionRefcounts.delete(sessionId);
    try { await api.request('DELETE', `/sessions/${sessionId}`); }
    catch (e) { console.warn('[airgap] Pi DELETE session failed:', e.message || e); }
    return true;
}

// _findOrOpenPiSession returns the Pi-side sessionId to use for the
// given VIN. Checks in this order:
//
//   1. The in-memory _domainCache — if ANY domain already has an
//      open session for this VIN, reuse its sessionId.
//   2. IDB-persisted session metadata for either domain on this VIN
//      (page reload survival).
//   3. POST /sessions to open a fresh Pi-side BLE link.
async function _findOrOpenPiSession({ api, vin }) {
    for (const entry of _domainCache.values()) {
        if (entry.session?.vin === vin && entry.session?.sessionId) {
            console.log('[airgap] reusing in-memory Pi session',
                entry.session.sessionId.slice(0, 8) + '… for vin', vin.slice(-6));
            return entry.session.sessionId;
        }
    }
    if (airgap.loadSessionMetadata) {
        for (const d of [DOMAIN_VEHICLE_SECURITY, DOMAIN_INFOTAINMENT]) {
            try {
                const meta = await airgap.loadSessionMetadata(vin, d);
                if (meta?.sessionId) {
                    console.log('[airgap] reusing IDB-persisted Pi session',
                        meta.sessionId.slice(0, 8) + '… (from domain ' + d + ')');
                    return meta.sessionId;
                }
            } catch (e) {
                console.warn('[airgap] IDB lookup failed:', e.message || e);
            }
        }
    }
    console.log('[airgap] opening fresh Pi-side BLE session for vin', vin.slice(-6));
    const open = await api.request('POST', '/sessions', { vin });
    return open.session_id;
}

async function _bindPiSession({ api, vin }) {
    const sessionId = await _findOrOpenPiSession({ api, vin });
    _piSessionAcquire(sessionId);
    return sessionId;
}

async function openDirectSession({ api, vin, deviceKeyPair, domain }) {
    if (!vin) throw new Error('openDirectSession: vin required');
    if (!deviceKeyPair?.publicKey || !deviceKeyPair?.privateKey) {
        throw new Error('openDirectSession: deviceKeyPair must hold both halves');
    }

    const proto = await airgap.loadProto();
    const myPubRaw = await airgap.exportPubkeyRaw(deviceKeyPair.publicKey);

    // 1. Get or create the Pi-side BLE session for this VIN. Both
    // domains share the same Pi sessionId — see _piSessionRefcounts
    // above for why this is safe now that the Pi demuxes by
    // request_uuid. _bindPiSession bumps the refcount; close() and
    // the error path below call _piSessionRelease which only tears
    // down the Pi-side session when the last domain releases.
    const sessionId = await _bindPiSession({ api, vin });
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

        // The BLE link is shared across domains, so the car may push
        // an unsolicited VCSEC notification (e.g. WhitelistInfo,
        // VehicleStatus) into the receive channel right around when
        // we send our SessionInfoRequest. The Pi drains BEFORE send
        // but only returns ONE frame after — so a VCSEC notification
        // that lands first is what we'd see, with the actual
        // SessionInfo still buffered. The next Exchange will drain
        // that buffered (now-stale-by-Pi-rules) SessionInfo and
        // re-send our request. The car responds again with a fresh
        // SessionInfo. Bounded retry until we win the race.
        const MAX_SESSION_INFO_ATTEMPTS = 4;
        let respMsg = null;
        let lastNonMatchSummary = null;
        for (let attempt = 1; attempt <= MAX_SESSION_INFO_ATTEMPTS; attempt++) {
            const reqResp = await api.request('POST', `/sessions/${sessionId}/exchange`, {
                payload_b64: airgap.bytesToBase64(reqBytes),
                timeout_ms:  SESSION_INFO_TIMEOUT_MS,
            });
            const respBytes = airgap.base64ToBytes(reqResp.response_b64);
            const candidate = airgap.decodeMessage(proto.RoutableMessage, respBytes);

            const candidateDomain = candidate.fromDestination?.domain;
            const hasSessionInfo = candidate.sessionInfo && candidate.sessionInfo.length > 0;
            if (hasSessionInfo && candidateDomain === domain) {
                respMsg = candidate;
                if (attempt > 1) {
                    console.log('[airgap] SessionInfo handshake succeeded on attempt', attempt, 'for domain', domain);
                }
                break;
            }

            // Wrong frame. Most common cause: VCSEC pushed an
            // unsolicited notification onto the shared BLE link
            // between our send and the car's SessionInfo reply.
            // Log enough detail to recognize the pattern in activity
            // logs, then retry — the Pi's pre-send drain will toss
            // the now-stale frame and the car re-replies.
            const keys = Object.keys(candidate).join(', ');
            const status = candidate.signedMessageStatus
                ? ` signedMessageStatus=${JSON.stringify(candidate.signedMessageStatus)}`
                : '';
            lastNonMatchSummary = `attempt=${attempt} fromDomain=${candidateDomain} keys=[${keys}]${status}`;
            console.warn('[airgap] SessionInfo handshake got non-matching frame:', lastNonMatchSummary);
        }
        if (!respMsg) {
            throw new Error(`expected session_info in response after ${MAX_SESSION_INFO_ATTEMPTS} attempts; last: ${lastNonMatchSummary}`);
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

        const session = {
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
            // Car's ephemeral pubkey — kept so we can re-derive the
            // AES session key from IDB-persisted metadata after a
            // page reload without needing a fresh handshake.
            vehiclePubRaw: sessionInfo.publicKey,
            epoch:    sessionInfo.epoch,
            counter:  sessionInfo.counter || 0,
            clockBase: sessionInfo.clockTime || 0,
            localBaselineMs,
            close: async () => {
                await _piSessionRelease(api, sessionId);
            },
        };

        // Persist metadata so a page reload can resume this session
        // without re-handshaking. Tesla Android does the same thing.
        try { await _persistSessionMetadata(session); }
        catch (e) { console.warn('[airgap] initial session persist failed:', e.message || e); }

        return session;
    } catch (e) {
        // Best-effort cleanup; refcounted release so we don't tear
        // down a Pi session another domain still holds.
        await _piSessionRelease(api, sessionId).catch(() => {});
        throw e;
    }
}

// isTransportDeadError detects errors from the Pi side that mean
// "the BLE link backing this session is gone — there is no point
// trying to refetch session info on it because the SessionInfoRequest
// would hit the same dead pipe." The error string comes from the
// Tesla SDK's BLE connector wrapped by the Pi's tesla_session.go:
//
//   "BLE send: send ATT request failed: io: read/write on closed pipe"
//   "BLE connection closed"
//   "BLE-SESSION not found"  (Pi reaped or restarted)
//
// Caller (typically _directDo) treats this as "evict + retry with
// a full handshake against a fresh Pi-side session." This is the
// correct recovery — a SessionInfoRequest refetch on a dead BLE
// link is just slower-to-fail.
function isTransportDeadError(e) {
    const msg = (e?.message || '').toLowerCase();
    return msg.includes('closed pipe')
        || msg.includes('ble send')
        || msg.includes('ble connection closed')
        || msg.includes('ble-session')           // Pi-side log prefix on session-gone errors
        || msg.includes('session not found')
        || msg.includes('no peripherals')
        || msg.includes('not connected');
}

// isStaleFrameError detects the "Pi returned stale response" error
// thrown when the response's request_uuid doesn't match the request
// we just sent. Cause: the Pi-side BLE channel buffered a frame from
// an earlier command (or an unsolicited car-side notification) that
// landed between Pi's pre-send drain and Send, and Pi returned it as
// the response to our new request.
//
// Distinct from transport-dead: the BLE link is FINE, the session is
// alive, we just need to retry the command. Pi's pre-send drain on
// the next Exchange will pop the stale frame; the car re-responds to
// our retried command (built with a fresh counter+uuid, so no replay
// risk). Caller (_directDo) treats this as a transient retry — the
// command itself is unchanged.
function isStaleFrameError(e) {
    const msg = (e?.message || '').toLowerCase();
    return msg.includes('stale response')
        || msg.includes('stale frame');
}

// _bytesEqual is a constant-time-ish equality check for Uint8Array
// values. Used by refetchSessionInfo to detect epoch changes.
function _bytesEqual(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

// refetchSessionInfo does an in-place session-info refresh on an
// already-open BLE session. The Tesla Android app does this exact
// thing in `xe0/C32376j.java` — when a command comes back with
// INVALID_SIGNATURE / INVALID_TOKEN_OR_COUNTER / INCORRECT_EPOCH /
// INACTIVE_KEY, the app sends a fresh SessionInfoRequest on the same
// BLE connection, gets back a new SessionInfo (new ephemeral pubkey
// + counter + epoch + clock), re-derives the AES key, and retries
// the failed command. No BLE link teardown, no full handshake.
//
// We mirror that: reuse session.sessionId / session.routingAddress /
// session.myPubRaw, swap in the new sessionKey / vehiclePubRaw /
// counter / epoch / clockBase IN PLACE on the same session object,
// persist the updated metadata. Caller is the reactive-invalidation
// path in app.js, which retries the command once after a successful
// refetch.
//
// Cost: one BLE round-trip (~200ms-1s warm) instead of the ~5-15s
// full handshake we'd pay if we evicted + reopened.
async function refetchSessionInfo({ api, deviceKeyPair, session }) {
    const proto    = await airgap.loadProto();
    const challenge = crypto.getRandomValues(new Uint8Array(16));

    const reqBytes = airgap.encodeMessage(proto.RoutableMessage, {
        toDestination:   { domain: session.domain },
        fromDestination: { routingAddress: session.routingAddress },
        sessionInfoRequest: { publicKey: session.myPubRaw },
        uuid: challenge,
    });

    // Same shared-BLE-link race as openDirectSession: a VCSEC
    // unsolicited notification can land on the receive channel
    // ahead of the actual SessionInfo reply. Retry until we get a
    // SessionInfo from the expected domain.
    const MAX_SESSION_INFO_ATTEMPTS = 4;
    let respMsg = null;
    let lastNonMatchSummary = null;
    for (let attempt = 1; attempt <= MAX_SESSION_INFO_ATTEMPTS; attempt++) {
        const reqResp = await api.request('POST', `/sessions/${session.sessionId}/exchange`, {
            payload_b64: airgap.bytesToBase64(reqBytes),
            timeout_ms:  SESSION_INFO_TIMEOUT_MS,
        });
        const respBytes = airgap.base64ToBytes(reqResp.response_b64);
        const candidate = airgap.decodeMessage(proto.RoutableMessage, respBytes);

        const candidateDomain = candidate.fromDestination?.domain;
        const hasSessionInfo = candidate.sessionInfo && candidate.sessionInfo.length > 0;
        if (hasSessionInfo && candidateDomain === session.domain) {
            respMsg = candidate;
            if (attempt > 1) {
                console.log('[airgap] refetchSessionInfo succeeded on attempt', attempt, 'for domain', session.domain);
            }
            break;
        }

        const keys = Object.keys(candidate).join(', ');
        const status = candidate.signedMessageStatus
            ? ` signedMessageStatus=${JSON.stringify(candidate.signedMessageStatus)}`
            : '';
        lastNonMatchSummary = `attempt=${attempt} fromDomain=${candidateDomain} keys=[${keys}]${status}`;
        console.warn('[airgap] refetchSessionInfo got non-matching frame:', lastNonMatchSummary);
    }
    if (!respMsg) {
        throw new Error(`refetchSessionInfo: expected session_info after ${MAX_SESSION_INFO_ATTEMPTS} attempts; last: ${lastNonMatchSummary}`);
    }
    const sessionInfoBytes = respMsg.sessionInfo;
    const sessionInfo = airgap.decodeMessage(proto.SessionInfo, sessionInfoBytes);

    if (!sessionInfo.publicKey || sessionInfo.publicKey.length !== 65) {
        throw new Error(`refetchSessionInfo: malformed car pubkey (len ${sessionInfo.publicKey?.length})`);
    }
    if (!sessionInfo.epoch || sessionInfo.epoch.length !== 16) {
        throw new Error(`refetchSessionInfo: malformed epoch (len ${sessionInfo.epoch?.length})`);
    }

    // Re-derive AES key from (our private key, NEW car ephemeral pubkey).
    const carEphPub = await airgap.importPeerPubkey(sessionInfo.publicKey);
    const keyBytes  = await airgap.deriveSessionKeyMaterial(deviceKeyPair.privateKey, carEphPub);
    const sessionKey = await crypto.subtle.importKey(
        'raw', keyBytes,
        { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );

    // Verify HMAC over the new SessionInfo (same logic as the
    // initial handshake — proves the response came from the car,
    // not a MITM byte-forwarder).
    const receivedTag =
        respMsg.signatureData?.sessionInfoTag?.tag ||
        respMsg.signatureData?.session_info_tag?.tag;
    if (!receivedTag || receivedTag.length === 0) {
        throw new Error('refetchSessionInfo: missing HMAC tag in response');
    }
    const subkey = await airgap.hmacSubkey(keyBytes, 'session info');
    const verifyMeta = new airgap.MetadataBlockBuilder();
    verifyMeta.add(airgap.TAG.SIGNATURE_TYPE,  new Uint8Array([airgap.SIGNATURE_TYPE.HMAC]));
    verifyMeta.add(airgap.TAG.PERSONALIZATION, new TextEncoder().encode(session.vin));
    verifyMeta.add(airgap.TAG.CHALLENGE,       challenge);
    const expectedTag = await verifyMeta.hmac(subkey, sessionInfoBytes);

    if (expectedTag.length !== receivedTag.length) {
        throw new Error(`refetchSessionInfo: HMAC length mismatch`);
    }
    let diff = 0;
    for (let i = 0; i < expectedTag.length; i++) {
        diff |= expectedTag[i] ^ receivedTag[i];
    }
    if (diff !== 0) {
        throw new Error('refetchSessionInfo: HMAC verification FAILED');
    }

    // Swap the new keying material IN PLACE on the same session
    // object. Anything else holding a reference (e.g. an in-flight
    // command builder waiting on the queue) picks up the new key /
    // counter / epoch automatically.
    //
    // Counter/epoch merge follows Tesla's pattern in
    // `de0/C15009g.java:303-319`:
    //   • If the epoch changed → take the new state wholesale.
    //   • If the epoch is the same → keep the HIGHER of the two
    //     counters (handles the case where another client has been
    //     sending commands on the same session).
    //   • Update `localBaselineMs` only if the new clockTime is at
    //     least as recent as the old (avoids regressing on a clock
    //     skew).
    const epochChanged = !_bytesEqual(session.epoch, sessionInfo.epoch);
    const newCounter   = sessionInfo.counter || 0;
    const newClockTime = sessionInfo.clockTime || 0;

    session.sessionKey      = sessionKey;
    session.keyBytes        = keyBytes;
    session.vehiclePubRaw   = sessionInfo.publicKey;
    session.epoch           = sessionInfo.epoch;
    session.counter         = epochChanged ? newCounter : Math.max(session.counter, newCounter);
    session.clockBase       = newClockTime;
    if (epochChanged || newClockTime >= session.clockBase) {
        session.localBaselineMs = Date.now();
    }

    // Persist updated metadata so a reload right after refetch picks
    // up the new keying material, not the stale one.
    try { await _persistSessionMetadata(session); }
    catch (e) { console.warn('[airgap] refetch persist failed:', e.message || e); }

    console.log('[airgap] in-place SessionInfo refetch ✓', 'domain=' + session.domain, 'counter=' + session.counter);
    return session;
}

// _persistSessionMetadata writes the durable bits of a session to
// IndexedDB. Everything except the AES key — that's recomputed on
// hydration from (local long-term private key, vehiclePubRaw).
async function _persistSessionMetadata(session) {
    if (!airgap.saveSessionMetadata) return; // keystore not loaded yet
    await airgap.saveSessionMetadata(session.vin, session.domain, {
        sessionId:       session.sessionId,
        vin:             session.vin,
        domain:          session.domain,
        routingAddress:  session.routingAddress,
        myPubRaw:        session.myPubRaw,
        vehiclePubRaw:   session.vehiclePubRaw,
        epoch:           session.epoch,
        counter:         session.counter,
        clockBase:       session.clockBase,
        localBaselineMs: session.localBaselineMs,
        savedAt:         Date.now(),
    });
}

// _hydrateSessionFromIdb tries to rebuild a usable session from
// persisted metadata. Returns null if no metadata exists OR if the
// metadata can't be turned into a working session (e.g. local
// private key rotated). The caller falls back to a fresh handshake
// on null.
async function _hydrateSessionFromIdb({ api, vin, deviceKeyPair, domain }) {
    if (!airgap.loadSessionMetadata) return null;
    const meta = await airgap.loadSessionMetadata(vin, domain);
    if (!meta) return null;

    try {
        const carEphPub = await airgap.importPeerPubkey(meta.vehiclePubRaw);
        const keyBytes  = await airgap.deriveSessionKeyMaterial(deviceKeyPair.privateKey, carEphPub);
        const sessionKey = await crypto.subtle.importKey(
            'raw', keyBytes,
            { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
        );

        // Hydration also acquires a refcount on the Pi-side
        // sessionId, so cross-domain reuse + multi-tab survival
        // stays accurate after page reload.
        _piSessionAcquire(meta.sessionId);

        const session = {
            sessionId:       meta.sessionId,
            domain:          meta.domain,
            vin:             meta.vin,
            routingAddress:  meta.routingAddress,
            sessionKey,
            keyBytes,
            myPubRaw:        meta.myPubRaw,
            vehiclePubRaw:   meta.vehiclePubRaw,
            epoch:           meta.epoch,
            counter:         meta.counter,
            clockBase:       meta.clockBase,
            localBaselineMs: meta.localBaselineMs,
            close: async () => {
                await _piSessionRelease(api, meta.sessionId);
            },
        };
        console.log('[airgap] hydrated session from IDB:', vin.slice(-6), 'domain=' + domain, 'counter=' + session.counter);
        return session;
    } catch (e) {
        console.warn('[airgap] session hydration failed (will re-handshake):', e.message || e);
        // Stale metadata (e.g. local key rotated) — wipe it so we
        // don't keep trying the same bad data.
        try { await airgap.deleteSessionMetadata(vin, domain); } catch {}
        return null;
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

// sendDirectCommandWithApi ships a pre-encoded inner payload through
// the byte forwarder. The caller supplies the bytes (Thread C made
// action builders return ENCODED bytes, not an object, so VCSEC and
// Infotainment can share this path — they use different proto wrappers
// inside the ciphertext).
async function sendDirectCommandWithApi({ api, session, payloadBytes, flags }) {
    // Need the proto types for RoutableMessage encode/decode. This
    // was missing for the entire life of Thread C-2 (the unit-test
    // suite mocked this function out, so the call site was never
    // exercised with the real proto path until we hit the car).
    const proto = await airgap.loadProto();

    const actionBytes = payloadBytes;
    // flags is a bit-field on the RoutableMessage. The only bit we
    // use is FLAG_ENCRYPT_RESPONSE (bit 1 / value 2), set on
    // Infotainment state-read requests like getChargeState — the
    // car otherwise refuses to send the response in the clear and
    // replies with MESSAGEFAULT_ERROR_REQUIRES_RESPONSE_ENCRYPTION.
    // The flag MUST appear in both the wire RoutableMessage AND the
    // AAD metadata so the digests match on both sides.
    const wireFlags = flags || 0;

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
        flags:        wireFlags,
    });

    const env = await airgap.aesGcmEncrypt(session.sessionKey, actionBytes, aadDigest);

    const requestUuid = crypto.getRandomValues(new Uint8Array(16));
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
        uuid: requestUuid,
        flags: wireFlags,
    });

    const r = await api.request('POST', `/sessions/${session.sessionId}/exchange`, {
        payload_b64: airgap.bytesToBase64(cmdRoutable),
        timeout_ms:  COMMAND_TIMEOUT_MS,
    });

    const respBytes = airgap.base64ToBytes(r.response_b64);
    const respMsg   = airgap.decodeMessage(proto.RoutableMessage, respBytes);

    // The Pi's BLE forwarder reads whatever is next in the receive
    // channel — if a previous request's response arrived late (after
    // its timeout), the channel holds that stale response and the
    // NEXT exchange pulls it. That manifests as: charge succeeds
    // (first request, channel empty), climate gets back charge's
    // response, decrypt fails because the request tag the car used
    // to AAD-encrypt the charge response doesn't match the climate
    // request's tag we'd use to compute AAD.
    //
    // The car echoes our uuid back as request_uuid on the matching
    // response, so a mismatch here means we received a response to
    // a DIFFERENT request. Surface it loudly instead of letting it
    // masquerade as an opaque AES decrypt error.
    if (respMsg.requestUuid && respMsg.requestUuid.length > 0) {
        let matches = respMsg.requestUuid.length === requestUuid.length;
        if (matches) {
            for (let i = 0; i < requestUuid.length; i++) {
                if (respMsg.requestUuid[i] !== requestUuid[i]) { matches = false; break; }
            }
        }
        if (!matches) {
            const sent = airgap.bytesToHex(requestUuid).slice(0, 16);
            const got  = airgap.bytesToHex(respMsg.requestUuid).slice(0, 16);
            throw new Error(`Pi returned stale response: sent uuid=${sent}… got request_uuid=${got}… (Pi-side BLE channel has buffered a previous response)`);
        }
    }

    // Stale-frame detection for unsolicited car broadcasts that carry
    // NO request_uuid (the uuid check above can't catch them). Two
    // signals:
    //
    //   1. fromDestination.domain doesn't match the domain we sent to.
    //      Example: we sent to Infotainment (3) but the Pi returned a
    //      VCSEC broadcast (2) — a WhitelistOperation_status or
    //      VehicleStatus push that happened to land in the BLE receive
    //      channel before our actual reply.
    //
    //   2. We requested encrypted-response (FLAG_ENCRYPT_RESPONSE) but
    //      the frame has no AES_GCM_ResponseData. Either the car sent
    //      a status-only reply (which would have set signedMessageStatus,
    //      so let those through) or it's an unsolicited unencrypted
    //      broadcast (no signedMessageStatus, just protobufMessageAsBytes).
    //
    // Both surface as "stale frame" errors so _directDo's retry loop
    // picks them up. Pi's pre-send drain on the next /exchange tosses
    // the stale frame; the car re-responds to our retried request.
    const respFromDomain = respMsg.fromDestination?.domain;
    if (respFromDomain != null && respFromDomain !== session.domain) {
        throw new Error(`Pi returned stale frame: expected from domain=${session.domain}, got from domain=${respFromDomain}`);
    }
    const isEncryptedRequest = (wireFlags & FLAG_ENCRYPT_RESPONSE_BIT) !== 0;
    const hasAesGcm = !!respMsg.signatureData?.AES_GCM_ResponseData;
    const hasPayload = respMsg.protobufMessageAsBytes && respMsg.protobufMessageAsBytes.length > 0;
    const hasStatus  = !!respMsg.signedMessageStatus;
    if (isEncryptedRequest && hasPayload && !hasAesGcm && !hasStatus) {
        throw new Error('Pi returned stale frame: requested encrypted response but got unencrypted payload with no status (unsolicited car broadcast)');
    }

    // Thread C-2: decrypt the payload if present. The car wraps
    // command responses (status, returned data, fault details) in
    // an AES-GCM ciphertext under the same session key, with
    // AAD derived from a metadata block that includes a hash of the
    // request that triggered it (REQUEST_HASH) — so a response can't
    // be replayed against a different request.
    //
    // For status-only commands (honk, lock) the unencrypted
    // signedMessageStatus is enough and there's no payload to
    // decrypt; for state reads the encrypted protobufMessageAsBytes
    // carries a CarServer.Response we want.
    let decryptedPayload = null;
    const gcmResp = respMsg.signatureData?.AES_GCM_ResponseData;
    if (gcmResp && respMsg.protobufMessageAsBytes && respMsg.protobufMessageAsBytes.length > 0) {
        const requestHash = airgap.makeRequestHash(env.tag);
        const responseDomain = respMsg.fromDestination?.domain ?? session.domain;
        const responseFlags  = respMsg.flags || 0;
        const fault          = respMsg.signedMessageStatus?.signedMessageFault || 0;

        const aadDigest = await airgap.buildAesGcmResponseMetadata({
            domain:       responseDomain,
            verifierName: session.vin,
            counter:      gcmResp.counter || 0,
            flags:        responseFlags,
            requestHash,
            fault,
        });
        try {
            decryptedPayload = await airgap.aesGcmDecrypt(
                session.sessionKey,
                gcmResp.nonce,
                respMsg.protobufMessageAsBytes,
                gcmResp.tag,
                aadDigest,
            );
        } catch (e) {
            // Decrypt failed. The AAD digest mixes in REQUEST_HASH
            // (sha256 of OUR request's GCM tag) and the response
            // counter, so a failure on a structurally valid response
            // means the car AAD'd it against a DIFFERENT request —
            // i.e. we got back the response to a previous command
            // that the Pi had buffered. This is the same stale-frame
            // race as the request_uuid/from-domain mismatches above,
            // just expressed via the crypto layer instead of plain
            // metadata. Throw so _directDo's retry loop picks it up.
            //
            // We treat this as stale-frame ONLY when we actually
            // expected an encrypted response (FLAG_ENCRYPT_RESPONSE
            // set). Without that flag the car may legitimately respond
            // with status-only and an unrelated AES_GCM tag we
            // can't decrypt, but the caller doesn't need the
            // payload anyway.
            const wasEncryptedRequest = (wireFlags & FLAG_ENCRYPT_RESPONSE_BIT) !== 0;
            console.warn('[airgap] response decrypt failed:', e.message || e);
            if (wasEncryptedRequest) {
                throw new Error(`Pi returned stale frame: decrypt failed against this request's AAD (counter=${gcmResp.counter}, requestHash mismatch — channel had a buffered response to a different request)`);
            }
        }
    }

    // Persist the updated counter (and other mutable bits) so a
    // page reload picks up where we left off instead of resending
    // a counter value the car has already seen. Fire-and-forget;
    // an IDB write delay shouldn't block the command response.
    _persistSessionMetadata(session).catch(e =>
        console.warn('[airgap] counter persist failed:', e.message || e));

    return { routable: respMsg, decryptedPayload };
}

// ── Session cache ────────────────────────────────────────────────
//
// Thread D: the SessionInfo handshake costs ~2 s round-trip over BLE.
// Closing and reopening per command makes a UX flow of "lock, then
// flash, then honk" feel sluggish. Cache the open session per domain
// for a short idle window; reuse it; close it when the operator
// leaves or the TTL expires.
//
// Tesla Android keeps the AES shared-secret cache forever (only
// clears on account change), and persists session metadata to a
// durable store (Realm) so process restart re-derives the same key
// without a fresh handshake. We mirror that: NO IDLE TTL on the
// in-memory cache, AND IndexedDB persistence so reloads pick up
// where we left off.
//
// Invalidation is reactive — the car returns INVALID_SIGNATURE /
// INVALID_KEY_HANDLE when its side of the session has rotated, and
// the caller calls evictSession(vin, domain) to drop our copy and
// re-handshake on the next attempt.

const _domainCache = new Map(); // domain → { session }

async function withCachedSession({ api, vin, deviceKeyPair, domain }, body) {
    // 1. In-memory cache — instant reuse.
    let entry = _domainCache.get(domain);
    if (entry) {
        try {
            return await body(entry.session, /*cached*/true);
        } catch (e) {
            // Transport-dead errors (Pi-side BLE link gone, session
            // not found, etc.) → drop the bad session and fall
            // through to fresh handshake. This is the recovery path
            // ALL callers benefit from — verifyClosures (vcsecSync),
            // directRefreshState (awakeSync), the background reader,
            // and the _directDo retry loop don't need to know.
            //
            // Any OTHER exception (fault codes, decrypt failures,
            // network errors) bubbles up so the caller can decide.
            if (isTransportDeadError(e)) {
                console.warn('[airgap] cached session transport dead — evicting + opening fresh:', e.message);
                await evictSession(vin, domain);
                // Fall through to handshake below.
            } else {
                console.warn('[airgap] in-flight error on cached session:', e.message || e);
                throw e;
            }
        }
    }

    // 2. IDB hydration — try to rebuild a session from persisted
    //    metadata. No network, no handshake. ~50ms.
    const hydrated = await _hydrateSessionFromIdb({ api, vin, deviceKeyPair, domain });
    if (hydrated) {
        _domainCache.set(domain, { session: hydrated });
        try {
            return await body(hydrated, /*cached*/true);
        } catch (e) {
            if (isTransportDeadError(e)) {
                console.warn('[airgap] hydrated session transport dead — evicting + opening fresh:', e.message);
                await evictSession(vin, domain);
                // Fall through to handshake below.
            } else {
                console.warn('[airgap] hydrated session failed on first use:', e.message || e);
                throw e;
            }
        }
    }

    // 3. Cold start — full BLE handshake. ~2-15s depending on radio.
    //
    // openDirectSession's first step is _findOrOpenPiSession, which
    // can return a STALE sessionId from IDB if the cached/hydrated
    // paths above were never taken (e.g. user clicks global Refresh
    // after a Pi restart: no cached entry, no Infotainment IDB row,
    // but a VCSEC IDB row pointing at a long-dead sessionId). The
    // SessionInfoRequest then immediately 404s with "BLE session
    // not found" and we'd surface that to the user verbatim.
    //
    // Catch transport-dead here too: do a full VIN-scoped evict
    // (drops every IDB row regardless of sessionId equality) and
    // retry the cold start exactly once. After evict, IDB is empty,
    // so _findOrOpenPiSession's next call falls through to a fresh
    // POST /sessions.
    let session;
    try {
        session = await openDirectSession({ api, vin, deviceKeyPair, domain });
    } catch (e) {
        if (!isTransportDeadError(e)) throw e;
        console.warn('[airgap] cold-start hit stale Pi sessionId — VIN-scoped evict + retry:', e.message || e);
        await evictSession(vin, domain);
        session = await openDirectSession({ api, vin, deviceKeyPair, domain });
    }
    _domainCache.set(domain, { session });
    try {
        return await body(session, /*cached*/false);
    } catch (e) {
        // Fresh handshake but the very first command failed —
        // something fundamental is wrong. Evict and re-raise.
        _evict(domain);
        throw e;
    }
}

// refreshCachedSession is the new reactive-invalidation entry point
// for "session is stale" faults (INVALID_SIGNATURE,
// INVALID_TOKEN_OR_COUNTER, INCORRECT_EPOCH, INACTIVE_KEY). Tesla
// Android does NOT tear down the BLE link in these cases — it sends
// a fresh SessionInfoRequest on the existing BLE session, gets back
// new keying material, and retries. We do the same.
//
// On success: the in-memory session is updated in place with the
// new key/counter/epoch. The next command rides the same BLE link.
//
// On failure (BLE link is genuinely dead, Pi reaped the session,
// etc.): fall back to evictSession() so the next attempt does a
// full handshake.
async function refreshCachedSession({ api, vin, domain, deviceKeyPair }) {
    const entry = _domainCache.get(domain);
    if (!entry) {
        // Nothing to refresh — caller will hit withCachedSession
        // next time and do a full handshake.
        return false;
    }
    try {
        await refetchSessionInfo({ api, deviceKeyPair, session: entry.session });
        return true;
    } catch (e) {
        console.warn('[airgap] in-place refresh failed, falling back to full evict:', e.message || e);
        await evictSession(vin, domain);
        return false;
    }
}

// evictSession is the fallback for "session is genuinely dead, need
// a full handshake" — both BLE side and crypto side. Drops the
// in-memory cache AND the IDB rows.
//
// Semantics: the unit of liveness is the (VIN, BLE link), NOT
// (VIN, domain). Both domains share one Pi-side sessionId, so a
// transport-dead error from any one domain means the BLE link is
// dead for the whole VIN. We therefore tear down EVERY cached
// session AND EVERY IDB session metadata row for this VIN —
// regardless of which sessionId each row references.
//
// Why the regardless-of-sessionId-equality matters: in the wild
// IDB can hold mixed-vintage metadata (e.g. a VCSEC row written
// before the shared-sessionId model was reintroduced and an
// Infotainment row written after) where each points at a
// different sessionId. A stricter "only evict rows whose sessionId
// matches the dead one" rule leaves the other domain's stale row
// in place; the next _findOrOpenPiSession walks IDB, finds that
// row, returns its dead sessionId, hands it to openDirectSession,
// and the handshake fails identically. We saw this as "Refresh:
// BLE session not found" surviving 5 clicks in a row.
//
// `domain` parameter is preserved as a hint for logging, but the
// action is VIN-scoped.
async function evictSession(vin, domain) {
    // 1. Drop every in-memory cached domain for this VIN. _evict
    //    triggers session.close() which decrements the refcount;
    //    any leftover refcount entries are zeroed below.
    const victims = [];
    for (const [d, e] of _domainCache.entries()) {
        if (e.session?.vin === vin) victims.push({ d, sessionId: e.session.sessionId });
    }
    for (const v of victims) _evict(v.d);

    // 2. Wipe IDB metadata for BOTH domains on this VIN regardless
    //    of stored sessionId. Hydration would otherwise resurrect a
    //    dead reference.
    if (airgap.deleteSessionMetadata) {
        for (const d of [DOMAIN_VEHICLE_SECURITY, DOMAIN_INFOTAINMENT]) {
            try { await airgap.deleteSessionMetadata(vin, d); }
            catch (e) { console.warn('[airgap] IDB session delete failed:', e.message || e); }
        }
    }

    // 3. Zero any leftover refcounts for sessionIds that were
    //    associated with this VIN, so the next _bindPiSession
    //    opens fresh instead of pretending a session is still
    //    live.
    for (const v of victims) _piSessionRefcounts.delete(v.sessionId);

    console.warn('[airgap] evicted all sessions for vin', vin.slice(-6),
        '· dropped domains:', victims.map(v => v.d).join(',') || '(none cached)',
        '· trigger=' + domain);
}

function _evict(domain) {
    const entry = _domainCache.get(domain);
    if (!entry) return;
    _domainCache.delete(domain);
    // Best-effort BLE close. Don't wait — the Pi has its own reaper.
    entry.session.close().catch(() => {});
}

// closeAllCachedSessions drops every domain's cached in-memory
// session AND wipes IDB-persisted metadata. Called on "forget this
// Pi" — NOT on page unload (we want the IDB metadata to survive
// reloads). Browser beforeunload still calls _evict-only via
// closeAllInMemoryOnly() below.
function closeAllCachedSessions() {
    for (const domain of [..._domainCache.keys()]) {
        _evict(domain);
    }
    try { if (airgap.clearAllSessionMetadata) airgap.clearAllSessionMetadata(); } catch {}
}

// closeAllInMemoryOnly is the lighter beforeunload path — clears
// in-memory cache (and sends the BLE close to free the Pi mutex)
// but LEAVES IDB metadata intact so reload can hydrate. The Pi has
// its own 5-min reaper so the BLE close on unload is a polite
// release, not a correctness requirement.
function closeAllInMemoryOnly() {
    for (const domain of [..._domainCache.keys()]) {
        _evict(domain);
    }
}

// ── Action builders (Thread C v1) ────────────────────────────────
//
// Each builder returns { domain, bytes }: the wire bytes ready to be
// AES-GCM-encrypted, and the BLE domain those bytes target. Two proto
// wrappers come into play depending on domain:
//
//   • DOMAIN_INFOTAINMENT (3) → CarServer.Action wrapping VehicleAction
//   • DOMAIN_VEHICLE_SECURITY (2) → VCSEC.UnsignedMessage
//
// Both end up encrypted opaquely once they hit sendDirectCommandWithApi;
// the per-domain proto choice only matters here at construction time.

const DOMAIN_INFOTAINMENT     = 3;
const DOMAIN_VEHICLE_SECURITY = 2;

// VCSEC enum values, vendored from vcsec.proto so action builders
// don't have to re-parse the proto every call.
const RKE_ACTION = Object.freeze({
    UNLOCK:                 0,
    LOCK:                   1,
    REMOTE_DRIVE:          20,
    AUTO_SECURE_VEHICLE:   29,
    WAKE_VEHICLE:          30,
});
const CLOSURE_MOVE = Object.freeze({
    NONE:  0,
    MOVE:  1,
    STOP:  2,
    OPEN:  3,
    CLOSE: 4,
});

// _encodeInfotainmentAction is the common path for any
// VehicleAction sub-message. Returns the encoded CarServer.Action.
async function _encodeInfotainmentAction(vehicleAction) {
    const proto = await airgap.loadProto();
    return airgap.encodeMessage(proto.Action, { vehicleAction });
}

// _encodeVCSECMessage wraps a sub_message into VCSEC.UnsignedMessage
// and encodes it. The fields object's single key picks the oneof.
async function _encodeVCSECMessage(subFields) {
    const proto = await airgap.loadProto();
    return airgap.encodeMessage(proto.VCSECUnsignedMessage, subFields);
}

// ─── Infotainment actions ───
async function honkAction()        { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ vehicleControlHonkHornAction: {} }) }; }
async function flashLightsAction() { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ vehicleControlFlashLightsAction: {} }) }; }
async function climateOnAction()   { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ hvacAutoAction: { powerOn: true } }) }; }
async function climateOffAction()  { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ hvacAutoAction: { powerOn: false } }) }; }
async function sentryOnAction()    { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ vehicleControlSetSentryModeAction: { on: true } }) }; }
async function sentryOffAction()   { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ vehicleControlSetSentryModeAction: { on: false } }) }; }
async function startChargingAction()    { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ chargingStartStopAction: { start: {} } }) }; }
async function stopChargingAction()     { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ chargingStartStopAction: { stop:  {} } }) }; }
async function chargeMaxRangeAction()   { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ chargingStartStopAction: { startMaxRange:  {} } }) }; }
async function chargeStandardRangeAction(){ return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ chargingStartStopAction: { startStandard: {} } }) }; }
async function setChargeLimitAction(percent) {
    const p = Math.round(percent);
    if (p < 50 || p > 100) throw new Error('charge limit must be 50..100');
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ chargingSetLimitAction: { percent: p } }) };
}

// ─── Climate keeper / cabin overheat / accessory power / wheel heater ───
//
// HvacClimateKeeperAction.keeperId enum: 0=Off, 1=On, 2=Dog, 3=Camp.

const CLIMATE_KEEPER = Object.freeze({ OFF: 0, ON: 1, DOG: 2, CAMP: 3 });

async function setClimateKeeperAction(mode) {
    const m = Number(mode);
    if (![0,1,2,3].includes(m)) throw new Error('climate keeper mode must be 0..3');
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ hvacClimateKeeperAction: { climateKeeperAction: m } }) };
}
async function setCabinOverheatAction(on)     { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ setCabinOverheatProtectionAction: { on: !!on, fanOnly: false } }) }; }
async function setKeepAccPowerAction(on)      { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ hvacBioweaponModeAction: { on: !!on, manualOverride: false } }) }; }
async function setSteeringWheelHeaterAction(on){ return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ hvacSteeringWheelHeaterAction: { powerOn: !!on } }) }; }

// ─── Windows ───
// VehicleControlWindowAction.action is a oneof (vent / close / unknown);
// the Void inner messages just need {} to set the oneof case.
async function ventWindowsAction() { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ vehicleControlWindowAction: { vent:  {} } }) }; }
async function closeWindowsAction(){ return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ vehicleControlWindowAction: { close: {} } }) }; }

// ─── Seat heater / cooler ───
//
// SEAT_POS names mirror the proto's CAR_SEAT_* / HvacSeatCoolerPosition_*
// enums (heaters and coolers use different enum systems — heaters use
// a Void oneof, coolers use a numeric enum). Keep both maps so callers
// can use one vocabulary.
const SEAT_POS_HEATER = Object.freeze({
    FRONT_LEFT: 'CAR_SEAT_FRONT_LEFT',
    FRONT_RIGHT: 'CAR_SEAT_FRONT_RIGHT',
    REAR_LEFT: 'CAR_SEAT_REAR_LEFT',
    REAR_CENTER: 'CAR_SEAT_REAR_CENTER',
    REAR_RIGHT: 'CAR_SEAT_REAR_RIGHT',
});
const SEAT_HEATER_LEVEL = Object.freeze({
    OFF: 'SEAT_HEATER_OFF',
    LOW: 'SEAT_HEATER_LOW',
    MED: 'SEAT_HEATER_MED',
    HIGH: 'SEAT_HEATER_HIGH',
});
async function setSeatHeaterAction(position, level) {
    const p = SEAT_POS_HEATER[position] || position;
    const l = SEAT_HEATER_LEVEL[level]   || level;
    return {
        domain: DOMAIN_INFOTAINMENT,
        bytes: await _encodeInfotainmentAction({
            hvacSeatHeaterActions: {
                hvacSeatHeaterAction: [{ [l]: {}, [p]: {} }],
            },
        }),
    };
}

// Cooler enum is numeric: 1=Off, 2=Low, 3=Med, 4=High. Positions are
// FrontLeft=1, FrontRight=2.
const SEAT_COOLER_LEVEL = Object.freeze({ OFF: 1, LOW: 2, MED: 3, HIGH: 4 });
const SEAT_COOLER_POS   = Object.freeze({ FRONT_LEFT: 1, FRONT_RIGHT: 2 });
async function setSeatCoolerAction(position, level) {
    const p = SEAT_COOLER_POS[position]   ?? position;
    const l = SEAT_COOLER_LEVEL[level]    ?? level;
    return {
        domain: DOMAIN_INFOTAINMENT,
        bytes: await _encodeInfotainmentAction({
            hvacSeatCoolerActions: {
                hvacSeatCoolerAction: [{ seatPosition: p, seatCoolerLevel: l }],
            },
        }),
    };
}

// ─── Homelink / remote drive ───
async function homelinkAction({ latitude, longitude }) {
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
        throw new Error('homelink needs valid lat/lon');
    }
    return {
        domain: DOMAIN_INFOTAINMENT,
        bytes: await _encodeInfotainmentAction({
            vehicleControlTriggerHomelinkAction: { location: { latitude, longitude } },
        }),
    };
}
async function remoteDriveAction() {
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ vehicleControlRemoteStartAction: {} }) };
}

// ─── Valet / speed-limit (PIN-protected) ───
function _validatePin(pin) {
    const p = (pin || '').toString();
    if (!/^\d{4}$/.test(p)) throw new Error('PIN must be exactly 4 digits');
    return p;
}
async function setValetModeAction(on, pin) {
    const p = _validatePin(pin);
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ vehicleControlSetValetModeAction: { on: !!on, password: p } }) };
}
async function activateSpeedLimitAction(pin) {
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ drivingSpeedLimitAction: { activate: true,  pin: _validatePin(pin) } }) };
}
async function deactivateSpeedLimitAction(pin) {
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ drivingSpeedLimitAction: { activate: false, pin: _validatePin(pin) } }) };
}
async function clearSpeedLimitPinAction(pin) {
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ drivingClearSpeedLimitPinAction: { pin: _validatePin(pin) } }) };
}
async function setSpeedLimitMphAction(mph) {
    const m = Number(mph);
    if (!Number.isFinite(m) || m < 50 || m > 90) throw new Error('speed limit must be 50..90 mph');
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ drivingSetSpeedLimitAction: { limitMph: m } }) };
}

// ─── Navigation (4 forms — from the SDK fork) ───
//
// Order enums are nested per message in protobuf.js, so we use
// numeric values directly. REPLACE=1, PREPEND=2, APPEND=3.
const NAV_ORDER = Object.freeze({ REPLACE: 1, PREPEND: 2, APPEND: 3 });

async function navigateGpsAction({ lat, lon, order }) {
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({
        navigationGpsRequest: { lat: Number(lat), lon: Number(lon), order: order || NAV_ORDER.REPLACE },
    }) };
}
async function navigateGpsWithLabelAction({ lat, lon, label, order }) {
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({
        navigationGpsDestinationRequest: { lat: Number(lat), lon: Number(lon), destination: label || '', order: order || NAV_ORDER.REPLACE },
    }) };
}
async function navigateSearchAction({ query, order }) {
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({
        navigationRequest: { destination: query, order: order || NAV_ORDER.REPLACE },
    }) };
}
async function navigateWaypointsAction({ waypoints }) {
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({
        navigationWaypointsRequest: { waypoints },
    }) };
}

// ─── Boombox ───
async function boomboxAction(sound) {
    const s = Number(sound);
    if (!Number.isInteger(s) || s < 0 || s > 65535) throw new Error('sound must be 0..65535');
    return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ boomboxAction: { sound: s } }) };
}

// ─── State-read actions ───
// Each wraps a GetVehicleData sub-message; the car responds with a
// CarServer.Response carrying the requested data. Domain is always
// Infotainment (the centre console serves these reads).

// FLAG_ENCRYPT_RESPONSE = 1 (enum value from universal_message.proto).
// On the wire flags field it's used as a bitmask: bit-position 1, so
// the integer value to OR in is 1 << 1 = 2. The car returns
// MESSAGEFAULT_ERROR_REQUIRES_RESPONSE_ENCRYPTION for state reads
// (getChargeState, getClimateState, getDriveState) when this bit
// isn't set.
const FLAG_ENCRYPT_RESPONSE_BIT = 1 << 1;

async function getChargeStateAction()   { return { domain: DOMAIN_INFOTAINMENT, flags: FLAG_ENCRYPT_RESPONSE_BIT, bytes: await _encodeInfotainmentAction({ getVehicleData: { getChargeState:   {} } }) }; }
async function getClimateStateAction()  { return { domain: DOMAIN_INFOTAINMENT, flags: FLAG_ENCRYPT_RESPONSE_BIT, bytes: await _encodeInfotainmentAction({ getVehicleData: { getClimateState:  {} } }) }; }
async function getDriveStateAction()    { return { domain: DOMAIN_INFOTAINMENT, flags: FLAG_ENCRYPT_RESPONSE_BIT, bytes: await _encodeInfotainmentAction({ getVehicleData: { getDriveState:    {} } }) }; }
async function getLocationStateAction() { return { domain: DOMAIN_INFOTAINMENT, flags: FLAG_ENCRYPT_RESPONSE_BIT, bytes: await _encodeInfotainmentAction({ getVehicleData: { getLocationState: {} } }) }; }

// getFullVehicleDataAction is the "awake sync" payload: one BLE round-
// trip carrying all the Infotainment-domain slices in a single
// GetVehicleData request. Cheaper than three separate reads when the
// session is already open, and gives the client a self-consistent
// snapshot rather than three temporally-skewed ones.
//
// Includes getLocationState because Homelink needs the car's current
// lat/lon — that lives in LocationState, not DriveState (which only
// carries shift state + speed + active route info).
async function getFullVehicleDataAction() {
    return {
        domain: DOMAIN_INFOTAINMENT,
        bytes: await _encodeInfotainmentAction({
            getVehicleData: {
                getChargeState:   {},
                getClimateState:  {},
                getDriveState:    {},
                getLocationState: {},
                getClosuresState: {},
            },
        }),
    };
}

// ─── VCSEC GET_STATUS ───
//
// The VCSEC equivalent of "give me current state": wraps an
// InformationRequest with type GET_STATUS in the VCSEC.UnsignedMessage
// envelope. Car responds with FromVCSECMessage{ vehicleStatus: ... }
// carrying lock state, sleep flag, closures, presence — the cheap,
// no-wake state we can poll continuously.
//
// 0 = INFORMATION_REQUEST_TYPE_GET_STATUS (vcsec.proto).
//
// Also sets FLAG_ENCRYPT_RESPONSE. The response carries a
// FromVCSECMessage.vehicleStatus, which we want to decode — so it
// needs to come back encrypted under our session key. Tesla's
// Android app sets this flag on essentially all state-read paths;
// we mirror.
async function vcsecGetStatusAction() {
    return {
        domain: DOMAIN_VEHICLE_SECURITY,
        flags: FLAG_ENCRYPT_RESPONSE_BIT,
        bytes: await _encodeVCSECMessage({
            InformationRequest: { informationRequestType: 0 },
        }),
    };
}

// ─── Defrost + temperature (deferred from Thread C v1) ───
//
// HvacSetPreconditioningMaxAction toggles "max defrost"; the SDK uses
// it for the Defrost button on the mobile app.
// HvacTemperatureAdjustmentAction sets target cabin temperature; the
// Temperature sub-message accepts a celsius float via the
// `levels` repeated field (the SDK does it that way to handle dual-
// zone vehicles — front/rear separate temps).

async function defrostOnAction()  { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ hvacSetPreconditioningMaxAction: { on: true,  manualOverride: false } }) }; }
async function defrostOffAction() { return { domain: DOMAIN_INFOTAINMENT, bytes: await _encodeInfotainmentAction({ hvacSetPreconditioningMaxAction: { on: false, manualOverride: false } }) }; }

async function setClimateTempAction(celsius) {
    const c = Number(celsius);
    if (!Number.isFinite(c) || c < 15 || c > 28) {
        throw new Error('climate temperature must be 15..28 °C');
    }
    return {
        domain: DOMAIN_INFOTAINMENT,
        bytes: await _encodeInfotainmentAction({
            hvacTemperatureAdjustmentAction: {
                // levels = repeated float; first entry is driver, second
                // passenger. Set both to the same value for single-zone
                // cars and the SDK's "match passenger to driver" UX.
                levels: [c, c],
            },
        }),
    };
}

// ─── VCSEC actions ───
async function lockAction()    { return { domain: DOMAIN_VEHICLE_SECURITY, bytes: await _encodeVCSECMessage({ RKEAction: RKE_ACTION.LOCK   }) }; }
async function unlockAction()  { return { domain: DOMAIN_VEHICLE_SECURITY, bytes: await _encodeVCSECMessage({ RKEAction: RKE_ACTION.UNLOCK }) }; }
async function wakeAction()    { return { domain: DOMAIN_VEHICLE_SECURITY, bytes: await _encodeVCSECMessage({ RKEAction: RKE_ACTION.WAKE_VEHICLE }) }; }

async function openFrunkAction()      { return { domain: DOMAIN_VEHICLE_SECURITY, bytes: await _encodeVCSECMessage({ closureMoveRequest: { frontTrunk: CLOSURE_MOVE.OPEN } }) }; }
async function openTrunkAction()      { return { domain: DOMAIN_VEHICLE_SECURITY, bytes: await _encodeVCSECMessage({ closureMoveRequest: { rearTrunk:  CLOSURE_MOVE.OPEN } }) }; }
async function closeTrunkAction()     { return { domain: DOMAIN_VEHICLE_SECURITY, bytes: await _encodeVCSECMessage({ closureMoveRequest: { rearTrunk:  CLOSURE_MOVE.CLOSE } }) }; }
async function openChargePortAction() { return { domain: DOMAIN_VEHICLE_SECURITY, bytes: await _encodeVCSECMessage({ closureMoveRequest: { chargePort: CLOSURE_MOVE.OPEN  } }) }; }
async function closeChargePortAction(){ return { domain: DOMAIN_VEHICLE_SECURITY, bytes: await _encodeVCSECMessage({ closureMoveRequest: { chargePort: CLOSURE_MOVE.CLOSE } }) }; }

Object.assign(window.airgap, {
    openDirectSession,
    sendDirectCommandWithApi,
    withCachedSession,
    closeAllCachedSessions,
    closeAllInMemoryOnly,
    evictSession,
    refreshCachedSession,
    refetchSessionInfo,
    evaluateFault,
    isTransportDeadError,
    isStaleFrameError,
    MAX_BLE_ATTEMPTS,
    TRANSIENT_DELAY_MS,
    DOMAIN_INFOTAINMENT,
    DOMAIN_VEHICLE_SECURITY,

    // Action builders.
    honkAction, flashLightsAction,
    climateOnAction, climateOffAction,
    defrostOnAction, defrostOffAction,
    setClimateTempAction,
    sentryOnAction, sentryOffAction,
    startChargingAction, stopChargingAction,
    chargeMaxRangeAction, chargeStandardRangeAction,
    setChargeLimitAction,
    lockAction, unlockAction, wakeAction,
    openFrunkAction, openTrunkAction, closeTrunkAction,
    openChargePortAction, closeChargePortAction,

    // Climate / comfort
    setClimateKeeperAction, setCabinOverheatAction,
    setKeepAccPowerAction, setSteeringWheelHeaterAction,
    CLIMATE_KEEPER,

    // Windows
    ventWindowsAction, closeWindowsAction,

    // Seat heater + cooler
    setSeatHeaterAction, setSeatCoolerAction,
    SEAT_POS_HEATER, SEAT_HEATER_LEVEL,
    SEAT_COOLER_POS, SEAT_COOLER_LEVEL,

    // Homelink, remote drive
    homelinkAction, remoteDriveAction,

    // Valet + speed-limit (PIN-protected)
    setValetModeAction,
    activateSpeedLimitAction, deactivateSpeedLimitAction,
    clearSpeedLimitPinAction, setSpeedLimitMphAction,

    // Navigation
    navigateGpsAction, navigateGpsWithLabelAction,
    navigateSearchAction, navigateWaypointsAction,
    NAV_ORDER,

    // Boombox
    boomboxAction,

    // State reads.
    getChargeStateAction, getClimateStateAction, getDriveStateAction, getLocationStateAction,
    getFullVehicleDataAction,

    // VCSEC GET_STATUS (cheap, no-wake state poll).
    vcsecGetStatusAction,
});
