# airgap client — architecture

This is a pure-TypeScript-in-the-browser Tesla BLE client. It talks to a
Raspberry Pi running `netfilterd`, which forwards opaque encrypted bytes
over the BLE radio to the car. The client owns its own long-term ECDH
key (non-extractable WebCrypto). The Pi never sees plaintext or session
keys.

## Topology

```
[Web browser]   ─\
[iOS RN app]    ──> [Pi: bearer auth + BLE radio] <─> Car
[Android RN app]/
```

Each client device holds its own P-256 keypair, derives its own AES-GCM
session keys via ECDH against the car's ephemeral pubkey, and presents
opaque RoutableMessage bytes to the Pi's `/api/ble/*` byte-forwarder.

The same TypeScript that runs in the browser is intended to run inside
React Native via `react-native-quick-crypto` (Node-crypto compatible) or
the upcoming SubtleCrypto in Hermes. The four layers — protocol crypto,
key storage, HTTP transport, and UI — were separated specifically so
RN can swap the key-storage layer (IndexedDB → react-native-keychain)
and the UI layer without touching the rest.

## Where the code lives

```
client/
├── index.html         — Alpine.js view + activity log panel + reset BLE
├── airgap.css         — visual style
├── app.js             — Alpine model: _directDo retry loop, per-command
│                        methods, reactive session refresh wiring
├── session.js         — BLE session lifecycle: openDirectSession,
│                        refetchSessionInfo (in-place), withCachedSession
│                        (memory + IDB hydrate + fresh handshake fallback),
│                        sendDirectCommandWithApi (encrypt/send/decrypt),
│                        evaluateFault (Tesla-mirror retry policy),
│                        action builders for every Tesla command.
├── state.js           — VehicleState store: per-VIN slices, IDB
│                        persistence, in-session piggyback decode hooks.
├── crypto.js          — AES-GCM, ECDH→SHA-1 KDF, AAD metadata block.
├── proto.js           — protobuf.js setup, message-type lookups.
├── keystore.js        — IndexedDB schema: device-key + session metadata.
├── activity-log.js    — durable per-command diagnostic ring buffer.
├── state-test.html    — in-browser test runner (46 tests, runs via
│                        `python3 -m http.server` + headless Chrome).
└── proto/             — vendored Tesla .proto files.
```

## The model in one paragraph

Every action the user takes (lock, climate-on, refresh battery) goes
through `_directDo`, which runs a **retry loop** (max 10 attempts, per
Tesla's `nb0/C24292a.java:374`). Each attempt enqueues onto a per-VIN
**serialization queue** (correctness — Tesla's session counter is
monotonic), then runs inside `withCachedSession` which finds the
session by tier: in-memory cache → IndexedDB hydration → fresh BLE
handshake. The encrypted RoutableMessage goes to the Pi via
`/api/ble/sessions/{id}/exchange`; the Pi forwards opaque bytes over
BLE; the response comes back; we decrypt with AES-GCM, verify AAD,
decode the protobuf payload, and apply it to the per-slice
`VehicleState` store. If the car returns a fault, the **policy
evaluator** decides between three actions: session-stale → in-place
SessionInfo refetch on the same warm BLE session (~1 round-trip);
transient → 100ms delay + retry; semantic → surface to user. Every
attempt is logged to localStorage so you can see what happened.

## Where each design decision came from

We arrived at the current shape by reading the decompiled Tesla Android
RN app (see `out/VCSEC_findings/`, `out/tesla-protocol-implementation/`,
and `out/tesla-protocol-followup/`). Each Tesla parallel below
explicitly cites where we learned it.

| What | Tesla source | Where it lives here |
|---|---|---|
| Long-term ECDH key, non-extractable, OS-keystore-backed | `rb0/C28280a.java` uses BKS; we use WebCrypto + IDB structured-clone | `keystore.js` |
| Forever-cached AES session secrets (no idle TTL) | `rb0/C28284e.java:42` `static HashMap sharedSecrets` cleared only on email change | `session.js _domainCache`, no TTL |
| Persist session metadata across restarts, re-derive AES on load | `qb0/C27674d.java` Realm + `com/tesla/sessionmanager/VehicleSessionInfo.java` | `keystore.js saveSessionMetadata`, `session.js _hydrateSessionFromIdb` |
| Persisted fields: vehiclePub, counter, epoch, clockBase, piSessionId | Moshi adapter: publicKeyHex, handle, counter, clockTime, epochHex, epochStartSeconds | `_persistSessionMetadata` |
| In-place SessionInfo refetch on existing BLE session | `xe0/C32376j.java:1230` + `fd0/C17267l.java` — no link teardown | `session.js refetchSessionInfo` |
| Reactive invalidation on session-stale faults | `ed0/C15676c.java:366-378` clears on INVALID_SIGNATURE/INVALID_KEY_HANDLE | `evaluateFault` → 'session-stale' → `refreshCachedSession` |
| Retry policy: 10× BLE, 100ms transient delay | `nb0/C24292a.java:374-386, 390-489` | `evaluateFault` + the loop in `_directDo` |
| Counter merge on same epoch: keep MAX | `de0/C15009g.java:303-319` | `refetchSessionInfo` |
| Epoch start refresh only when new clock ≥ old | `de0/C15009g.java:311-319` | `refetchSessionInfo` |
| `request_uuid` echo correlation, retry on mismatch | `com/tesla/messagedecoding/RoutableMessageDecoder.java:1260` | `sendDirectCommandWithApi` uuid check |
| `FLAG_ENCRYPT_RESPONSE` = `1 << 1 = 2` | `fd0/C17261f.java:310-315` | `FLAG_ENCRYPT_RESPONSE_BIT` |
| Per-VIN per-domain queue | `be0/C3782l.java:63-82` ConcurrentHashMap<vin, deque> | `state.js _queues` |
| Lazy per-screen state load (no auto-fetch on connect) | `C14237n1.java:1423-1445` connectionEstablished does auth + device-info, not state | `_postVinSetup` is empty by design |
| In-session piggyback for state-changing commands | Their per-screen lazy pattern, we map "screen visit" to "command on that screen" | `_directDo` `opts.piggybackState` |
| Per-card refresh icons | UI affordance for the lazy-load pattern | stat-tile-refresh in `index.html` |

## What we deliberately did NOT copy

- **Their Redux cloud-backed local store.** Tesla's state appears
  populated because their cloud has synced it from the car. We have no
  cloud — `localStorage` (`VehicleState`) is our equivalent, populated
  by user-driven refresh + in-session piggybacks after commands.
- **Their full sealed Result hierarchy in
  `RoutableMessageDecoder.Result`.** Tesla has ~23 error subtypes + 17
  success subtypes flowing through a tag-dispatch evaluator. We use a
  fault-code policy function with three categories
  (`session-stale` / `transient` / `semantic`) and a switch on
  `action.domain` for response decode. ~10× less code, same behavior
  for the cases we actually encounter.
- **Their JVM-Java implementation.** They had the manpower for three
  implementations (Go SDK, JVM Android, presumably Swift iOS); we run
  the same TS in browser + RN via existing polyfills.
- **Other RoutableMessage flag bits** (`FLAG_SUPPORTS_MESSAGE_FRAMING`,
  `FLAG_COMPRESSED_ZLIB`). Tesla's builder
  (`fd0/C17261f.java:310-315`) only OR's `FLAG_ENCRYPT_RESPONSE` in the
  code paths we inspected; we match.

## The retry policy table

When a command comes back with `operationStatus != OK`,
`evaluateFault(fault)` is called and returns one of:

```
session-stale   → refresh session (in-place), retry. 0ms delay.
transient       → wait, retry. 100ms delay.
semantic        → surface to user, stop. 0ms delay.
```

| Fault code | Name | Category |
|---|---|---|
| 0 | NONE | (success) |
| 1 | BUSY | transient |
| 2 | TIMEOUT | transient |
| 3 | UNKNOWN_KEY_ID | semantic |
| 4 | INACTIVE_KEY | session-stale |
| 5 | INVALID_SIGNATURE | session-stale |
| 6 | INVALID_TOKEN_OR_COUNTER | session-stale |
| 7 | INSUFFICIENT_PRIVILEGES | semantic |
| 8 | INVALID_DOMAINS | semantic |
| 9 | INVALID_COMMAND | semantic |
| 10 | DECODING | semantic |
| 11 | INTERNAL | transient |
| 12 | WRONG_PERSONALIZATION | semantic |
| 13 | BAD_PARAMETER | semantic |
| 14 | KEYCHAIN_IS_FULL | semantic |
| 15 | INCORRECT_EPOCH | session-stale |
| 16 | IV_INCORRECT_LENGTH | semantic |
| 17 | TIME_EXPIRED | session-stale |
| 18 | NOT_PROVISIONED | semantic |
| 19 | COULD_NOT_HASH_METADATA | semantic |
| 28 | REQUIRES_RESPONSE_ENCRYPTION | semantic (we set the flag now) |

`MAX_BLE_ATTEMPTS = 10` per Tesla's `m99481a(BLE)`. Beyond that the
user gets `[label] exhausted 10 retries`.

## The session lifecycle, end-to-end

1. **First connect:** user pastes URL + bearer; `loadKeyState` reads
   the device keypair from IDB (or `generateDeviceKey` creates one);
   `connect` health-checks the Pi and writes localStorage cfg.

2. **First command:**
   - `_directDo` → `queue.enqueue` → `withCachedSession`.
   - In-memory cache empty AND IDB has no metadata for this (vin, domain).
   - Falls through to `openDirectSession`: POST /sessions (BLE
     scan+connect, 2-15s cold), then SessionInfoRequest exchange to
     get the car's ephemeral pubkey + counter + epoch + clockTime.
   - Derive AES key via ECDH→SHA1. Verify SessionInfo HMAC.
   - Persist `{vehiclePub, counter, epoch, clockBase, sessionId,
     routingAddress, myPubRaw, localBaselineMs}` to IDB.
   - Send the encrypted command. Decrypt response.

3. **Subsequent commands (warm session):** memory cache hit, ~200ms
   round-trip per command.

4. **Page reload:** memory cleared. Next command's `withCachedSession`
   finds IDB metadata, hydrates session in memory (re-derives AES key
   from local private + persisted vehiclePub), uses existing piSessionId.
   First command after reload is ~200ms, not a full handshake.

5. **Pi-side BLE link still alive (within 5min reaper):** hydration
   succeeds; commands work immediately.

6. **Pi rebooted or BLE link reaped:** hydration succeeds but first
   `/exchange` returns "session not found". `withCachedSession` doesn't
   currently distinguish this from a network error — it propagates the
   exception. The retry loop in `_directDo` evaluates the fault
   (transient via TIMEOUT, or session-stale via INVALID_SIGNATURE on
   the next attempt) and recovers; the recovery path may include a full
   handshake. **TODO:** detect 404 explicitly on session-not-found and
   short-circuit to a full handshake.

7. **Car-side key rotation (epoch flip, counter reset):** command comes
   back `INVALID_TOKEN_OR_COUNTER` or `INCORRECT_EPOCH`.
   `evaluateFault` returns `session-stale`. `refreshCachedSession`
   sends a fresh `SessionInfoRequest` on the SAME warm BLE session;
   car returns a new SessionInfo; we update keying material in place
   and retry the original command. ~1 round-trip total recovery,
   invisible to the user.

## The activity log

Every `_directDo` attempt records one entry to localStorage. Schema:

```json
{
  "at": 1717250000000,
  "label": "lock",
  "result": "ok|retry|refresh|error|event",
  "domain": 2,
  "attempt": 1,
  "fault": 5,
  "durationMs": 230,
  "vin": "5YJ...",
  "note": "INVALID_SIGNATURE"
}
```

Ring buffer, 100 entries, ~20KB. Visible inline on the page via the
"Activity log" card. "Copy as JSON" puts a paste-able dump on the
clipboard. Survives reload. Use it when something at the car
misbehaves — paste the relevant rows into chat instead of trying to
capture DevTools.

## What's tested (`state-test.html`)

46 in-browser tests covering: VehicleState persistence + load
round-trip + legacy-format compat; `applyVcsecStatus` with enum
translation + closures-intent grace; `applyCarServerResponse` for
charge/climate/drive/location/sentry/windows with oneof normalization;
`applyOptimistic` slice writes; `SessionQueue` FIFO + error tolerance;
`schedulePiggyback` debounce + coalesce + no-auto-upgrade; mocked
`vcsecSync`/`awakeSync` with real proto encode/decode;
`refreshCachedSession` no-cached-session fallback;
real-path `sendDirectCommandWithApi` round-trip;
`evaluateFault` full table; `activity-log` round-trip and ring-buffer
trim.

Run via:
```bash
cd client && python3 -m http.server 8765
# then visit http://localhost:8765/state-test.html
```

Or headless:
```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless --disable-gpu --virtual-time-budget=20000 \
  --dump-dom http://127.0.0.1:8765/state-test.html | grep -oE 'badge (pass|fail)' | sort | uniq -c
```

## Known holes worth fixing later

1. **Pi-side session-not-found should fast-path to full handshake**
   rather than going through the retry policy's transient/session-stale
   branches. A 404 from POST /sessions/{id}/exchange is unambiguous.

2. **Multi-tab racing on the same VIN.** Both tabs hydrate from the
   same IDB row and increment their own counters. One will hit
   `INVALID_TOKEN_OR_COUNTER` first, trigger reactive refresh, and the
   other tab's next command will too. Recoverable but visible. Could
   coordinate via BroadcastChannel.

3. **Closure-sensor freshness.** VCSEC's Hall sensors lag by minutes.
   The closure tile shows the timestamp; stale (>5 min) gets a yellow
   dot. Real fix is to ask Infotainment for closures state (live, but
   requires console awake) — that's what the global Refresh button
   does.

4. **`FETCHING_SESSION_INFO` per-slice UI badge.** Currently the
   global `directStatus` line shows "refreshing session…" during a
   stale-fault recovery. A per-slice spinner would be nicer but
   requires more invasive UI plumbing.

5. **No formal decoder Result type.** Our fault-code switch is
   functionally complete but doesn't mirror Tesla's
   `RoutableMessageDecoder.Result.AbstractC14110a.{a..x}` hierarchy.
   The cost of refactoring is significant for low marginal value at
   our scale; if the protocol gets harder to extend this is the first
   thing to add.
