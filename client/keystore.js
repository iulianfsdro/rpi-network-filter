// keystore.js — device-key persistence + crypto.subtle helpers.
//
// V4.4 Phase 3a. The client owns its own long-term P-256 keypair from
// here on. WebCrypto generates it with `extractable: false`, IndexedDB
// stores the live CryptoKey objects (NOT JWK / NOT raw bytes — the
// private key must never round-trip through JS-visible memory). The
// OS-level key store backs IndexedDB on Safari/Chrome; the private
// scalar is unreachable to any JS, including this app's own.
//
// Public-key extraction stays available — `extractable: false` only
// applies to the private half. The pubkey is exported as raw SEC1
// (uncompressed point, 65 bytes: 0x04 || X || Y), the same shape the
// Tesla SDK's `ecdh.P256().NewPublicKey(...)` accepts, so the Pi can
// forward it to SendAddKeyRequest without further conversion.
//
// Phase 3c will add the matching ECDH(peer_pub) → derive → AES-GCM
// session-key path on top of this same keypair. The private key never
// leaves WebCrypto; even the derived session bytes will be opaque
// CryptoKey handles, not raw secrets.

const DB_NAME = 'airgap';
const DB_VERSION = 1;
const KEY_STORE = 'keys';
const KEY_ID = 'tesla-device-key';

// openDB is intentionally tiny — we only ever read/write one keyed
// record. No migrations to worry about (yet); if v2 ever happens we
// branch on event.oldVersion in onupgradeneeded.
async function openDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = () => {
            req.result.createObjectStore(KEY_STORE);
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

// generateDeviceKey produces a fresh P-256 ECDH keypair. The private
// half is non-extractable: `crypto.subtle.exportKey` will refuse to
// serialise it; `wrapKey` will refuse to wrap it; no API path returns
// the raw scalar. Usages are ECDH only — we never sign Schnorr from
// the client (the Tesla protocol's SchnorrSignature path is rarely
// exercised and not on the per-command hot path; Phase 3c will route
// any such requests through the Pi's existing pubkey enrolment if
// they're ever needed).
async function generateDeviceKey() {
    return crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits', 'deriveKey']
    );
}

// loadDeviceKey returns the persisted CryptoKeyPair if one exists,
// or null if the device hasn't been initialised yet. The CryptoKey
// objects come back live — usable directly with crypto.subtle.
async function loadDeviceKey() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(KEY_STORE, 'readonly');
        const req = tx.objectStore(KEY_STORE).get(KEY_ID);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
    });
}

// saveDeviceKey persists a freshly-generated keypair. Overwrites any
// existing record under KEY_ID, so the caller is responsible for
// confirming "rotate?" intent before invoking.
async function saveDeviceKey(kp) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(KEY_STORE, 'readwrite');
        tx.objectStore(KEY_STORE).put(kp, KEY_ID);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

// deleteDeviceKey wipes the persisted keypair. Called from "rotate"
// (with confirm) and from "forget this Pi" (so credentials don't
// outlive an enrolment).
async function deleteDeviceKey() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(KEY_STORE, 'readwrite');
        tx.objectStore(KEY_STORE).delete(KEY_ID);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

// exportPubkeyRaw returns the 65-byte SEC1 uncompressed point for the
// given public CryptoKey. Suitable for direct base64-then-POST to the
// Pi's /api/ble/pair/external-pubkey endpoint.
async function exportPubkeyRaw(pubKey) {
    const buf = await crypto.subtle.exportKey('raw', pubKey);
    return new Uint8Array(buf);
}

// fingerprintHex produces a short, stable identifier for a public key
// — SHA-256 of the raw bytes, truncated to 8 hex bytes. Used in UI for
// "this is the key currently enrolled" so the operator can tell two
// rotations apart at a glance.
async function fingerprintHex(rawPubKey) {
    const h = await crypto.subtle.digest('SHA-256', rawPubKey);
    const bytes = new Uint8Array(h).slice(0, 8);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(':');
}

// bytesToBase64 / base64ToBytes are the obvious helpers — no
// dependencies, no edge cases for the 65-byte payloads we deal with.
function bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

// Surface the API on `window` so app.js can pick it up without a
// module loader. Keeping the bundle build-step-free is a deliberate
// choice for the v0 client.
window.airgap = window.airgap || {};
Object.assign(window.airgap, {
    generateDeviceKey,
    loadDeviceKey,
    saveDeviceKey,
    deleteDeviceKey,
    exportPubkeyRaw,
    fingerprintHex,
    bytesToBase64,
    base64ToBytes,
});
