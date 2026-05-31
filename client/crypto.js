// crypto.js — Tesla BLE session crypto, ported to crypto.subtle.
//
// V4.4 Phase 3c (foundation). Phase 3 of the BLE-key rearchitecture
// moves the long-term ECDH key from the Pi to the client; this file
// is what makes the *session* key live on the client too.
//
// Phase 3a: client generates its own keypair (extractable:false).
// Phase 3b: Pi forwards opaque bytes between client and BLE radio.
// Phase 3c (here): client derives the AES-GCM session key locally
//                  from its private key and the car's ephemeral pubkey
//                  (delivered via Pi inside SessionInfo bytes).
// Phase 3c (next commits): wire encrypt/decrypt + HMAC counter onto
//                          this session key; build the RoutableMessage
//                          codec; run one command end-to-end.
//
// ── Tesla's KDF, exactly as the SDK does it ──
//
//   1. ECDH(my_priv_d, car_eph_pub) → shared X coordinate (32 bytes,
//      big-endian, zero-padded if the integer is shorter than 256
//      bits). WebCrypto's deriveBits with the ECDH algorithm returns
//      exactly this — same wire format the SDK's
//      `elliptic.P256().ScalarMult` produces with FillBytes.
//
//   2. SHA-1 over those 32 bytes → 20 bytes.
//
//   3. First 16 bytes of the SHA-1 digest → AES-128-GCM key.
//
// The SHA-1 here is NOT for collision resistance — it's a fixed-output
// PRG that compresses the shared secret into the AES key. The SDK
// comment is explicit about this: "collision resistance isn't needed."
// We can't change it without breaking interop with the car firmware.

window.airgap = window.airgap || {};

// importPeerPubkey wraps the raw 65-byte SEC1 uncompressed point
// (0x04 || X || Y) that comes back from the car inside a SessionInfo
// message. Marked non-extractable + zero usages — we only ever pass
// it as the `public` arg to deriveBits, never serialise it again.
async function importPeerPubkey(rawSec1Bytes) {
    if (rawSec1Bytes.length !== 65 || rawSec1Bytes[0] !== 0x04) {
        throw new Error(`expected 65-byte SEC1 uncompressed point (0x04 || X || Y), got ${rawSec1Bytes.length} bytes${rawSec1Bytes.length ? ` starting 0x${rawSec1Bytes[0].toString(16)}` : ''}`);
    }
    return crypto.subtle.importKey(
        'raw', rawSec1Bytes,
        { name: 'ECDH', namedCurve: 'P-256' },
        false, []
    );
}

// deriveSessionKeyMaterial returns the raw 16-byte AES-GCM key as a
// Uint8Array. Internal helper used by deriveSessionKey + the test
// harness (which needs to compare bytes against a known vector).
//
// The split exists because crypto.subtle.importKey('raw', …) wraps
// the bytes in an opaque CryptoKey — once we go through that gate
// there's no way to inspect what we have. Tests need to see the
// bytes; production code never should.
async function deriveSessionKeyMaterial(myPrivCryptoKey, peerPubCryptoKey) {
    // ECDH gives back the shared X coordinate as raw bytes — the
    // same 32-byte big-endian value Go's ScalarMult+FillBytes
    // produces. 256 bits = exactly 32 bytes; no length surprise.
    const sharedBytes = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: peerPubCryptoKey },
        myPrivCryptoKey,
        256
    );
    const digest = await crypto.subtle.digest('SHA-1', sharedBytes);
    return new Uint8Array(digest).slice(0, 16);
}

// deriveSessionKey returns an AES-GCM CryptoKey ready for encrypt /
// decrypt. The intermediate 16 bytes never need to be visible to
// caller code — only crypto.subtle gets them, and only as input to
// importKey.
//
// Caller responsibility: pass the right peer pubkey. Tesla maintains
// SEPARATE session keys per domain (VCSEC vs Infotainment) — each
// domain's SessionInfo contains its own ephemeral pubkey, so derive
// one key per domain and don't mix them.
async function deriveSessionKey(myPrivCryptoKey, peerPubCryptoKey) {
    const keyBytes = await deriveSessionKeyMaterial(myPrivCryptoKey, peerPubCryptoKey);
    return crypto.subtle.importKey(
        'raw', keyBytes,
        { name: 'AES-GCM' },
        false, ['encrypt', 'decrypt']
    );
}

// bytesToHex / hexToBytes are crypto-adjacent helpers. Kept here so
// the test harness can render derived bytes for visual inspection.
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
    const clean = hex.replace(/\s+/g, '');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
}

Object.assign(window.airgap, {
    importPeerPubkey,
    deriveSessionKey,
    deriveSessionKeyMaterial,
    bytesToHex,
    hexToBytes,
});
