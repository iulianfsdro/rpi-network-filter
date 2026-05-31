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

// ── Tesla metadata block (Phase 3c-2) ──
//
// Every signed/encrypted message authenticates a sorted list of
// (tag, value) pairs that name the message: signature type, domain,
// recipient (VIN), epoch, expiry, counter. The serialisation is
// strict — tags MUST be ascending, lengths MUST be ≤ 255 bytes — and
// is hashed (SHA-256) to produce the AES-GCM AAD. A MITM that tampers
// with any of these fields breaks the AAD digest and AES-GCM rejects
// the ciphertext on decrypt.
//
// Mirrors authentication/metadata.go. The (tag || length || value)
// framing is verbatim; TAG_END = 0xff appended once at the close.

// Tags — values from signatures.proto (signatures.Tag_*). Kept here
// as a named enum so callsites read like the SDK.
const TAG = Object.freeze({
    SIGNATURE_TYPE:  0,
    DOMAIN:          1,
    PERSONALIZATION: 2,
    EPOCH:           3,
    EXPIRES_AT:      4,
    COUNTER:         5,
    CHALLENGE:       6,
    FLAGS:           7,
    REQUEST_HASH:    8,
    FAULT:           9,
    END:           255,
});

// SignatureType enum values, also from signatures.proto. Phase 3c
// uses AES_GCM_PERSONALIZED for commands and HMAC for session-info
// handshake.
const SIGNATURE_TYPE = Object.freeze({
    AES_GCM:              0,
    AES_GCM_PERSONALIZED: 5,
    HMAC:                 6,
    HMAC_PERSONALIZED:    8,
    AES_GCM_RESPONSE:     9,
});

const DOMAIN = Object.freeze({
    BROADCAST:        0,
    VEHICLE_SECURITY: 2,
    INFOTAINMENT:     3,
});

// MetadataBlockBuilder accumulates (tag, value) pairs and renders the
// final byte buffer. Stateful so the caller can assemble it
// imperatively; matches the SDK's metadata type. Throws on
// out-of-order tags (a programmer error — would break wire compat
// silently if allowed).
class MetadataBlockBuilder {
    constructor() {
        this.parts = [];
        this.lastTag = -1;
    }
    add(tag, value) {
        if (tag < this.lastTag) {
            throw new Error(`metadata tag ${tag} added after ${this.lastTag} (must be ascending)`);
        }
        if (value == null) return this; // nullable — matches SDK
        if (value.length > 255) {
            throw new Error(`metadata value for tag ${tag} is ${value.length} bytes (max 255)`);
        }
        this.lastTag = tag;
        this.parts.push(new Uint8Array([tag, value.length]));
        this.parts.push(value);
        return this;
    }
    addUint32(tag, v) {
        const buf = new Uint8Array(4);
        new DataView(buf.buffer).setUint32(0, v >>> 0, false); // big-endian
        return this.add(tag, buf);
    }
    // bytes returns the encoded block WITHOUT the trailing TAG_END.
    // Internal — checksum() is what production code calls.
    bytes() {
        let total = 0;
        for (const p of this.parts) total += p.length;
        const out = new Uint8Array(total);
        let off = 0;
        for (const p of this.parts) { out.set(p, off); off += p.length; }
        return out;
    }
    // checksum returns SHA-256( bytes() || 0xff || trailing ). The
    // trailing arg is the message payload for cases where the SDK
    // appends the to-be-authenticated message after TAG_END (the
    // session-info HMAC path); pass null for the standard AES-GCM
    // AAD case.
    async checksum(trailing) {
        const head = this.bytes();
        const t = trailing || new Uint8Array(0);
        const total = new Uint8Array(head.length + 1 + t.length);
        total.set(head, 0);
        total[head.length] = TAG.END;
        total.set(t, head.length + 1);
        const digest = await crypto.subtle.digest('SHA-256', total);
        return new Uint8Array(digest);
    }
}

// buildAesGcmMetadata is the canonical builder for an AES-GCM
// command's metadata. Fields are required by the SDK in this order;
// flags is only added if > 0 (matches the SDK's "for backwards
// compatibility" behaviour).
async function buildAesGcmMetadata({ domain, verifierName, epoch, expiresAt, counter, flags }) {
    const m = new MetadataBlockBuilder();
    m.add(TAG.SIGNATURE_TYPE, new Uint8Array([SIGNATURE_TYPE.AES_GCM_PERSONALIZED]));
    m.add(TAG.DOMAIN,         new Uint8Array([domain]));
    m.add(TAG.PERSONALIZATION, typeof verifierName === 'string'
        ? new TextEncoder().encode(verifierName) : verifierName);
    m.add(TAG.EPOCH,          epoch);
    m.addUint32(TAG.EXPIRES_AT, expiresAt);
    m.addUint32(TAG.COUNTER,    counter);
    if (flags && flags > 0) m.addUint32(TAG.FLAGS, flags);
    return await m.checksum(null);
}

// aesGcmEncrypt encrypts plaintext under sessionKey with the given
// AAD digest. Generates a fresh 12-byte nonce per call (the SDK does
// the same with crypto/rand). Returns the parts the SDK's wire
// envelope expects separately: { nonce, ciphertext, tag } — the
// Tesla protocol stores them in distinct protobuf fields rather than
// the typical "ct || tag" concatenation.
async function aesGcmEncrypt(sessionKey, plaintext, aadDigest) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aadDigest, tagLength: 128 },
        sessionKey, plaintext,
    ));
    // crypto.subtle returns ct||tag; the wire format wants them split.
    const ctLen = sealed.length - 16;
    return {
        nonce,
        ciphertext: sealed.slice(0, ctLen),
        tag:        sealed.slice(ctLen),
    };
}

// aesGcmEncryptWithNonce is the deterministic version for testing —
// caller supplies the nonce. Production code MUST NOT reuse nonces
// under the same key; AES-GCM loses confidentiality and integrity
// catastrophically on nonce reuse.
async function aesGcmEncryptWithNonce(sessionKey, plaintext, aadDigest, nonce) {
    const sealed = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aadDigest, tagLength: 128 },
        sessionKey, plaintext,
    ));
    const ctLen = sealed.length - 16;
    return {
        nonce,
        ciphertext: sealed.slice(0, ctLen),
        tag:        sealed.slice(ctLen),
    };
}

// aesGcmDecrypt reverses the envelope. Throws on tag mismatch (which
// also covers any AAD tampering — the SDK collapses both into a
// single "invalid signature" error).
async function aesGcmDecrypt(sessionKey, nonce, ciphertext, tag, aadDigest) {
    // Reassemble ct||tag for crypto.subtle.
    const sealed = new Uint8Array(ciphertext.length + tag.length);
    sealed.set(ciphertext, 0);
    sealed.set(tag, ciphertext.length);
    const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aadDigest, tagLength: 128 },
        sessionKey, sealed,
    );
    return new Uint8Array(pt);
}

// hmacSubkey derives a label-specific HMAC key from the raw session
// bytes. SDK: subkey(label) = HMAC-SHA256(sessionKey, label). Used
// for the session-info handshake — the AES-GCM key proper is what
// encrypts commands.
//
// keyBytes is the 16-byte AES-GCM session key (raw Uint8Array, not a
// CryptoKey — HMAC needs a different importKey path). Tests use this
// directly; production code wraps it in deriveSessionInfoHmacKey.
async function hmacSubkey(keyBytes, label) {
    const k = await crypto.subtle.importKey(
        'raw', keyBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false, ['sign'],
    );
    const tag = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(label));
    return new Uint8Array(tag);
}

Object.assign(window.airgap, {
    importPeerPubkey,
    deriveSessionKey,
    deriveSessionKeyMaterial,
    bytesToHex,
    hexToBytes,
    TAG,
    SIGNATURE_TYPE,
    DOMAIN,
    MetadataBlockBuilder,
    buildAesGcmMetadata,
    aesGcmEncrypt,
    aesGcmEncryptWithNonce,
    aesGcmDecrypt,
    hmacSubkey,
});
