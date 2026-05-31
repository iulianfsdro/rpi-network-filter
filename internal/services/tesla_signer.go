// tesla_signer.go — the BLE-key abstraction seam.
//
// V4.4 sets up the rearchitecture in which the long-term BLE ECDH key
// will eventually live on the operator's device (laptop / phone PWA /
// native app), not the Pi. The Pi will become a pure BLE byte-forwarder:
// it receives the car's SessionInfo, forwards it to the client, and the
// client's WebCrypto runtime does Exchange (P-256 ECDH) + AES-GCM
// session crypto. The Pi never sees a private scalar.
//
// This file is Phase 0 — the seam. It introduces TeslaSigner so every
// place in services/tesla.go that needs the key goes through one
// interface. The default implementation (localFileSigner) is bit-for-bit
// what the code did before: load-or-generate a SEC1 PEM on disk at
// teslaKeyPath. No behaviour change. The Phase-3 RemoteSigner will plug
// into the same interface and the calls don't have to know.
package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/teslamotors/vehicle-command/pkg/protocol"
)

// TeslaSigner produces the ECDHPrivateKey used for BLE session
// establishment + the public-key material the operator pastes into the
// Tesla mobile app for enrolment. Two implementations planned:
//
//   - localFileSigner   — Phase 0/1/2. Long-term key on the Pi disk.
//     What the codebase has always done. The default until the client
//     app exists.
//
//   - remoteSigner       — Phase 3. ECDH + Schnorr are forwarded to the
//     operator's enrolled device over the byte-forwarder API; the Pi
//     proxies the question and waits for a signed answer. The Pi never
//     holds a private scalar.
//
// Per Tesla's BLE protocol the long-term key is touched exactly twice
// per BLE session (one ECDH per CarServer/VCSEC domain to derive an
// AES-GCM session key). Everything else for the duration of the session
// — every command, every state read — runs on that session key, which
// is short-lived and per-connection. That keeps the remote-signer path
// from being chatty.
type TeslaSigner interface {
	// Key returns the underlying SDK ECDHPrivateKey. The localFileSigner
	// reads/generates on disk; the remoteSigner will return a stub key
	// whose Exchange() rountrips to the client.
	Key() (protocol.ECDHPrivateKey, error)

	// PublicKeyPEM returns the operator's public key as a PKIX-encoded
	// PEM block — the form the Tesla mobile app expects in "Add Key".
	PublicKeyPEM() (string, error)
}

// localFileSigner persists the BLE long-term key as a SEC1 PEM file at
// path, mode 0600, root-owned. On first call (file absent) it generates
// a fresh P-256 key, writes it, and returns it. Same wire behaviour as
// the previous TeslaService.loadOrGenerateKey — lifted out so a future
// remote signer can replace it without touching call sites.
type localFileSigner struct {
	path string
}

// NewLocalFileSigner wires a localFileSigner against the given on-disk
// path. teslaKeyPath is the conventional default.
func NewLocalFileSigner(path string) *localFileSigner {
	return &localFileSigner{path: path}
}

// ErrPiKeyDisabled is returned by Key() when no key file exists on
// disk. V4.4 Phase 4: the Pi must never auto-generate a signing key
// because the architecture has the operator's device own its own
// non-extractable WebCrypto P-256 keypair, and command crypto runs
// entirely on the client through /api/ble/sessions.
//
// Handlers that surface this error should redirect users to the
// client app rather than retrying.
var ErrPiKeyDisabled = errors.New("Pi-resident BLE key is disabled — use the client app's /api/ble/sessions path instead")

// Key loads the keyfile if present. **V4.4 Phase 4: no longer
// auto-generates.** Pre-V4.4 deployments may still have a file on
// disk and this method continues to serve them. New installs (and
// installs where the operator has wiped the file) return
// ErrPiKeyDisabled — the client owns the long-term key from then on.
func (s *localFileSigner) Key() (protocol.ECDHPrivateKey, error) {
	if _, err := os.Stat(s.path); err == nil {
		return protocol.LoadPrivateKey(s.path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	return nil, ErrPiKeyDisabled
}

// EphemeralSigner generates a fresh in-memory P-256 keypair on every
// Key() call. Never persists, never returns the same key twice. Used
// by sendUnauthenticated paths (currently only the SendAddKeyRequest
// enrolment of an external client pubkey) where the SDK requires a
// priv arg to construct *vehicle.Vehicle but doesn't actually consult
// it for the unauthenticated transport handshake.
//
// V4.4 Phase 4 makes localFileSigner refuse to auto-generate, which
// is correct for command-time signing — but the pairing flow still
// needs *some* key value to satisfy NewVehicle's signature. An
// ephemeral throwaway threads that needle: the Pi never persists it,
// it never gets enrolled with any car, and it dies when the function
// returns.
type EphemeralSigner struct{}

// NewEphemeralSigner wires a zero-state signer.
func NewEphemeralSigner() *EphemeralSigner { return &EphemeralSigner{} }

// Key produces a fresh P-256 keypair each call and returns it as a
// protocol.ECDHPrivateKey. Goes through UnmarshalECDHPrivateKey with
// the raw scalar so we don't have to round-trip through PEM.
func (s *EphemeralSigner) Key() (protocol.ECDHPrivateKey, error) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key gen: %w", err)
	}
	scalar := ecKey.D.FillBytes(make([]byte, 32))
	priv := protocol.UnmarshalECDHPrivateKey(scalar)
	if priv == nil {
		return nil, fmt.Errorf("unmarshal ephemeral key returned nil")
	}
	return priv, nil
}

// PublicKeyPEM is meaningless for an ephemeral signer — each call
// would return a different pubkey. Returns an error so callers don't
// silently use a key the next call won't recognise.
func (s *EphemeralSigner) PublicKeyPEM() (string, error) {
	return "", fmt.Errorf("ephemeral signer has no stable public key")
}

// PublicKeyPEM returns the matching public key as a PKIX-encoded PEM
// block. The SDK stores the public key inside ECDHPrivateKey as raw
// SEC1 bytes (uncompressed point); we re-marshal it through ecdsa +
// x509 to the PKIX shape because that's what the Tesla mobile app's
// Add-Key flow expects.
func (s *localFileSigner) PublicKeyPEM() (string, error) {
	priv, err := s.Key()
	if err != nil {
		return "", err
	}
	pubBytes := priv.PublicBytes()
	if len(pubBytes) == 0 {
		return "", fmt.Errorf("private key produced empty public bytes")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pubBytes)
	if x == nil {
		return "", fmt.Errorf("public key bytes are not a valid P-256 point")
	}
	pubEC := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	der, err := x509.MarshalPKIXPublicKey(pubEC)
	if err != nil {
		return "", fmt.Errorf("marshal PKIX: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
