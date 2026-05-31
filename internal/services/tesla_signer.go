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
	"fmt"
	"os"
	"path/filepath"

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

// Key loads the keyfile if present, generates + writes one otherwise.
// The file is SEC1 PEM ("EC PRIVATE KEY"), the same shape the SDK's
// SavePrivateKey produces — so protocol.LoadPrivateKey reads it back
// without ceremony.
func (s *localFileSigner) Key() (protocol.ECDHPrivateKey, error) {
	if _, err := os.Stat(s.path); err == nil {
		return protocol.LoadPrivateKey(s.path)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir key dir: %w", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return nil, fmt.Errorf("marshal EC key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(s.path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	return protocol.LoadPrivateKey(s.path)
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
