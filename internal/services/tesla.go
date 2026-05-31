// Package-level Tesla BLE service — V4.4 Phase 4 / Thread A purge.
//
// What's left here after the rearchitecture:
//
//   • VIN / SetVIN — the one Tesla-related config the Pi still tracks.
//     The BLE scanner needs to know which advertisement to match, and
//     the client uses the same VIN as the personalization field in its
//     AES-GCM AAD. Stored in the settings table.
//
//   • Pairing state probe — IsPaired tells the client/UI whether a
//     previous enrolment landed. Cheap DB lookup.
//
//   • RequestPairingExternal — enrols a CALLER-supplied P-256 pubkey
//     on the car. Uses an EphemeralSigner to satisfy the SDK's
//     NewVehicle API without resurrecting any Pi-resident key.
//
//   • AcquireBLEForVIN — the entry point the byte-forwarder API
//     (BLESessionService) uses to grab the BLE adapter for a session.
//     Holds the adapter mutex; caller closes via the returned release.
//
//   • sendUnauthenticated — internal helper underlying
//     RequestPairingExternal. Now takes a TeslaSigner argument so the
//     caller picks what key satisfies the SDK signature (ephemeral
//     for new enrolments, localFileSigner for legacy paths that still
//     have a file on disk).
//
//   • CommandLog — read-only audit trail.
//
// Everything else the file used to do — per-command methods
// (Lock / Unlock / Honk / climate / closures / …), the background
// poller, snapshot caching, closure assertions, withVCSEC /
// withInfotainment helpers — is gone. The Pi no longer holds a
// signing key so those paths can't function; the client app at
// client/index.html owns the Tesla UI now, with its own crypto.
package services

import (
	"context"
	"crypto/ecdh"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/connector/ble"
	keysproto "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/keys"
	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/vcsec"
	"github.com/teslamotors/vehicle-command/pkg/vehicle"
)

const (
	// teslaKeyPath is where pre-V4.4 deployments persisted a Pi-resident
	// signing key. Phase 4 makes localFileSigner refuse to auto-generate;
	// the path stays a constant only so legacy deployments with a file
	// on disk continue to load it (the file is unused after Phase 4 but
	// not deleted automatically). New installs never create this file.
	teslaKeyPath = "/var/lib/netfilterd/tesla/private_key.pem"

	// teslaBLEAdapter is the Linux HCI device name. Pi 4/5 has a single
	// built-in BLE radio on hci0; a USB BLE dongle would land at hci1.
	teslaBLEAdapter = "hci0"

	// teslaScanTimeout caps how long ScanVehicleBeacon waits for an
	// advertisement. Tesla beacons broadcast every ~100ms while awake;
	// 15s is a comfortable upper bound even if the car is asleep.
	teslaScanTimeout = 15 * time.Second
)

// adapterInitMu + adapterInitOK gate ble.InitAdapterWithID. Two
// constraints to honour:
//
//   1. go-ble panics if InitAdapterWithID is called twice in the same
//      process when the prior call succeeded — so we must remember
//      success and skip the second call.
//   2. The first call CAN fail transiently (rfkill not yet unblocked,
//      bluetoothd not yet running, race during early boot). A sync.Once
//      would freeze that failure for the process lifetime, breaking
//      every later scan even after the environment recovers. We retry
//      on failure instead.
//
// Net: take the mutex, init only if we haven't already succeeded,
// surface the latest error if any.
var (
	adapterInitMu sync.Mutex
	adapterInitOK bool
)

// TeslaService is the slimmed-down post-Phase-4 service. The bleMu
// serialises every BLE adapter operation; Linux can only host one
// HCI client at a time and the SDK's session handshake isn't designed
// for interleaving.
type TeslaService struct {
	db      *sql.DB
	audit   *AuditService
	signer  TeslaSigner
	adapter string
	bleMu   sync.Mutex
}

// NewTeslaService wires the service. No poller — the Pi can't read
// state without a signing key, and we don't have one.
func NewTeslaService(db *sql.DB, audit *AuditService) *TeslaService {
	return &TeslaService{
		db:      db,
		audit:   audit,
		signer:  NewLocalFileSigner(teslaKeyPath),
		adapter: teslaBLEAdapter,
	}
}

// ── Pairing state ────────────────────────────────────────────────

// PublicKeyPEM delegates to the configured TeslaSigner. Returns the
// PKIX-PEM public key if a Pi key file happens to be on disk (legacy);
// returns an error / empty string on a Phase-4-clean Pi.
func (s *TeslaService) PublicKeyPEM() (string, error) {
	return s.signer.PublicKeyPEM()
}

// IsPaired returns true if tesla_pairing has a paired_at row for the
// configured VIN. Cheap (one SELECT).
func (s *TeslaService) IsPaired() bool {
	vin := s.VIN()
	if vin == "" {
		return false
	}
	var paired int
	err := s.db.QueryRow(
		`SELECT 1 FROM tesla_pairing WHERE vin = ? AND paired_at IS NOT NULL`,
		vin,
	).Scan(&paired)
	return err == nil && paired == 1
}

// RequestPairingExternal enrols a client-supplied P-256 public key on
// the car. The client (laptop, phone PWA) generated a non-extractable
// WebCrypto keypair on first run; here it ships the public half so
// the car adds it to its owner-key list. The operator finishes by
// tapping their NFC card on the centre console.
//
// pubKeyRawSEC1 is the 65-byte uncompressed point (0x04 || X || Y) —
// the format crypto.subtle's exportKey('raw', ecdhPubKey) produces.
//
// Internally uses an EphemeralSigner because the unauthenticated
// transport handshake doesn't consult the priv argument; we just need
// SOMETHING to give NewVehicle.
func (s *TeslaService) RequestPairingExternal(ctx context.Context, pubKeyRawSEC1 []byte) error {
	// Validate input shape FIRST — cheap, deterministic. Otherwise a
	// missing VIN masks a real "your pubkey is malformed" error and
	// the operator gets a misleading hint.
	if len(pubKeyRawSEC1) != 65 || pubKeyRawSEC1[0] != 0x04 {
		return fmt.Errorf("invalid SEC1 uncompressed P-256 point (expected 65 bytes starting 0x04, got %d bytes)", len(pubKeyRawSEC1))
	}
	pubKey, err := ecdh.P256().NewPublicKey(pubKeyRawSEC1)
	if err != nil {
		return fmt.Errorf("parse external public key: %w", err)
	}
	vin, err := s.requireVIN()
	if err != nil {
		return err
	}
	return s.sendUnauthenticated(ctx, vin, NewEphemeralSigner(), func(car *vehicle.Vehicle) error {
		return car.SendAddKeyRequestWithRole(
			ctx,
			pubKey,
			keysproto.Role_ROLE_DRIVER,
			vcsec.KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY,
		)
	})
}

// ── BLE adapter ──────────────────────────────────────────────────

// AcquireBLEForVIN scans for the given VIN, opens a raw BLE
// connection, and holds bleMu for the connection's lifetime. The
// returned release closure closes the connection AND releases the
// adapter mutex; the caller MUST eventually invoke it (typically via
// defer) — otherwise every subsequent BLE operation blocks forever.
//
// This is the entry point for the byte-forwarder API
// (BLESessionService).
func (s *TeslaService) AcquireBLEForVIN(ctx context.Context, vin string) (*ble.Connection, func(), error) {
	if err := initAdapter(s.adapter); err != nil {
		return nil, nil, fmt.Errorf("BLE adapter init: %w", err)
	}
	s.bleMu.Lock()

	scanCtx, scanCancel := context.WithTimeout(ctx, teslaScanTimeout)
	defer scanCancel()
	beacon, err := ble.ScanVehicleBeacon(scanCtx, vin)
	if err != nil {
		s.bleMu.Unlock()
		return nil, nil, fmt.Errorf("scan %s: %w", vin, err)
	}
	conn, err := ble.NewConnectionFromScanResult(scanCtx, vin, beacon)
	if err != nil {
		s.bleMu.Unlock()
		return nil, nil, fmt.Errorf("BLE connect %s: %w", vin, err)
	}
	release := func() {
		conn.Close()
		s.bleMu.Unlock()
	}
	return conn, release, nil
}

// RequireVIN exposes requireVIN to callers outside this file (the
// BLE session service uses it when the request body omits VIN).
func (s *TeslaService) RequireVIN() (string, error) {
	return s.requireVIN()
}

// sendUnauthenticated opens a fresh BLE connection, calls car.Connect
// (just the transport handshake), and invokes fn. Whatever fn does it
// MUST NOT call StartSession — that would fail because we're not
// establishing a signed session here.
//
// The signer arg lets the caller pass an ephemeral throwaway key.
// V4.4 Phase 4 only uses this path for SendAddKeyRequest, which is
// unauthenticated and doesn't actually consult the priv — but the
// SDK's NewVehicle demands one for type-signature reasons.
func (s *TeslaService) sendUnauthenticated(parent context.Context, vin string, signer TeslaSigner, fn func(*vehicle.Vehicle) error) error {
	if err := initAdapter(s.adapter); err != nil {
		return fmt.Errorf("BLE adapter init: %w", err)
	}

	s.bleMu.Lock()
	defer s.bleMu.Unlock()

	priv, err := signer.Key()
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	scanCtx, scanCancel := context.WithTimeout(parent, teslaScanTimeout)
	defer scanCancel()
	beacon, err := ble.ScanVehicleBeacon(scanCtx, vin)
	if err != nil {
		return fmt.Errorf("scan %s: %w", vin, err)
	}

	conn, err := ble.NewConnectionFromScanResult(scanCtx, vin, beacon)
	if err != nil {
		return fmt.Errorf("BLE connect %s: %w", vin, err)
	}
	defer conn.Close()

	car, err := vehicle.NewVehicle(conn, priv, nil)
	if err != nil {
		return fmt.Errorf("vehicle init: %w", err)
	}
	if err := car.Connect(parent); err != nil {
		return fmt.Errorf("car connect: %w", err)
	}
	return fn(car)
}

// initAdapter handles the "init only once per process, retry on
// transient failure" semantics for ble.InitAdapterWithID.
func initAdapter(name string) error {
	adapterInitMu.Lock()
	defer adapterInitMu.Unlock()
	if adapterInitOK {
		return nil
	}
	if err := ble.InitAdapterWithID(name); err != nil {
		return err
	}
	adapterInitOK = true
	return nil
}

// ── Settings (VIN) ────────────────────────────────────────────────

// VIN returns the configured Tesla VIN (set via the client app's
// "Crypto VIN" field). Empty string means "not configured".
func (s *TeslaService) VIN() string {
	var vin string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key = 'tesla_vin'`).Scan(&vin)
	return strings.TrimSpace(vin)
}

// SetVIN stores the VIN in the settings table. 17 chars, alphanumeric.
func (s *TeslaService) SetVIN(vin string) error {
	vin = strings.TrimSpace(strings.ToUpper(vin))
	if len(vin) != 17 {
		return fmt.Errorf("VIN must be exactly 17 characters; got %d", len(vin))
	}
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value) VALUES ('tesla_vin', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		vin,
	)
	return err
}

func (s *TeslaService) requireVIN() (string, error) {
	vin := s.VIN()
	if vin == "" {
		return "", errors.New("no VIN configured — set one in the client app")
	}
	return vin, nil
}

// ── Command-log audit ─────────────────────────────────────────────

// TeslaCommandLogEntry is one row from tesla_command_log.
type TeslaCommandLogEntry struct {
	At        string
	Command   string
	Succeeded bool
	LatencyMs int64
	Error     string
}

// CommandLog returns the most recent `limit` audit entries
// newest-first. Empty most of the time on a Phase-4-clean Pi —
// client-driven commands don't yet write here. Thread C will wire
// naming through the byte-forwarder endpoints so this fills back up.
func (s *TeslaService) CommandLog(limit int) ([]TeslaCommandLogEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT at, command, succeeded, latency_ms, error
		   FROM tesla_command_log
		   ORDER BY at DESC, id DESC
		   LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query command log: %w", err)
	}
	defer rows.Close()
	var out []TeslaCommandLogEntry
	for rows.Next() {
		var e TeslaCommandLogEntry
		var okInt int
		if err := rows.Scan(&e.At, &e.Command, &okInt, &e.LatencyMs, &e.Error); err != nil {
			return nil, fmt.Errorf("scan command log row: %w", err)
		}
		e.Succeeded = okInt == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// LogCommand writes a single audit row. Exported so the byte-
// forwarder layer can record commands once it learns names. Best-
// effort: a DB error here doesn't tank the command result.
func (s *TeslaService) LogCommand(userID int64, name string, ok bool, latencyMs int64, errMsg string) {
	okInt := 0
	if ok {
		okInt = 1
	}
	if _, err := s.db.Exec(
		`INSERT INTO tesla_command_log (user_id, command, succeeded, latency_ms, error, at)
		 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		userID, name, okInt, latencyMs, errMsg,
	); err != nil {
		log.Printf("[TESLA] audit log write failed: %v", err)
	}
}
