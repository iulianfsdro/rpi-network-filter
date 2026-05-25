// Package-level Tesla BLE service.
//
// Three things this file is designed around:
//
//  1. The BLE adapter is a single-tenant resource. Linux's HCI socket
//     can host one active connection at a time, so every operation
//     (poll, command, pairing probe) takes the same mutex. Concurrent
//     /garage clicks queue behind it; a slow operation can't deadlock
//     anything else because each call carries a context with a hard
//     ceiling.
//
//  2. Connections are short-lived. The SDK's example pattern is
//     scan → connect → start-session → call → close. We replicate it
//     in withVCSEC()/withInfotainment() helpers — there's no long-
//     running BLE session to lose track of, no reconnect storm to
//     reason about.
//
//  3. State reads come from two sub-systems with very different costs.
//     VCSEC (body-controller-state) answers in ~500ms-1s whether the
//     infotainment is awake or not — that's the 30s background poll.
//     Infotainment (charge / climate state) needs the centre-console
//     computer awake, so we wake-then-query on demand and cache the
//     result. The protected-deny floor is not affected; this service
//     talks to the car directly over BLE, never through the SNI proxy.
package services

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/connector/ble"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
	keysproto "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/keys"
	universal "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/vcsec"
	"github.com/teslamotors/vehicle-command/pkg/vehicle"
)

const (
	// teslaKeyPath is where the operator's BLE private key lives. It's
	// the credential that lets us issue signed commands once the matching
	// public key has been enrolled via the Tesla mobile app's Add Key
	// flow. Lose this file → re-pair from scratch. Mode 0600, root.
	teslaKeyPath = "/var/lib/netfilterd/tesla/private_key.pem"

	// teslaBLEAdapter is the Linux HCI device name. Pi 4 has a single
	// built-in BLE radio on hci0; a USB BLE dongle would land at hci1
	// — we'd surface that via config later.
	teslaBLEAdapter = "hci0"

	// teslaScanTimeout caps how long ScanVehicleBeacon waits for an
	// advertisement. Tesla beacons broadcast every ~100ms while awake;
	// 15s is a comfortable upper bound even if the car is asleep.
	teslaScanTimeout = 15 * time.Second

	// teslaCommandTimeout caps a single command/state-read round-trip.
	// BLE writes typically come back in 300-800ms; we allow a generous
	// 15s to absorb transient packet loss without hard-failing.
	teslaCommandTimeout = 15 * time.Second

	// teslaWakeSettleDelay is how long we wait after sending Wakeup
	// before assuming the infotainment is reachable. Empirically the
	// centre-console computer needs 5-12s; 10s is the SDK's example
	// value and works in practice.
	teslaWakeSettleDelay = 10 * time.Second

	// teslaPollInterval is the cadence of the background body-controller-
	// state poll. Reads are cheap (VCSEC, no wake required) and keep the
	// /garage UI fresh without burning 12V battery.
	teslaPollInterval = 30 * time.Second
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

// VehicleSnapshot is the consolidated state /garage reads. Every field
// is paired with an "as of" timestamp so the UI can render staleness
// honestly — a charge_state from 8 minutes ago should LOOK different
// from one polled five seconds ago.
type VehicleSnapshot struct {
	// Configuration / pairing state.
	VIN    string
	Paired bool

	// VCSEC (cheap, always-available subset).
	LockState     string // "locked" / "unlocked" / "internal_locked" / "unknown"
	SleepStatus   string // "awake" / "asleep" / "unknown"
	UserPresent   bool
	Closures      ClosuresSnapshot
	BCSFreshness  time.Duration // age of the lock/closures data; ∞ if never polled

	// Infotainment (rich, requires wake). Zero values + ChargeFreshness
	// = "unknown / never polled" — the UI suppresses cards on that.
	BatteryPct        int32
	UsableBatteryPct  int32
	BatteryRangeKm    float32
	EstBatteryRangeKm float32
	ChargeLimitSOC    int32
	ChargingState     string
	ChargerPowerKW    int32
	MinutesToFull     int32
	ChargePortOpen    bool
	FastChargerPresent bool
	ChargeFreshness   time.Duration

	InsideTempC      float32
	OutsideTempC     float32
	DriverTempSetC   float32
	IsClimateOn      bool
	FanStatus        int32
	SeatHeaterLeft   int32
	SeatHeaterRight  int32
	ClimateFreshness time.Duration
}

// ClosuresSnapshot is the per-aperture state in plain strings (not the
// protobuf enum) so templates can render it without importing the SDK.
type ClosuresSnapshot struct {
	FrontDriverDoor    string
	FrontPassengerDoor string
	RearDriverDoor     string
	RearPassengerDoor  string
	FrontTrunk         string
	RearTrunk          string
	ChargePort         string
	Tonneau            string
}

// TeslaService is the singleton wrapping every BLE operation. Held by
// the composition root in services.Services.Tesla.
type TeslaService struct {
	db       *sql.DB
	audit    *AuditService
	keyPath  string
	adapter  string

	// bleMu serialises every BLE adapter operation. Linux can only host
	// one HCI client at a time and the SDK's session handshake isn't
	// designed for interleaving — one operation per acquisition.
	bleMu sync.Mutex

	// stateMu protects the cached snapshot used by /garage. RWMutex
	// because the snapshot is read-heavy (every page refresh).
	stateMu sync.RWMutex
	snap    VehicleSnapshot
	lastBCSAt     time.Time
	lastChargeAt  time.Time
	lastClimateAt time.Time

	// Lifecycle.
	pollerCtx    context.Context
	pollerCancel context.CancelFunc
	pollerDone   chan struct{}
}

// NewTeslaService wires the service. Doesn't start the poller — call
// Start() from the composition root after migrations are done.
func NewTeslaService(db *sql.DB, audit *AuditService) *TeslaService {
	return &TeslaService{
		db:      db,
		audit:   audit,
		keyPath: teslaKeyPath,
		adapter: teslaBLEAdapter,
	}
}

// ── Pairing + key management ────────────────────────────────────────

// PublicKeyPEM returns the operator's BLE public key as a PEM block,
// generating the keypair on first call. The returned PEM is what the
// operator pastes into the Tesla mobile app's Add Key flow.
//
// Generating writes the private key to teslaKeyPath, mode 0600. The
// directory is created with mode 0700 if missing.
func (s *TeslaService) PublicKeyPEM() (string, error) {
	priv, err := s.loadOrGenerateKey()
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

// loadOrGenerateKey hides the SDK's split between LoadPrivateKey
// (works on PEM files) and key generation (lives in the internal
// authentication package). We generate a vanilla P-256 ECDSA key with
// crypto/ecdsa and write it as SEC1 PEM — the same shape the SDK's
// SavePrivateKey produces — so protocol.LoadPrivateKey reads it on the
// next call.
func (s *TeslaService) loadOrGenerateKey() (protocol.ECDHPrivateKey, error) {
	if _, err := os.Stat(s.keyPath); err == nil {
		return protocol.LoadPrivateKey(s.keyPath)
	}
	if err := os.MkdirAll(filepath.Dir(s.keyPath), 0o700); err != nil {
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
	if err := os.WriteFile(s.keyPath, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	return protocol.LoadPrivateKey(s.keyPath)
}

// IsPaired returns true if the tesla_pairing row says we have a
// confirmed VCSEC session against this VIN. The check is cheap (one
// SELECT) and is what /garage uses to decide between the pairing card
// and the live dashboard.
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

// RequestPairing sends an add-key-request over BLE — the unauthenticated
// pairing protocol the Tesla expects for a new key.
//
// The actual flow is *not* "paste a PEM into the Tesla mobile app." It
// is:
//
//   1. The Pi opens an anonymous BLE connection to the car (no signed
//      session — this request is allowed without auth, on purpose,
//      because there is no key yet that COULD sign it).
//   2. We send the public key + role + form-factor. The SDK marshals
//      it into a VCSEC ToVCSECMessage with SIGNATURE_TYPE_PRESENT_KEY
//      (= "this is a new key I'm presenting").
//   3. The car displays a prompt on the centre console: "<role> key
//      wants to be added — tap your NFC card to approve."
//   4. The operator taps their physical NFC key card on the centre
//      console reader, then confirms intent on the touchscreen.
//   5. The car enrols the key. From this moment, signed VCSEC sessions
//      against our key succeed — which is exactly what ConfirmPairing
//      polls for below.
//
// SendAddKeyRequest returns immediately after step 2 — a nil return
// does NOT mean the key is enrolled. The operator's UI calls this and
// then polls ConfirmPairing until the human has done step 4.
//
// Role + form factor are baked in:
//   - DRIVER: can operate the car (lock/unlock/climate/charge/closures)
//     but cannot enrol or remove other keys. Safer default than OWNER
//     for a third-party device.
//   - CLOUD_KEY: Tesla's form-factor enum for "cloud-style key holder"
//     — what the official tesla-control documents for third-party
//     servers and what tesla-control's examples use.
func (s *TeslaService) RequestPairing(ctx context.Context) error {
	vin, err := s.requireVIN()
	if err != nil {
		return err
	}
	pubKey, err := s.publicKeyECDH()
	if err != nil {
		return fmt.Errorf("public key extraction: %w", err)
	}

	// add-key-request is `requiresAuth: false` in the SDK — no
	// StartSession needed. We use sendUnauthenticated() instead of
	// withVCSEC() so we don't try to negotiate a signed session against
	// a key the car has never seen.
	return s.sendUnauthenticated(ctx, vin, func(car *vehicle.Vehicle) error {
		return car.SendAddKeyRequestWithRole(
			ctx,
			pubKey,
			keysproto.Role_ROLE_DRIVER,
			vcsec.KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY,
		)
	})
}

// ConfirmPairing polls for the post-enrollment state — i.e. it tries a
// signed VCSEC session against the configured VIN. If that succeeds,
// the car has accepted our key and we record the success in
// tesla_pairing. The UI calls this in a loop after RequestPairing
// returns, while the operator is walking out to the centre console.
func (s *TeslaService) ConfirmPairing(ctx context.Context) error {
	vin, err := s.requireVIN()
	if err != nil {
		return err
	}
	if err := s.withVCSEC(ctx, vin, func(car *vehicle.Vehicle) error {
		_, err := car.BodyControllerState(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("VCSEC session against %s: %w (key not enrolled yet — tap the NFC card on the centre console)", vin, err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO tesla_pairing (vin, paired_at) VALUES (?, CURRENT_TIMESTAMP)
		 ON CONFLICT(vin) DO UPDATE SET paired_at = CURRENT_TIMESTAMP`,
		vin,
	); err != nil {
		return fmt.Errorf("record pairing: %w", err)
	}
	return nil
}

// publicKeyECDH returns the operator's key as an *ecdh.PublicKey, the
// type the SDK's SendAddKeyRequest expects. The SDK stores keys as
// authentication.ECDHPrivateKey (interface); we extract the SEC1
// public bytes and re-marshal.
func (s *TeslaService) publicKeyECDH() (*ecdh.PublicKey, error) {
	priv, err := s.loadOrGenerateKey()
	if err != nil {
		return nil, err
	}
	pubBytes := priv.PublicBytes()
	if len(pubBytes) == 0 {
		return nil, fmt.Errorf("private key produced empty public bytes")
	}
	return ecdh.P256().NewPublicKey(pubBytes)
}

// sendUnauthenticated is withVCSEC's sibling for operations that must
// NOT start a signed session — only add-key-request today. It opens a
// fresh BLE connection, calls car.Connect (just the transport
// handshake), and invokes fn. Whatever fn does, it must not call
// StartSession — that would fail because the car doesn't know our
// key yet.
func (s *TeslaService) sendUnauthenticated(parent context.Context, vin string, fn func(*vehicle.Vehicle) error) error {
	if err := initAdapter(s.adapter); err != nil {
		return fmt.Errorf("BLE adapter init: %w", err)
	}

	s.bleMu.Lock()
	defer s.bleMu.Unlock()

	priv, err := s.loadOrGenerateKey()
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

// ── State reads ─────────────────────────────────────────────────────

// PollBodyControllerState refreshes the cheap subset of state — lock,
// closures, sleep status, user presence. Works whether the infotainment
// is awake or not. This is the background poller's job; UI requests
// can also call it directly when they need fresh-as-possible data
// without the wake cost.
func (s *TeslaService) PollBodyControllerState(ctx context.Context) error {
	vin, err := s.requireVIN()
	if err != nil {
		return err
	}
	var bcs *vcsec.VehicleStatus
	err = s.withVCSEC(ctx, vin, func(car *vehicle.Vehicle) error {
		var inner error
		bcs, inner = car.BodyControllerState(ctx)
		return inner
	})
	if err != nil {
		return err
	}
	s.updateBCS(bcs)
	return nil
}

// PollChargeAndClimate refreshes battery + climate state. Requires the
// infotainment to be awake; we wake-and-wait if it isn't. Use sparingly
// — keeping the infotainment up draws 12V battery.
func (s *TeslaService) PollChargeAndClimate(ctx context.Context, wake bool) error {
	vin, err := s.requireVIN()
	if err != nil {
		return err
	}
	return s.withInfotainment(ctx, vin, wake, func(car *vehicle.Vehicle) error {
		chargeCtx, cancel := context.WithTimeout(ctx, teslaCommandTimeout)
		defer cancel()
		chargeData, err := car.GetState(chargeCtx, vehicle.StateCategoryCharge)
		if err != nil {
			return fmt.Errorf("GetState(charge): %w", err)
		}
		s.updateCharge(chargeData.GetChargeState())

		climateCtx, cancel2 := context.WithTimeout(ctx, teslaCommandTimeout)
		defer cancel2()
		climateData, err := car.GetState(climateCtx, vehicle.StateCategoryClimate)
		if err != nil {
			// Don't fail the whole call if just climate refuses;
			// charge data is the more valuable read.
			log.Printf("[TESLA] GetState(climate) failed (charge succeeded): %v", err)
			return nil
		}
		s.updateClimate(climateData.GetClimateState())
		return nil
	})
}

// Snapshot returns the cached state. Cheap; safe to call from every
// /garage page render. Freshness fields update implicitly from the
// "last X at" timestamps so the UI can colour stale data.
func (s *TeslaService) Snapshot() VehicleSnapshot {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	out := s.snap
	out.VIN = s.VIN()
	out.Paired = s.IsPaired()
	now := time.Now()
	if !s.lastBCSAt.IsZero() {
		out.BCSFreshness = now.Sub(s.lastBCSAt)
	}
	if !s.lastChargeAt.IsZero() {
		out.ChargeFreshness = now.Sub(s.lastChargeAt)
	}
	if !s.lastClimateAt.IsZero() {
		out.ClimateFreshness = now.Sub(s.lastClimateAt)
	}
	return out
}

// ── Commands ────────────────────────────────────────────────────────
//
// Each public command takes (ctx, userID) — userID lands in the audit
// row so the /garage activity strip and security logs can attribute
// who issued what. The body of every method is the same three-line
// pattern: lookup VIN, withVCSEC/withInfotainment + the SDK call,
// auditCommand wrapping for timing.

func (s *TeslaService) Lock(ctx context.Context, userID int64) error {
	return s.runVCSECCommand(ctx, userID, "lock", func(car *vehicle.Vehicle) error {
		return car.Lock(ctx)
	})
}

func (s *TeslaService) Unlock(ctx context.Context, userID int64) error {
	return s.runVCSECCommand(ctx, userID, "unlock", func(car *vehicle.Vehicle) error {
		return car.Unlock(ctx)
	})
}

func (s *TeslaService) Wakeup(ctx context.Context, userID int64) error {
	return s.runVCSECCommand(ctx, userID, "wake", func(car *vehicle.Vehicle) error {
		return car.Wakeup(ctx)
	})
}

func (s *TeslaService) Honk(ctx context.Context, userID int64) error {
	return s.runInfotainmentCommand(ctx, userID, "honk", true, func(car *vehicle.Vehicle) error {
		return car.HonkHorn(ctx)
	})
}

func (s *TeslaService) FlashLights(ctx context.Context, userID int64) error {
	return s.runInfotainmentCommand(ctx, userID, "flash_lights", true, func(car *vehicle.Vehicle) error {
		return car.FlashLights(ctx)
	})
}

func (s *TeslaService) OpenFrunk(ctx context.Context, userID int64) error {
	return s.runVCSECCommand(ctx, userID, "open_frunk", func(car *vehicle.Vehicle) error {
		return car.OpenFrunk(ctx)
	})
}

func (s *TeslaService) OpenTrunk(ctx context.Context, userID int64) error {
	return s.runVCSECCommand(ctx, userID, "open_trunk", func(car *vehicle.Vehicle) error {
		return car.OpenTrunk(ctx)
	})
}

func (s *TeslaService) CloseTrunk(ctx context.Context, userID int64) error {
	return s.runVCSECCommand(ctx, userID, "close_trunk", func(car *vehicle.Vehicle) error {
		return car.CloseTrunk(ctx)
	})
}

func (s *TeslaService) OpenChargePort(ctx context.Context, userID int64) error {
	return s.runVCSECCommand(ctx, userID, "open_charge_port", func(car *vehicle.Vehicle) error {
		return car.OpenChargePort(ctx)
	})
}

func (s *TeslaService) CloseChargePort(ctx context.Context, userID int64) error {
	return s.runVCSECCommand(ctx, userID, "close_charge_port", func(car *vehicle.Vehicle) error {
		return car.CloseChargePort(ctx)
	})
}

func (s *TeslaService) ClimateOn(ctx context.Context, userID int64) error {
	return s.runInfotainmentCommand(ctx, userID, "climate_on", true, func(car *vehicle.Vehicle) error {
		return car.ClimateOn(ctx)
	})
}

func (s *TeslaService) ClimateOff(ctx context.Context, userID int64) error {
	return s.runInfotainmentCommand(ctx, userID, "climate_off", false, func(car *vehicle.Vehicle) error {
		return car.ClimateOff(ctx)
	})
}

func (s *TeslaService) SetClimateTemp(ctx context.Context, userID int64, celsius float32) error {
	return s.runInfotainmentCommand(ctx, userID, fmt.Sprintf("set_climate_temp:%.1f", celsius), true, func(car *vehicle.Vehicle) error {
		return car.ChangeClimateTemp(ctx, celsius, celsius)
	})
}

func (s *TeslaService) SetChargingLimit(ctx context.Context, userID int64, percent int32) error {
	return s.runInfotainmentCommand(ctx, userID, fmt.Sprintf("set_charging_limit:%d", percent), true, func(car *vehicle.Vehicle) error {
		return car.ChangeChargeLimit(ctx, percent)
	})
}

func (s *TeslaService) StartCharging(ctx context.Context, userID int64) error {
	return s.runInfotainmentCommand(ctx, userID, "start_charging", true, func(car *vehicle.Vehicle) error {
		return car.ChargeStart(ctx)
	})
}

func (s *TeslaService) StopCharging(ctx context.Context, userID int64) error {
	return s.runInfotainmentCommand(ctx, userID, "stop_charging", true, func(car *vehicle.Vehicle) error {
		return car.ChargeStop(ctx)
	})
}

func (s *TeslaService) SetSentryMode(ctx context.Context, userID int64, on bool) error {
	name := "sentry_off"
	if on {
		name = "sentry_on"
	}
	return s.runInfotainmentCommand(ctx, userID, name, true, func(car *vehicle.Vehicle) error {
		return car.SetSentryMode(ctx, on)
	})
}

// TriggerHomelink fires the car's Homelink relay at its current GPS
// location. The SDK's TriggerHomelink takes lat/long because the car
// can have multiple Homelink locations stored (home + office + lake
// house) and uses the position to pick which one to trigger. Cleanest
// UX is: don't ask the operator anything — read the car's own current
// position and pass that through. If the car is parked AT a Homelinked
// location, it fires that one. If it's nowhere near a Homelink, the
// relay simply doesn't fire (no harm done).
//
// Two BLE operations share one Infotainment session: GetState(Location)
// then TriggerHomelink. We can't reuse runInfotainmentCommand because
// that does one fn() call; instead we open the session ourselves with
// withInfotainment and audit-log the timing around the whole thing.
func (s *TeslaService) TriggerHomelink(ctx context.Context, userID int64) error {
	vin, err := s.requireVIN()
	if err != nil {
		s.logCommand(userID, "homelink", false, 0, err.Error())
		return err
	}
	start := time.Now()
	var lat, lng float32
	runErr := s.withInfotainment(ctx, vin, true, func(car *vehicle.Vehicle) error {
		locCtx, cancel := context.WithTimeout(ctx, teslaCommandTimeout)
		defer cancel()
		loc, err := car.GetState(locCtx, vehicle.StateCategoryLocation)
		if err != nil {
			return fmt.Errorf("GetState(location): %w", err)
		}
		ls := loc.GetLocationState()
		if ls == nil {
			return fmt.Errorf("location state empty — is the car awake?")
		}
		lat, lng = ls.GetLatitude(), ls.GetLongitude()
		if lat == 0 && lng == 0 {
			return fmt.Errorf("car returned (0,0) for location — GPS not yet fixed")
		}
		hlCtx, hlCancel := context.WithTimeout(ctx, teslaCommandTimeout)
		defer hlCancel()
		return car.TriggerHomelink(hlCtx, lat, lng)
	})
	latency := time.Since(start).Milliseconds()
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}
	// Audit name embeds the coordinates so the activity log says
	// where the trigger fired — useful when the operator has more
	// than one Homelinked location.
	auditName := fmt.Sprintf("homelink:%.5f,%.5f", lat, lng)
	if runErr != nil && lat == 0 && lng == 0 {
		auditName = "homelink"
	}
	s.logCommand(userID, auditName, runErr == nil, latency, errMsg)
	return runErr
}

// ── Background poller lifecycle ─────────────────────────────────────

// Start kicks off the background poll loop. Safe to call multiple times
// (Stop-then-Start cycles work). Polls VCSEC every teslaPollInterval;
// stays idle if the service isn't paired yet.
func (s *TeslaService) Start(ctx context.Context) {
	if s.pollerCancel != nil {
		s.Stop()
	}
	ctx, cancel := context.WithCancel(ctx)
	s.pollerCtx = ctx
	s.pollerCancel = cancel
	s.pollerDone = make(chan struct{})

	go s.runPoller(ctx)
}

// Stop signals the poller and waits up to 5s for it to exit. Called
// from main on shutdown.
func (s *TeslaService) Stop() {
	if s.pollerCancel == nil {
		return
	}
	s.pollerCancel()
	select {
	case <-s.pollerDone:
	case <-time.After(5 * time.Second):
		log.Printf("[TESLA] poller didn't exit within 5s; abandoning")
	}
	s.pollerCancel = nil
}

func (s *TeslaService) runPoller(ctx context.Context) {
	defer close(s.pollerDone)
	tick := time.NewTicker(teslaPollInterval)
	defer tick.Stop()
	for {
		if s.IsPaired() {
			pollCtx, cancel := context.WithTimeout(ctx, teslaCommandTimeout+teslaScanTimeout)
			if err := s.PollBodyControllerState(pollCtx); err != nil {
				// Don't spam the journal — BLE out-of-range is the
				// common case when the Pi isn't in/near the car.
				if !errors.Is(err, context.DeadlineExceeded) {
					log.Printf("[TESLA] poll BCS: %v", err)
				}
			}
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ── Settings access ─────────────────────────────────────────────────

// VIN returns the configured Tesla VIN (set via /settings or the
// pairing flow). Empty string means "not configured" — the service
// stays idle.
func (s *TeslaService) VIN() string {
	var vin string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key = 'tesla_vin'`).Scan(&vin)
	return strings.TrimSpace(vin)
}

// SetVIN stores the VIN in the settings table. UI calls this after the
// user enters their VIN; the value persists across restarts.
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
		return "", errors.New("no VIN configured — set one via /garage")
	}
	return vin, nil
}

// ── BLE session helpers ─────────────────────────────────────────────

// withVCSEC opens a fresh BLE connection, starts a VCSEC-domain
// session, runs fn, then closes — the same pattern as the SDK
// examples/ble. Holds the BLE mutex for the entire operation.
func (s *TeslaService) withVCSEC(ctx context.Context, vin string, fn func(*vehicle.Vehicle) error) error {
	return s.withSession(ctx, vin, []universal.Domain{universal.Domain_DOMAIN_VEHICLE_SECURITY}, false, fn)
}

// withInfotainment opens a BLE connection and starts BOTH a VCSEC and
// an Infotainment session — Infotainment is what answers charge/climate
// state and most commands; VCSEC stays open for the lock/closure ops
// the SDK routes through there. If wakeIfAsleep is true and the first
// Infotainment session attempt fails, we send Wakeup and retry once
// after a settle delay.
func (s *TeslaService) withInfotainment(ctx context.Context, vin string, wakeIfAsleep bool, fn func(*vehicle.Vehicle) error) error {
	return s.withSession(
		ctx, vin,
		[]universal.Domain{universal.Domain_DOMAIN_VEHICLE_SECURITY, universal.Domain_DOMAIN_INFOTAINMENT},
		wakeIfAsleep,
		fn,
	)
}

func (s *TeslaService) withSession(parent context.Context, vin string, domains []universal.Domain, wakeIfAsleep bool, fn func(*vehicle.Vehicle) error) error {
	if err := initAdapter(s.adapter); err != nil {
		return fmt.Errorf("BLE adapter init: %w", err)
	}

	s.bleMu.Lock()
	defer s.bleMu.Unlock()

	priv, err := s.loadOrGenerateKey()
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

	if err := car.StartSession(parent, domains); err != nil {
		if !wakeIfAsleep {
			return fmt.Errorf("start session %v: %w", domains, err)
		}
		// Retry path: wake the infotainment, wait, retry.
		log.Printf("[TESLA] session refused (likely asleep): %v — waking and retrying once", err)
		wakeCtx, wakeCancel := context.WithTimeout(parent, teslaCommandTimeout)
		if werr := car.Wakeup(wakeCtx); werr != nil {
			wakeCancel()
			return fmt.Errorf("wakeup: %w", werr)
		}
		wakeCancel()
		select {
		case <-time.After(teslaWakeSettleDelay):
		case <-parent.Done():
			return parent.Err()
		}
		if err := car.StartSession(parent, domains); err != nil {
			return fmt.Errorf("start session after wake: %w", err)
		}
	}

	return fn(car)
}

// initAdapter brings the BLE adapter online for go-ble. Idempotent on
// success (won't re-call and trip go-ble's double-init panic) and
// retriable on failure (caller can recover after the operator unblocks
// rfkill or starts bluetoothd).
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

// runVCSECCommand is the standard command wrapper: VCSEC session,
// audit-logged with start/end times, surfaces errors to the caller.
func (s *TeslaService) runVCSECCommand(ctx context.Context, userID int64, name string, fn func(*vehicle.Vehicle) error) error {
	return s.runCommand(ctx, userID, name, false, false, fn)
}

// runInfotainmentCommand wraps an Infotainment-domain command (climate,
// charging, sentry). wakeIfAsleep is usually true — clicking "Climate On"
// from /garage implies the user wants the car to wake up.
func (s *TeslaService) runInfotainmentCommand(ctx context.Context, userID int64, name string, wakeIfAsleep bool, fn func(*vehicle.Vehicle) error) error {
	return s.runCommand(ctx, userID, name, true, wakeIfAsleep, fn)
}

func (s *TeslaService) runCommand(ctx context.Context, userID int64, name string, infotainment, wakeIfAsleep bool, fn func(*vehicle.Vehicle) error) error {
	vin, err := s.requireVIN()
	if err != nil {
		s.logCommand(userID, name, false, 0, err.Error())
		return err
	}
	start := time.Now()
	var runErr error
	if infotainment {
		runErr = s.withInfotainment(ctx, vin, wakeIfAsleep, fn)
	} else {
		runErr = s.withVCSEC(ctx, vin, fn)
	}
	latency := time.Since(start).Milliseconds()
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}
	s.logCommand(userID, name, runErr == nil, latency, errMsg)
	return runErr
}

// TeslaCommandLogEntry mirrors a row from tesla_command_log, in plain
// types so handlers can JSON-encode it without leaking driver types.
type TeslaCommandLogEntry struct {
	At        string
	Command   string
	Succeeded bool
	LatencyMs int64
	Error     string
}

// CommandLog returns the most recent `limit` audit entries newest-first.
// The /garage activity strip is the only consumer today.
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

// logCommand writes a single audit row. Best-effort — a DB error here
// shouldn't tank the command result the caller cares about.
func (s *TeslaService) logCommand(userID int64, name string, ok bool, latencyMs int64, errMsg string) {
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

// ── Snapshot updates ────────────────────────────────────────────────

func (s *TeslaService) updateBCS(bcs *vcsec.VehicleStatus) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.lastBCSAt = time.Now()
	s.snap.LockState = lockStateString(bcs.GetVehicleLockState())
	s.snap.SleepStatus = sleepStatusString(bcs.GetVehicleSleepStatus())
	s.snap.UserPresent = bcs.GetUserPresence() == vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_PRESENT
	if cs := bcs.GetClosureStatuses(); cs != nil {
		s.snap.Closures = ClosuresSnapshot{
			FrontDriverDoor:    closureStateString(cs.GetFrontDriverDoor()),
			FrontPassengerDoor: closureStateString(cs.GetFrontPassengerDoor()),
			RearDriverDoor:     closureStateString(cs.GetRearDriverDoor()),
			RearPassengerDoor:  closureStateString(cs.GetRearPassengerDoor()),
			FrontTrunk:         closureStateString(cs.GetFrontTrunk()),
			RearTrunk:          closureStateString(cs.GetRearTrunk()),
			ChargePort:         closureStateString(cs.GetChargePort()),
			Tonneau:            closureStateString(cs.GetTonneau()),
		}
	}
}

func (s *TeslaService) updateCharge(cs *carserver.ChargeState) {
	if cs == nil {
		return
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.lastChargeAt = time.Now()
	s.snap.BatteryPct = cs.GetBatteryLevel()
	s.snap.UsableBatteryPct = cs.GetUsableBatteryLevel()
	s.snap.BatteryRangeKm = cs.GetBatteryRange()
	s.snap.EstBatteryRangeKm = cs.GetEstBatteryRange()
	s.snap.ChargeLimitSOC = cs.GetChargeLimitSoc()
	s.snap.ChargingState = chargingStateString(cs.GetChargingState())
	s.snap.ChargerPowerKW = cs.GetChargerPower()
	s.snap.MinutesToFull = cs.GetMinutesToFullCharge()
	s.snap.ChargePortOpen = cs.GetChargePortDoorOpen()
	s.snap.FastChargerPresent = cs.GetFastChargerPresent()
}

func (s *TeslaService) updateClimate(cl *carserver.ClimateState) {
	if cl == nil {
		return
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.lastClimateAt = time.Now()
	s.snap.InsideTempC = cl.GetInsideTempCelsius()
	s.snap.OutsideTempC = cl.GetOutsideTempCelsius()
	s.snap.DriverTempSetC = cl.GetDriverTempSetting()
	s.snap.IsClimateOn = cl.GetIsClimateOn()
	s.snap.FanStatus = cl.GetFanStatus()
	s.snap.SeatHeaterLeft = cl.GetSeatHeaterLeft()
	s.snap.SeatHeaterRight = cl.GetSeatHeaterRight()
}

// ── enum → string helpers (templates can't import the SDK protos) ──

func lockStateString(s vcsec.VehicleLockState_E) string {
	switch s {
	case vcsec.VehicleLockState_E_VEHICLELOCKSTATE_LOCKED:
		return "locked"
	case vcsec.VehicleLockState_E_VEHICLELOCKSTATE_UNLOCKED:
		return "unlocked"
	case vcsec.VehicleLockState_E_VEHICLELOCKSTATE_INTERNAL_LOCKED:
		return "internal_locked"
	case vcsec.VehicleLockState_E_VEHICLELOCKSTATE_SELECTIVE_UNLOCKED:
		return "selective_unlocked"
	default:
		return "unknown"
	}
}

func sleepStatusString(s vcsec.VehicleSleepStatus_E) string {
	switch s {
	case vcsec.VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_AWAKE:
		return "awake"
	case vcsec.VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_ASLEEP:
		return "asleep"
	default:
		return "unknown"
	}
}

func closureStateString(c vcsec.ClosureState_E) string {
	switch c {
	case vcsec.ClosureState_E_CLOSURESTATE_CLOSED:
		return "closed"
	case vcsec.ClosureState_E_CLOSURESTATE_OPEN:
		return "open"
	case vcsec.ClosureState_E_CLOSURESTATE_AJAR:
		return "ajar"
	case vcsec.ClosureState_E_CLOSURESTATE_OPENING:
		return "opening"
	case vcsec.ClosureState_E_CLOSURESTATE_CLOSING:
		return "closing"
	case vcsec.ClosureState_E_CLOSURESTATE_FAILED_UNLATCH:
		return "failed_unlatch"
	default:
		return "unknown"
	}
}

func chargingStateString(c *carserver.ChargeState_ChargingState) string {
	if c == nil {
		return "unknown"
	}
	// The SDK wraps each state in a oneof; the field name reveals it.
	switch {
	case c.GetDisconnected() != nil:
		return "disconnected"
	case c.GetCharging() != nil:
		return "charging"
	case c.GetNoPower() != nil:
		return "no_power"
	case c.GetStarting() != nil:
		return "starting"
	case c.GetComplete() != nil:
		return "complete"
	case c.GetStopped() != nil:
		return "stopped"
	default:
		return "unknown"
	}
}
