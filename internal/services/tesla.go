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
	IsPreconditioning bool // Tesla's smart pre-departure preconditioning (separate from defrost)
	DefrostOn         bool // true if DefrostMode is Normal or Max (what the /garage Defrost button reflects)
	DefrostMax        bool // true only if DefrostMode is Max — for finer UI later
	FanStatus        int32
	SeatHeaterLeft   int32
	SeatHeaterRight  int32
	SeatHeaterRearLeft   int32
	SeatHeaterRearCenter int32
	SeatHeaterRearRight  int32
	SteeringWheelHeater  bool
	FrontDefrosterOn     bool
	RearDefrosterOn      bool
	CabinOverheatProtection bool // operator-level COP toggle
	ClimateFreshness time.Duration

	// Extended state — populated by full-state polls.
	TirePressure       TirePressureSnapshot
	TPFreshness        time.Duration

	Location           LocationSnapshot
	LocationFreshness  time.Duration
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

	// Windows arrive from the CarServer ClosuresState (NOT VCSEC, which
	// only knows doors + trunks + frunk + charge-port + tonneau). They
	// stay zero/false until a full state poll runs.
	WindowDriverFront    bool
	WindowPassengerFront bool
	WindowDriverRear     bool
	WindowPassengerRear  bool

	// CarServer ClosuresState ALSO reports door + trunk + frunk + lock,
	// but as proto3 OPTIONAL fields wrapped in oneofs. The car may or
	// may not emit each one depending on firmware / model — empirically
	// the user's 2024 Berlin Model Y emits windows + sentry but NOT
	// the door/trunk/frunk optionals. When unset, the SDK's plain
	// bool getter returns false regardless of physical state, which
	// would let "closed" pin permanently.
	//
	// So we store these as *bool: nil = "Tesla didn't emit this field
	// for this vehicle", non-nil = "Tesla emitted it, here's the
	// actual state." The UI uses VCSEC's string as the fallback
	// whenever the Infotainment override is nil.
	InfDoorOpenDriverFront    *bool
	InfDoorOpenPassengerFront *bool
	InfDoorOpenDriverRear     *bool
	InfDoorOpenPassengerRear  *bool
	InfTrunkFrontOpen         *bool // frunk
	InfTrunkRearOpen          *bool // trunk
	InfLocked                 *bool

	// Sentry mode lives on CarServer ClosuresState too.
	SentryAvailable bool
	SentryOn        bool
}

// TirePressureSnapshot holds the four wheels' pressures in bar (Tesla
// reports kPa internally but the SDK normalises to bar). Zero means
// "no reading received yet" — TPMS only refreshes when the car is
// moving or after a state poll wakes it.
type TirePressureSnapshot struct {
	FrontLeftBar  float32
	FrontRightBar float32
	RearLeftBar   float32
	RearRightBar  float32

	HardWarningFrontLeft  bool
	HardWarningFrontRight bool
	HardWarningRearLeft   bool
	HardWarningRearRight  bool
}

// LocationSnapshot is the car's last-known position. Both fields can
// be zero when the GPS hasn't fixed yet (cold start, indoor parking).
type LocationSnapshot struct {
	Latitude  float32
	Longitude float32
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
	lastBCSAt      time.Time
	lastChargeAt   time.Time
	lastClimateAt  time.Time
	lastTPAt       time.Time
	lastLocationAt time.Time

	// Lifecycle.
	pollerCtx    context.Context
	pollerCancel context.CancelFunc
	pollerDone   chan struct{}

	// closureAssertions: operator-set closure states that take
	// priority over polled VCSEC/Infotainment data until a TTL
	// expires OR a poll arrives whose reading agrees with the
	// assertion. The point is to survive Tesla's VCSEC closure
	// sensor lag (sometimes hours after a clean physical close)
	// without the snapshot lying about state — the operator just
	// closed the frunk, the daemon writes "closed" here, every
	// subsequent /api/tesla/state read returns "closed" no matter
	// what the lagging sensor says, until 5 min later it gives up
	// (or the sensor finally agrees).
	closureAssertMu sync.Mutex
	closureAssertions map[string]closureAssertion
}

// closureAssertion is the per-closure operator override.
type closureAssertion struct {
	expectedClosed bool      // true = "operator says this is closed"
	until          time.Time // assertion drops at this point
}

// teslaClosureAssertTTL is how long an assertion holds against
// contradicting poll data. Long enough to cover Tesla's worst
// observed VCSEC closure-sensor lag in the wild; short enough that
// if the operator genuinely opened the frunk physically and the
// daemon missed it, the truth surfaces within a few minutes.
const teslaClosureAssertTTL = 5 * time.Minute

// NewTeslaService wires the service. Doesn't start the poller — call
// Start() from the composition root after migrations are done.
func NewTeslaService(db *sql.DB, audit *AuditService) *TeslaService {
	return &TeslaService{
		db:                db,
		audit:             audit,
		keyPath:           teslaKeyPath,
		adapter:           teslaBLEAdapter,
		closureAssertions: make(map[string]closureAssertion),
	}
}

// assertClosure marks a closure as operator-set. Subsequent Snapshot()
// reads return this state for that closure regardless of what the
// polled sensor data says, until either:
//   (a) teslaClosureAssertTTL passes since the assertion, or
//   (b) a poll arrives whose value agrees with the assertion
//       (we let it stick around for cleanup; next applyAssertions
//       call drops it).
//
// name is the snapshot field key — "front_trunk" / "rear_trunk" /
// "charge_port" / "window_*". expectedClosed: true if the operator's
// intent is "this should now be closed".
func (s *TeslaService) assertClosure(name string, expectedClosed bool) {
	s.closureAssertMu.Lock()
	defer s.closureAssertMu.Unlock()
	s.closureAssertions[name] = closureAssertion{
		expectedClosed: expectedClosed,
		until:          time.Now().Add(teslaClosureAssertTTL),
	}
}

// applyClosureAssertions mutates the passed snapshot copy, replacing
// each closure field with the operator-asserted value where applicable.
// Also drops expired assertions and assertions that now agree with the
// snapshot (no longer needed). Caller must hold no locks; we take both
// stateMu and closureAssertMu briefly.
//
// Closures handled (by the snapshot field name we set):
//   - front_trunk  → ClosuresSnapshot.FrontTrunk + InfTrunkFrontOpen
//   - rear_trunk   → RearTrunk + InfTrunkRearOpen
//   - charge_port  → ChargePort
//   - window_*     → Closures.Window*
func (s *TeslaService) applyClosureAssertions(snap *VehicleSnapshot) {
	s.closureAssertMu.Lock()
	defer s.closureAssertMu.Unlock()
	now := time.Now()
	for name, a := range s.closureAssertions {
		if now.After(a.until) {
			delete(s.closureAssertions, name)
			continue
		}
		// stateString picks the right ClosureState_E-equivalent label
		// the UI knows how to render.
		stateStr := "open"
		if a.expectedClosed {
			stateStr = "closed"
		}
		openBool := !a.expectedClosed
		// Track whether the current poll value already agrees, so we
		// can drop the assertion if so.
		agreed := false

		switch name {
		case "front_trunk":
			agreed = (snap.Closures.FrontTrunk == stateStr)
			snap.Closures.FrontTrunk = stateStr
			b := openBool
			snap.Closures.InfTrunkFrontOpen = &b
		case "rear_trunk":
			agreed = (snap.Closures.RearTrunk == stateStr)
			snap.Closures.RearTrunk = stateStr
			b := openBool
			snap.Closures.InfTrunkRearOpen = &b
		case "charge_port":
			// Three sources for charge port — VCSEC closure + Infotainment
			// inf bool + ChargeState.charge_port_door_open. Override all
			// three so whichever the UI prefers, it sees the assertion.
			agreed = (snap.Closures.ChargePort == stateStr)
			snap.Closures.ChargePort = stateStr
			snap.ChargePortOpen = openBool
		case "window_driver_front":
			agreed = (snap.Closures.WindowDriverFront == openBool)
			snap.Closures.WindowDriverFront = openBool
		case "window_passenger_front":
			agreed = (snap.Closures.WindowPassengerFront == openBool)
			snap.Closures.WindowPassengerFront = openBool
		case "window_driver_rear":
			agreed = (snap.Closures.WindowDriverRear == openBool)
			snap.Closures.WindowDriverRear = openBool
		case "window_passenger_rear":
			agreed = (snap.Closures.WindowPassengerRear == openBool)
			snap.Closures.WindowPassengerRear = openBool
		}

		if agreed {
			delete(s.closureAssertions, name)
		}
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

// PollChargeAndClimate refreshes the full Infotainment-domain state —
// charge, climate, closures (windows + sentry), location, tire
// pressure. Despite the legacy name, it's the "full" state-refresh
// path. Requires the infotainment to be awake; we wake-and-wait if it
// isn't. Use sparingly — keeping the infotainment up draws 12V battery.
//
// Each subsystem is fetched independently and best-effort: if one
// fails we log + continue rather than abandoning the others, because
// (a) the charge read is the most-valuable single fetch, and (b) some
// vehicles don't ship every subsystem (older Model S without TPMS,
// etc.).
func (s *TeslaService) PollChargeAndClimate(ctx context.Context, wake bool) error {
	vin, err := s.requireVIN()
	if err != nil {
		return err
	}
	return s.withInfotainment(ctx, vin, wake, func(car *vehicle.Vehicle) error {
		// charge — the headline number for /garage
		if data, err := getStateWithTimeout(ctx, car, vehicle.StateCategoryCharge); err == nil {
			s.updateCharge(data.GetChargeState())
		} else {
			return fmt.Errorf("GetState(charge): %w", err)
		}
		// climate — best-effort
		if data, err := getStateWithTimeout(ctx, car, vehicle.StateCategoryClimate); err == nil {
			s.updateClimate(data.GetClimateState())
		} else {
			log.Printf("[TESLA] GetState(climate) failed (charge succeeded): %v", err)
		}
		// closures (CarServer view — has windows + sentry mode, richer
		// than VCSEC's set)
		if data, err := getStateWithTimeout(ctx, car, vehicle.StateCategoryClosures); err == nil {
			s.updateClosures(data.GetClosuresState())
		} else {
			log.Printf("[TESLA] GetState(closures) failed: %v", err)
		}
		// tire pressure
		if data, err := getStateWithTimeout(ctx, car, vehicle.StateCategoryTirePressure); err == nil {
			s.updateTirePressure(data.GetTirePressureState())
		} else {
			log.Printf("[TESLA] GetState(tire-pressure) failed: %v", err)
		}
		// location
		if data, err := getStateWithTimeout(ctx, car, vehicle.StateCategoryLocation); err == nil {
			s.updateLocation(data.GetLocationState())
		} else {
			log.Printf("[TESLA] GetState(location) failed: %v", err)
		}
		return nil
	})
}

// getStateWithTimeout wraps car.GetState with the standard per-call
// timeout. Defined here rather than inline to keep PollChargeAndClimate
// readable.
func getStateWithTimeout(parent context.Context, car *vehicle.Vehicle, cat vehicle.StateCategory) (*carserver.VehicleData, error) {
	ctx, cancel := context.WithTimeout(parent, teslaCommandTimeout)
	defer cancel()
	return car.GetState(ctx, cat)
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
	if !s.lastTPAt.IsZero() {
		out.TPFreshness = now.Sub(s.lastTPAt)
	}
	if !s.lastLocationAt.IsZero() {
		out.LocationFreshness = now.Sub(s.lastLocationAt)
	}
	s.applyClosureAssertions(&out)
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

// OpenFrunk is the toggle command for the frunk on cars with a powered
// frunk (2024 Berlin Y, Cybertruck, Plaid) — Tesla's SDK has no
// CloseFrunk equivalent because the same OpenFrunk message is treated
// by the car as "actuate, whatever state I'm in." We read the
// snapshot's current frunk state to know which direction the operator
// is asking for, then assert the OPPOSITE post-success so the snapshot
// reflects intent even while VCSEC's notoriously laggy frunk-closed
// sensor catches up.
func (s *TeslaService) OpenFrunk(ctx context.Context, userID int64) error {
	s.stateMu.RLock()
	currentlyClosed := s.snap.Closures.FrontTrunk == "closed"
	s.stateMu.RUnlock()
	err := s.runVCSECCommand(ctx, userID, "open_frunk", func(car *vehicle.Vehicle) error {
		return car.OpenFrunk(ctx)
	})
	if err == nil {
		// If it was closed, expect it to now be OPEN; if open, expect CLOSED.
		s.assertClosure("front_trunk", !currentlyClosed)
	}
	return err
}

func (s *TeslaService) OpenTrunk(ctx context.Context, userID int64) error {
	err := s.runVCSECCommand(ctx, userID, "open_trunk", func(car *vehicle.Vehicle) error {
		return car.OpenTrunk(ctx)
	})
	if err == nil {
		s.assertClosure("rear_trunk", false) // expect open
	}
	return err
}

func (s *TeslaService) CloseTrunk(ctx context.Context, userID int64) error {
	err := s.runVCSECCommand(ctx, userID, "close_trunk", func(car *vehicle.Vehicle) error {
		return car.CloseTrunk(ctx)
	})
	if err == nil {
		s.assertClosure("rear_trunk", true) // expect closed
	}
	return err
}

// OpenChargePort / CloseChargePort are CarServer (Infotainment-domain)
// actions, NOT VCSEC closures — unlike trunk/frunk which go through the
// security subsystem. Routing them through runVCSECCommand sent the
// signed message to a domain without a session and the car rejected
// with "cannot send authenticated command before establishing a vehicle
// session". Infotainment also means we wake the centre-console
// computer if asleep; that's fine — charge-port actions are an
// operator gesture, not background polling.
func (s *TeslaService) OpenChargePort(ctx context.Context, userID int64) error {
	err := s.runInfotainmentCommand(ctx, userID, "open_charge_port", true, func(car *vehicle.Vehicle) error {
		return car.OpenChargePort(ctx)
	})
	if err == nil {
		s.assertClosure("charge_port", false) // expect open
	}
	return err
}

func (s *TeslaService) CloseChargePort(ctx context.Context, userID int64) error {
	err := s.runInfotainmentCommand(ctx, userID, "close_charge_port", true, func(car *vehicle.Vehicle) error {
		return car.CloseChargePort(ctx)
	})
	if err == nil {
		s.assertClosure("charge_port", true) // expect closed
	}
	return err
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

func (s *TeslaService) VentWindows(ctx context.Context, userID int64) error {
	err := s.runInfotainmentCommand(ctx, userID, "vent_windows", true, func(car *vehicle.Vehicle) error {
		return car.VentWindows(ctx)
	})
	if err == nil {
		s.assertClosure("window_driver_front", false)
		s.assertClosure("window_passenger_front", false)
		s.assertClosure("window_driver_rear", false)
		s.assertClosure("window_passenger_rear", false)
	}
	return err
}

func (s *TeslaService) CloseWindows(ctx context.Context, userID int64) error {
	err := s.runInfotainmentCommand(ctx, userID, "close_windows", true, func(car *vehicle.Vehicle) error {
		return car.CloseWindows(ctx)
	})
	if err == nil {
		s.assertClosure("window_driver_front", true)
		s.assertClosure("window_passenger_front", true)
		s.assertClosure("window_driver_rear", true)
		s.assertClosure("window_passenger_rear", true)
	}
	return err
}

// SetDefrost toggles "preconditioning max" — Tesla's defrost mode that
// fires the front/rear defrosters + seat heaters + cabin heater hard
// regardless of climate setpoint.
//
// manualOverride is only meaningful for the on path — it tells the car
// "ignore auto-end heuristics, stay on until the operator says
// otherwise." On the off path, manualOverride=true would mean "force
// off and stay off" but on some firmware the car treats that
// combination as ambiguous and silently keeps defrost running. Pass
// false on off — auto behaviour will respect the explicit off and
// shut down cleanly.
func (s *TeslaService) SetDefrost(ctx context.Context, userID int64, on bool) error {
	name := "defrost_off"
	if on {
		name = "defrost_on"
	}
	manualOverride := on
	return s.runInfotainmentCommand(ctx, userID, name, true, func(car *vehicle.Vehicle) error {
		return car.SetPreconditioningMax(ctx, on, manualOverride)
	})
}

// SetCabinOverheatProtection toggles the summer-parking feature that
// keeps the cabin from cooking on hot days. fanOnly=false uses the AC
// compressor (faster, more power); fanOnly=true just runs the fan
// (gentler on the 12V battery). We expose only the on/off semantics
// and pick fanOnly=false to match Tesla's default behaviour.
func (s *TeslaService) SetCabinOverheatProtection(ctx context.Context, userID int64, on bool) error {
	name := "cabin_overheat_off"
	if on {
		name = "cabin_overheat_on"
	}
	return s.runInfotainmentCommand(ctx, userID, name, true, func(car *vehicle.Vehicle) error {
		return car.SetCabinOverheatProtection(ctx, on, false)
	})
}

// SetKeepAccessoryPower toggles "keep cabin powered after Park."
// Useful for camp mode + accessory-power use cases. Costs ~1% / hour
// of 12V drain when on; the car warns the operator about that on its
// own UI.
func (s *TeslaService) SetKeepAccessoryPower(ctx context.Context, userID int64, on bool) error {
	name := "keep_accessory_power_off"
	if on {
		name = "keep_accessory_power_on"
	}
	return s.runInfotainmentCommand(ctx, userID, name, true, func(car *vehicle.Vehicle) error {
		return car.SetKeepAccessoryPowerMode(ctx, on)
	})
}

// SetSeatHeater configures one seat's heater level. position is one of
// "front-left" / "front-right" / "rear-left" / "rear-center" /
// "rear-right" (we constrain to those — Model S has back-rest variants
// the SDK supports but they're niche). level is 0 (off) … 3 (high).
func (s *TeslaService) SetSeatHeater(ctx context.Context, userID int64, position string, level int) error {
	seat, ok := seatPositionFromString(position)
	if !ok {
		return fmt.Errorf("invalid seat position %q", position)
	}
	if level < 0 || level > 3 {
		return fmt.Errorf("seat heater level %d out of range (0-3)", level)
	}
	name := fmt.Sprintf("seat_heater:%s=%d", position, level)
	return s.runInfotainmentCommand(ctx, userID, name, true, func(car *vehicle.Vehicle) error {
		return car.SetSeatHeater(ctx, map[vehicle.SeatPosition]vehicle.Level{seat: vehicle.Level(level)})
	})
}

func seatPositionFromString(s string) (vehicle.SeatPosition, bool) {
	switch s {
	case "front-left":
		return vehicle.SeatFrontLeft, true
	case "front-right":
		return vehicle.SeatFrontRight, true
	case "rear-left":
		return vehicle.SeatSecondRowLeft, true
	case "rear-center":
		return vehicle.SeatSecondRowCenter, true
	case "rear-right":
		return vehicle.SeatSecondRowRight, true
	default:
		return vehicle.SeatUnknown, false
	}
}

// SetSeatCooler is the cooled-seat sibling of SetSeatHeater. Tesla
// only supports it on the two front seats (Plaid / Cybertruck);
// other vehicles will accept the action but the car-side controller
// silently no-ops. Tesla also does NOT report cooler level back in
// any state category, so the UI can't sync a slider to current
// reality — operator-set values stick locally until the page reloads.
func (s *TeslaService) SetSeatCooler(ctx context.Context, userID int64, position string, level int) error {
	seat, ok := seatPositionFromString(position)
	if !ok {
		return fmt.Errorf("invalid seat position %q", position)
	}
	if seat != vehicle.SeatFrontLeft && seat != vehicle.SeatFrontRight {
		return fmt.Errorf("seat coolers exist only on front seats; got %q", position)
	}
	if level < 0 || level > 3 {
		return fmt.Errorf("seat cooler level %d out of range (0-3)", level)
	}
	name := fmt.Sprintf("seat_cooler:%s=%d", position, level)
	return s.runInfotainmentCommand(ctx, userID, name, true, func(car *vehicle.Vehicle) error {
		return car.SetSeatCooler(ctx, vehicle.Level(level), seat)
	})
}

// SetSteeringWheelHeater is the simple on/off; some models also support
// a level (Plaid), but the SDK's helper is boolean.
func (s *TeslaService) SetSteeringWheelHeater(ctx context.Context, userID int64, on bool) error {
	name := "steering_wheel_heater_off"
	if on {
		name = "steering_wheel_heater_on"
	}
	return s.runInfotainmentCommand(ctx, userID, name, true, func(car *vehicle.Vehicle) error {
		return car.SetSteeringWheelHeater(ctx, on)
	})
}

// ─── V4.3: charge profile shortcuts ──────────────────────────────

// ChargeMaxRange flips the charge limit to the Trip / Max-Range
// preset (typically 100%). Tesla auto-restores Standard on next
// completion when over-set.
func (s *TeslaService) ChargeMaxRange(ctx context.Context, userID int64) error {
	return s.runInfotainmentCommand(ctx, userID, "charge_max_range", true, func(car *vehicle.Vehicle) error {
		return car.ChargeMaxRange(ctx)
	})
}

func (s *TeslaService) ChargeStandardRange(ctx context.Context, userID int64) error {
	return s.runInfotainmentCommand(ctx, userID, "charge_standard_range", true, func(car *vehicle.Vehicle) error {
		return car.ChargeStandardRange(ctx)
	})
}

// ─── V4.3: guest / drive / climate-keeper ────────────────────────

func (s *TeslaService) SetGuestMode(ctx context.Context, userID int64, on bool) error {
	name := "guest_mode_off"
	if on {
		name = "guest_mode_on"
	}
	return s.runInfotainmentCommand(ctx, userID, name, true, func(car *vehicle.Vehicle) error {
		return car.SetGuestMode(ctx, on)
	})
}

// RemoteDrive is Tesla's "remote start" — primes the drive system
// so the operator can leave Park without the key. Acts as a key for
// up to two minutes. Doesn't actually move the car.
func (s *TeslaService) RemoteDrive(ctx context.Context, userID int64) error {
	return s.runVCSECCommand(ctx, userID, "remote_drive", func(car *vehicle.Vehicle) error {
		return car.RemoteDrive(ctx)
	})
}

// SetClimateKeeperMode picks one of Off / On / Dog / Camp. The SDK
// takes its own enum; we accept a string from the client (cleaner
// JSON surface) and translate.
func (s *TeslaService) SetClimateKeeperMode(ctx context.Context, userID int64, mode string) error {
	var m vehicle.ClimateKeeperMode
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "off":
		m = vehicle.ClimateKeeperModeOff
	case "on":
		m = vehicle.ClimateKeeperModeOn
	case "dog":
		m = vehicle.ClimateKeeperModeDog
	case "camp":
		m = vehicle.ClimateKeeperModeCamp
	default:
		return fmt.Errorf("invalid climate keeper mode %q (want off|on|dog|camp)", mode)
	}
	return s.runInfotainmentCommand(ctx, userID, "climate_keeper:"+mode, true, func(car *vehicle.Vehicle) error {
		// The override flag controls whether a smart-precondition cycle
		// can pre-empt; we pass false so manual mode is honoured.
		return car.SetClimateKeeperMode(ctx, m, false)
	})
}

// ─── V4.3: valet / speed-limit (PIN-protected) ───────────────────
//
// Each takes a string PIN. Tesla accepts 4-digit numeric PINs; we
// validate that shape client-side. We do NOT log the PIN in audit
// rows — the command name records the action; the PIN stays in the
// signed BLE payload and never lands in tesla_command_log.

func (s *TeslaService) SetValetMode(ctx context.Context, userID int64, on bool, pin string) error {
	if on {
		if err := validateTeslaPIN(pin); err != nil {
			return fmt.Errorf("valet PIN: %w", err)
		}
	}
	name := "valet_off"
	if on {
		name = "valet_on"
	}
	return s.runInfotainmentCommand(ctx, userID, name, true, func(car *vehicle.Vehicle) error {
		return car.SetValetMode(ctx, on, pin)
	})
}

func (s *TeslaService) ActivateSpeedLimit(ctx context.Context, userID int64, pin string) error {
	if err := validateTeslaPIN(pin); err != nil {
		return fmt.Errorf("speed-limit PIN: %w", err)
	}
	return s.runInfotainmentCommand(ctx, userID, "speed_limit_activate", true, func(car *vehicle.Vehicle) error {
		return car.ActivateSpeedLimit(ctx, pin)
	})
}

func (s *TeslaService) DeactivateSpeedLimit(ctx context.Context, userID int64, pin string) error {
	if err := validateTeslaPIN(pin); err != nil {
		return fmt.Errorf("speed-limit PIN: %w", err)
	}
	return s.runInfotainmentCommand(ctx, userID, "speed_limit_deactivate", true, func(car *vehicle.Vehicle) error {
		return car.DeactivateSpeedLimit(ctx, pin)
	})
}

func (s *TeslaService) ClearSpeedLimitPIN(ctx context.Context, userID int64, pin string) error {
	if err := validateTeslaPIN(pin); err != nil {
		return fmt.Errorf("speed-limit PIN: %w", err)
	}
	return s.runInfotainmentCommand(ctx, userID, "speed_limit_clear_pin", true, func(car *vehicle.Vehicle) error {
		return car.ClearSpeedLimitPIN(ctx, pin)
	})
}

// SetSpeedLimitMPH sets the cap in MPH. Tesla's UI prompts MPH even
// in regions that prefer km/h — the underlying field is MPH on the wire.
// Caller converts if needed.
func (s *TeslaService) SetSpeedLimitMPH(ctx context.Context, userID int64, mph float64) error {
	if mph < 50 || mph > 90 {
		return fmt.Errorf("speed limit must be 50-90 MPH; got %v", mph)
	}
	return s.runInfotainmentCommand(ctx, userID, fmt.Sprintf("speed_limit_set:%v", mph), true, func(car *vehicle.Vehicle) error {
		return car.SpeedLimitSetLimitMPH(ctx, mph)
	})
}

// ─── V4.3 Phase 3: navigation + boombox (custom-fork actions) ────────
//
// These commands aren't in upstream vehicle-command but live on our
// fork (github.com/ivan-prodanov/vehicle-command, branch
// feat/v4.3-nav-boombox). The proto messages and field numbers
// matched the python-tesla-fleet-api descriptor — same wire shape
// production cars accept.

// NavigateGPS sends a destination by lat/lon. order semantics:
//   0 = REPLACE (clear existing route + set fresh)  ← default for /garage
//   1 = PREPEND (add before current first stop)
//   2 = APPEND  (add at end of current route)
func (s *TeslaService) NavigateGPS(ctx context.Context, userID int64, lat, lon float64, order int) error {
	o := remoteNavOrderFromInt(order)
	return s.runInfotainmentCommand(ctx, userID, fmt.Sprintf("navigate_gps:%.5f,%.5f", lat, lon), true, func(car *vehicle.Vehicle) error {
		return car.NavigationGpsRequest(ctx, lat, lon, o)
	})
}

// NavigateGPSWithLabel is NavigateGPS plus the on-screen LABEL the car
// shows in its nav UI ("Home", "Office", whatever the operator wants).
// Coordinates still drive the routing; the label is cosmetic.
func (s *TeslaService) NavigateGPSWithLabel(ctx context.Context, userID int64, lat, lon float64, label string, order int) error {
	o := remoteNavOrderFromIntDest(order)
	return s.runInfotainmentCommand(ctx, userID, fmt.Sprintf("navigate_gps_labeled:%.5f,%.5f", lat, lon), true, func(car *vehicle.Vehicle) error {
		return car.NavigationGpsDestinationRequest(ctx, lat, lon, label, o)
	})
}

// NavigateSearch sends a free-text destination string. The car
// geocodes locally / via Tesla's cloud. Less precise than the GPS
// variants — useful when the operator only has a place name.
func (s *TeslaService) NavigateSearch(ctx context.Context, userID int64, query string, order int) error {
	return s.runInfotainmentCommand(ctx, userID, "navigate_search", true, func(car *vehicle.Vehicle) error {
		return car.NavigationRequest(ctx, query, int32(order))
	})
}

// NavigateWaypoints sends a multi-stop trip plan. waypoints is a
// comma-separated Google-Place-ID string per Tesla's wire format.
// Painful to type by hand; we expose it because PR #443 confirmed it
// works on production cars, leaving the door open for a future
// /garage integration that hands operators a Place-ID lookup.
func (s *TeslaService) NavigateWaypoints(ctx context.Context, userID int64, waypoints string) error {
	return s.runInfotainmentCommand(ctx, userID, "navigate_waypoints", true, func(car *vehicle.Vehicle) error {
		return car.NavigationWaypointsRequest(ctx, waypoints, nil)
	})
}

// RemoteBoombox plays one of the car's external-speaker sounds. The
// `sound` int is Tesla's opaque enum — exact values shift between
// firmware versions, so we pass through what the operator picks.
func (s *TeslaService) RemoteBoombox(ctx context.Context, userID int64, sound int) error {
	if sound < 0 || sound > 65535 {
		return fmt.Errorf("boombox sound out of uint16 range (0-65535)")
	}
	return s.runInfotainmentCommand(ctx, userID, fmt.Sprintf("boombox:%d", sound), true, func(car *vehicle.Vehicle) error {
		return car.RemoteBoombox(ctx, uint32(sound))
	})
}

// remoteNavOrderFromInt / *Dest map our integer arg to the SDK's enum.
// The two functions exist because protoc generated DIFFERENT enum
// types for the two requests even though their values match — they
// share message families.
func remoteNavOrderFromInt(i int) carserver.NavigationGpsRequest_RemoteNavTripOrder {
	switch i {
	case 1:
		return carserver.NavigationGpsRequest_REMOTE_NAV_TRIP_ORDER_REPLACE
	case 2:
		return carserver.NavigationGpsRequest_REMOTE_NAV_TRIP_ORDER_PREPEND
	case 3:
		return carserver.NavigationGpsRequest_REMOTE_NAV_TRIP_ORDER_APPEND
	default:
		return carserver.NavigationGpsRequest_REMOTE_NAV_TRIP_ORDER_REPLACE
	}
}

func remoteNavOrderFromIntDest(i int) carserver.NavigationGpsDestinationRequest_RemoteNavTripOrder {
	switch i {
	case 1:
		return carserver.NavigationGpsDestinationRequest_REMOTE_NAV_TRIP_ORDER_REPLACE
	case 2:
		return carserver.NavigationGpsDestinationRequest_REMOTE_NAV_TRIP_ORDER_PREPEND
	case 3:
		return carserver.NavigationGpsDestinationRequest_REMOTE_NAV_TRIP_ORDER_APPEND
	default:
		return carserver.NavigationGpsDestinationRequest_REMOTE_NAV_TRIP_ORDER_REPLACE
	}
}

// validateTeslaPIN constrains to 4 numeric digits, matching Tesla's
// own onboarding constraint.
func validateTeslaPIN(pin string) error {
	if len(pin) != 4 {
		return fmt.Errorf("PIN must be exactly 4 digits")
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return fmt.Errorf("PIN must be numeric")
		}
	}
	return nil
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

// teslaInfotainmentMaxAge caps how old the cached Charge/Climate/etc
// data is allowed to get before the poller refreshes it — but ONLY
// when the car is already awake (so we don't pay the wake-12V cost
// for cosmetic freshness). When the car is asleep, the cached data
// ages indefinitely and the /garage UI honestly displays "N minutes
// ago." The operator can force-refresh from the Refresh button if
// they actually need fresh data right now.
const teslaInfotainmentMaxAge = 2 * time.Minute

func (s *TeslaService) runPoller(ctx context.Context) {
	defer close(s.pollerDone)
	tick := time.NewTicker(teslaPollInterval)
	defer tick.Stop()
	for {
		if s.IsPaired() {
			pollCtx, cancel := context.WithTimeout(ctx, teslaCommandTimeout+teslaScanTimeout)
			if err := s.PollBodyControllerState(pollCtx); err != nil {
				if !errors.Is(err, context.DeadlineExceeded) {
					log.Printf("[TESLA] poll BCS: %v", err)
				}
			}
			cancel()

			// Opportunistic Infotainment refresh: piggyback on the
			// fact that the car just answered BCS. If it's awake AND
			// our cached Charge/Climate is stale, refresh those too —
			// the car is up already, no wake cost. If asleep, skip.
			s.stateMu.RLock()
			awake := s.snap.SleepStatus == "awake"
			cacheOld := s.lastChargeAt.IsZero() ||
				time.Since(s.lastChargeAt) > teslaInfotainmentMaxAge
			s.stateMu.RUnlock()
			if awake && cacheOld {
				icCtx, icCancel := context.WithTimeout(ctx, teslaCommandTimeout+teslaScanTimeout)
				// wake=false — we believe the car is already awake;
				// if BCS lied, the call no-ops and the cache just
				// stays stale until the next opportunity.
				if err := s.PollChargeAndClimate(icCtx, false); err != nil {
					if !errors.Is(err, context.DeadlineExceeded) {
						log.Printf("[TESLA] opportunistic Infotainment refresh: %v", err)
					}
				}
				icCancel()
			}
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
	s.snap.IsPreconditioning = cl.GetIsPreconditioning()
	// Defrost mode is a separate oneof from is_preconditioning. The
	// /garage "Defrost" button drives SetPreconditioningMax which the
	// car reflects as DefrostMode_Max (or sometimes Normal). The
	// is_preconditioning bool is Tesla's "pre-departure smart climate"
	// flag, not what the operator clicked — confused them earlier.
	if dm := cl.GetDefrostMode(); dm != nil {
		switch dm.GetType().(type) {
		case *carserver.ClimateState_DefrostMode_Max:
			s.snap.DefrostOn = true
			s.snap.DefrostMax = true
		case *carserver.ClimateState_DefrostMode_Normal:
			s.snap.DefrostOn = true
			s.snap.DefrostMax = false
		default:
			s.snap.DefrostOn = false
			s.snap.DefrostMax = false
		}
	}
	s.snap.FanStatus = cl.GetFanStatus()
	s.snap.SeatHeaterLeft = cl.GetSeatHeaterLeft()
	s.snap.SeatHeaterRight = cl.GetSeatHeaterRight()
	s.snap.SeatHeaterRearLeft = cl.GetSeatHeaterRearLeft()
	s.snap.SeatHeaterRearCenter = cl.GetSeatHeaterRearCenter()
	s.snap.SeatHeaterRearRight = cl.GetSeatHeaterRearRight()
	s.snap.SteeringWheelHeater = cl.GetSteeringWheelHeater()
	s.snap.FrontDefrosterOn = cl.GetIsFrontDefrosterOn()
	s.snap.RearDefrosterOn = cl.GetIsRearDefrosterOn()
	// GetAllowCabinOverheatProtection is the FEATURE-PERMITTED bit
	// (is COP supported / not blocked by user prefs). The actual
	// current state is the enum on GetCabinOverheatProtection —
	// Off / On / FanOnly. We collapse FanOnly to "on" for the toggle
	// since the operator-facing distinction doesn't matter at the
	// /garage level (it'd matter on a dedicated COP settings dialog).
	cop := cl.GetCabinOverheatProtection()
	s.snap.CabinOverheatProtection = cop == carserver.ClimateState_CabinOverheatProtectionOn ||
		cop == carserver.ClimateState_CabinOverheatProtectionFanOnly
}

// updateClosures takes the CarServer (Infotainment) ClosuresState —
// richer than VCSEC's set: includes windows + sentry-mode availability
// + the post-press latches on the charge port that VCSEC's sensor
// lags on. We only PARTIALLY merge into the closures snapshot — keep
// the door states from VCSEC (more reliable for those) but take
// windows + sentry from here.
func (s *TeslaService) updateClosures(cs *carserver.ClosuresState) {
	if cs == nil {
		return
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.snap.Closures.WindowDriverFront = cs.GetWindowOpenDriverFront()
	s.snap.Closures.WindowPassengerFront = cs.GetWindowOpenPassengerFront()
	s.snap.Closures.WindowDriverRear = cs.GetWindowOpenDriverRear()
	s.snap.Closures.WindowPassengerRear = cs.GetWindowOpenPassengerRear()
	// Each closure is wrapped in a proto3 optional/oneof. Read the
	// oneof itself (not the plain Get*) so we can distinguish
	// "field set to false" from "field never emitted." Helper below.
	s.snap.Closures.InfDoorOpenDriverFront = boolFromDoorOpenDriverFront(cs)
	s.snap.Closures.InfDoorOpenPassengerFront = boolFromDoorOpenPassengerFront(cs)
	s.snap.Closures.InfDoorOpenDriverRear = boolFromDoorOpenDriverRear(cs)
	s.snap.Closures.InfDoorOpenPassengerRear = boolFromDoorOpenPassengerRear(cs)
	s.snap.Closures.InfTrunkFrontOpen = boolFromDoorOpenTrunkFront(cs)
	s.snap.Closures.InfTrunkRearOpen = boolFromDoorOpenTrunkRear(cs)
	s.snap.Closures.InfLocked = boolFromLocked(cs)
	s.snap.Closures.SentryAvailable = cs.GetSentryModeAvailable()
	if sm := cs.GetSentryModeState(); sm != nil {
		// SentryModeState is a oneof; GetType() returns the variant.
		// "Sentry enabled" from the operator's perspective covers four
		// of the five variants — Off is the only state that means
		// "the feature is disabled." Idle is the typical resting state
		// when Sentry is enabled but no event has triggered, and the
		// earlier code wrongly classified that as off — making the
		// toggle button always send 'on' even when sentry was already
		// running.
		switch sm.GetType().(type) {
		case *carserver.ClosuresState_SentryModeState_Off:
			s.snap.Closures.SentryOn = false
		default:
			s.snap.Closures.SentryOn = true
		}
	}
}

func (s *TeslaService) updateTirePressure(tp *carserver.TirePressureState) {
	if tp == nil {
		return
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.lastTPAt = time.Now()
	s.snap.TirePressure = TirePressureSnapshot{
		FrontLeftBar:          tp.GetTpmsPressureFl(),
		FrontRightBar:         tp.GetTpmsPressureFr(),
		RearLeftBar:           tp.GetTpmsPressureRl(),
		RearRightBar:          tp.GetTpmsPressureRr(),
		HardWarningFrontLeft:  tp.GetTpmsHardWarningFl(),
		HardWarningFrontRight: tp.GetTpmsHardWarningFr(),
		HardWarningRearLeft:   tp.GetTpmsHardWarningRl(),
		HardWarningRearRight:  tp.GetTpmsHardWarningRr(),
	}
}

func (s *TeslaService) updateLocation(ls *carserver.LocationState) {
	if ls == nil {
		return
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.lastLocationAt = time.Now()
	s.snap.Location = LocationSnapshot{
		Latitude:  ls.GetLatitude(),
		Longitude: ls.GetLongitude(),
	}
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

// boolFromDoorOpen* + boolFromLocked: per-field proto3-optional readers.
// Each returns *bool — nil when the car didn't emit the optional, the
// real bool when it did. The UI uses this to distinguish "Tesla
// reports closed" from "Tesla reports nothing, fall back to VCSEC".
//
// We can't write one generic helper because each oneof's concrete
// type is distinct in the SDK; the cost is one function per closure,
// the win is "frunk no longer pins at closed forever" on Model Y.

func boolFromDoorOpenDriverFront(cs *carserver.ClosuresState) *bool {
	if x, ok := cs.GetOptionalDoorOpenDriverFront().(*carserver.ClosuresState_DoorOpenDriverFront); ok {
		v := x.DoorOpenDriverFront
		return &v
	}
	return nil
}

func boolFromDoorOpenPassengerFront(cs *carserver.ClosuresState) *bool {
	if x, ok := cs.GetOptionalDoorOpenPassengerFront().(*carserver.ClosuresState_DoorOpenPassengerFront); ok {
		v := x.DoorOpenPassengerFront
		return &v
	}
	return nil
}

func boolFromDoorOpenDriverRear(cs *carserver.ClosuresState) *bool {
	if x, ok := cs.GetOptionalDoorOpenDriverRear().(*carserver.ClosuresState_DoorOpenDriverRear); ok {
		v := x.DoorOpenDriverRear
		return &v
	}
	return nil
}

func boolFromDoorOpenPassengerRear(cs *carserver.ClosuresState) *bool {
	if x, ok := cs.GetOptionalDoorOpenPassengerRear().(*carserver.ClosuresState_DoorOpenPassengerRear); ok {
		v := x.DoorOpenPassengerRear
		return &v
	}
	return nil
}

func boolFromDoorOpenTrunkFront(cs *carserver.ClosuresState) *bool {
	if x, ok := cs.GetOptionalDoorOpenTrunkFront().(*carserver.ClosuresState_DoorOpenTrunkFront); ok {
		v := x.DoorOpenTrunkFront
		return &v
	}
	return nil
}

func boolFromDoorOpenTrunkRear(cs *carserver.ClosuresState) *bool {
	if x, ok := cs.GetOptionalDoorOpenTrunkRear().(*carserver.ClosuresState_DoorOpenTrunkRear); ok {
		v := x.DoorOpenTrunkRear
		return &v
	}
	return nil
}

func boolFromLocked(cs *carserver.ClosuresState) *bool {
	if x, ok := cs.GetOptionalLocked().(*carserver.ClosuresState_Locked); ok {
		v := x.Locked
		return &v
	}
	return nil
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
