// tesla-poc — V4 BLE range + capability spike. Throwaway code.
//
// Three things to prove before V4 commits to a BLE architecture:
//
//   1. The Pi 4 in the glovebox can see the Tesla's BLE radio reliably.
//      We log RSSI per scan and per-command round-trip latency. -75dBm
//      and below gets flaky; -65 to -55 is comfortable; better than -50
//      means the antenna position is great.
//
//   2. Pairing through the Tesla mobile app actually works with a
//      Go-SDK-generated key. The spike generates a PEM at
//      /var/lib/netfilterd/tesla/private_key.pem on first run and prints
//      the public key for the operator to drop into the Tesla app's
//      Add Key flow. Subsequent runs reuse it.
//
//   3. The "battery %" lives where the docs say it does: via the BLE
//      CarServer GetVehicleData → ChargeState path. We wake the
//      infotainment computer, query charge + climate, and print the
//      fields V4's /garage page will eventually surface. If battery_level
//      and battery_range come back populated, Tier C (Panda) stays cut.
//
// Usage on the Pi (with Pi sitting in the Tesla's glovebox):
//
//   sudo ./tesla-poc -vin 5YJ3...  -pair      # first run only
//   sudo ./tesla-poc -vin 5YJ3...              # subsequent reads
//
// Requires root for BLE scan + connect. Caps would also work; root is
// fine for a spike.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/connector/ble"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	universal "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/vehicle"
)

const (
	defaultKeyPath = "/var/lib/netfilterd/tesla/private_key.pem"
	connectTimeout = 30 * time.Second
	commandTimeout = 15 * time.Second
)

func main() {
	var (
		vin       = flag.String("vin", "", "Vehicle VIN (full 17 chars)")
		keyPath   = flag.String("key", defaultKeyPath, "Path to NIST-P256 SEC1 PEM private key")
		doPair    = flag.Bool("pair", false, "First-run mode: generate key + print fingerprint, then exit so you can enrol via the Tesla mobile app")
		probeWake = flag.Bool("wake", true, "Wake the infotainment computer before querying charge/climate state (false = body-controller-state only)")
	)
	flag.Parse()
	if *vin == "" {
		log.Fatal("--vin required (full 17-char VIN; printed on the door jamb sticker or in the mobile app)")
	}

	// Step 1: key — load if present, generate if not.
	privKey, generated, err := loadOrGenerateKey(*keyPath)
	if err != nil {
		log.Fatalf("key: %v", err)
	}
	if generated || *doPair {
		log.Printf("private key at %s", *keyPath)
		pubPEM, err := publicKeyPEM(privKey)
		if err != nil {
			log.Fatalf("pubkey extraction: %v", err)
		}
		log.Println("public key (paste into Tesla app → Locks → Add Key, or save as a file and import):")
		fmt.Println()
		fmt.Print(pubPEM)
		fmt.Println()
		if *doPair {
			log.Println("--pair set: stopping here. Enrol the key in the Tesla mobile app, tap your physical NFC key card on the centre console, then re-run without --pair.")
			return
		}
	}

	// Step 2: BLE adapter + scan. ble.ScanVehicleBeacon returns once it
	// sees the Tesla's advertising packet — that tells us we can reach
	// the radio at all and gives us the first RSSI sample.
	log.Println("initialising BLE adapter (hci0)…")
	if err := ble.InitAdapterWithID("hci0"); err != nil {
		log.Fatalf("BLE adapter init: %v (is bluetoothd running? are we root?)", err)
	}

	scanCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	t0 := time.Now()
	log.Printf("scanning for Tesla beacon (VIN %s)…", *vin)
	beacon, err := ble.ScanVehicleBeacon(scanCtx, *vin)
	if err != nil {
		log.Fatalf("scan: %v (Pi in BLE range of the car? Glovebox should be ~1m from the centre console radio)", err)
	}
	log.Printf("FOUND  name=%q  addr=%s  RSSI=%ddBm  (scan took %s)",
		beacon.LocalName, beacon.Address, beacon.RSSI, time.Since(t0).Round(time.Millisecond))
	rssiVerdict(int(beacon.RSSI))

	// Step 3: connect + session.
	log.Println("opening BLE connection…")
	t1 := time.Now()
	conn, err := ble.NewConnectionFromScanResult(scanCtx, *vin, beacon)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	log.Printf("connected in %s", time.Since(t1).Round(time.Millisecond))

	car, err := vehicle.NewVehicle(conn, privKey, nil)
	if err != nil {
		log.Fatalf("vehicle: %v", err)
	}

	sessCtx, sessCancel := context.WithTimeout(context.Background(), commandTimeout)
	defer sessCancel()
	t2 := time.Now()
	if err := car.Connect(sessCtx); err != nil {
		log.Fatalf("car.Connect: %v", err)
	}
	// Session for the VCSEC domain (cheap state — locks, closures, sleep).
	if err := car.StartSession(sessCtx, []universal.Domain{universal.Domain_DOMAIN_VEHICLE_SECURITY}); err != nil {
		log.Fatalf("StartSession(VCSEC): %v (is the key enrolled? if you just paired, give it 30s and tap the NFC card on the console)", err)
	}
	log.Printf("VCSEC session up in %s", time.Since(t2).Round(time.Millisecond))

	// Step 4: cheap read — body-controller-state. Works whether or not
	// the infotainment is awake. This is the call /garage's background
	// 30s poll will use.
	log.Println("reading body-controller-state…")
	t3 := time.Now()
	bcsCtx, bcsCancel := context.WithTimeout(context.Background(), commandTimeout)
	defer bcsCancel()
	bcs, err := car.BodyControllerState(bcsCtx)
	if err != nil {
		log.Fatalf("BodyControllerState: %v", err)
	}
	log.Printf("body-controller-state in %s", time.Since(t3).Round(time.Millisecond))
	fmt.Printf("  vehicleLockState:   %v\n", bcs.GetVehicleLockState())
	fmt.Printf("  vehicleSleepStatus: %v\n", bcs.GetVehicleSleepStatus())
	fmt.Printf("  userPresence:       %v\n", bcs.GetUserPresence())
	if cs := bcs.GetClosureStatuses(); cs != nil {
		fmt.Printf("  closures:           frontDriver=%v frontPassenger=%v rearDriver=%v rearPassenger=%v frunk=%v trunk=%v chargePort=%v tonneau=%v\n",
			cs.GetFrontDriverDoor(), cs.GetFrontPassengerDoor(),
			cs.GetRearDriverDoor(), cs.GetRearPassengerDoor(),
			cs.GetFrontTrunk(), cs.GetRearTrunk(),
			cs.GetChargePort(), cs.GetTonneau())
	}

	if !*probeWake {
		log.Println("skipping charge/climate probe (--wake=false)")
		return
	}

	// Step 5: start an Infotainment session — that's the domain that
	// answers GetVehicleData → charge_state / climate_state. If the
	// infotainment is asleep, we'll need to wake it first.
	log.Println("starting Infotainment session for charge/climate state…")
	t4 := time.Now()
	infoCtx, infoCancel := context.WithTimeout(context.Background(), commandTimeout)
	defer infoCancel()
	if err := car.StartSession(infoCtx, []universal.Domain{universal.Domain_DOMAIN_INFOTAINMENT}); err != nil {
		log.Printf("Infotainment session refused (likely asleep): %v — waking the car", err)
		wakeCtx, wakeCancel := context.WithTimeout(context.Background(), commandTimeout)
		if werr := car.Wakeup(wakeCtx); werr != nil {
			wakeCancel()
			log.Fatalf("Wakeup: %v", werr)
		}
		wakeCancel()
		log.Println("wake sent — waiting 10s for the infotainment to come up…")
		time.Sleep(10 * time.Second)
		infoCtx2, infoCancel2 := context.WithTimeout(context.Background(), commandTimeout)
		defer infoCancel2()
		if err := car.StartSession(infoCtx2, []universal.Domain{universal.Domain_DOMAIN_INFOTAINMENT}); err != nil {
			log.Fatalf("Infotainment session (after wake): %v", err)
		}
	}
	log.Printf("Infotainment session up in %s", time.Since(t4).Round(time.Millisecond))

	// Step 6: the answer to "does BLE actually give us battery %?"
	// GetState(StateCategoryCharge) returns the same CarServer
	// VehicleData shape Fleet API gives, but routed through BLE.
	log.Println("reading charge state…")
	t5 := time.Now()
	chgCtx, chgCancel := context.WithTimeout(context.Background(), commandTimeout)
	defer chgCancel()
	chargeData, err := car.GetState(chgCtx, vehicle.StateCategoryCharge)
	if err != nil {
		log.Fatalf("GetState(charge): %v", err)
	}
	log.Printf("charge state in %s", time.Since(t5).Round(time.Millisecond))
	if cs := chargeData.GetChargeState(); cs != nil {
		fmt.Printf("  battery_level:        %v %%\n", cs.GetBatteryLevel())
		fmt.Printf("  usable_battery_level: %v %%\n", cs.GetUsableBatteryLevel())
		fmt.Printf("  battery_range:        %v\n", cs.GetBatteryRange())
		fmt.Printf("  est_battery_range:    %v\n", cs.GetEstBatteryRange())
		fmt.Printf("  charge_limit_soc:     %v %%\n", cs.GetChargeLimitSoc())
		fmt.Printf("  charger_power:        %v kW\n", cs.GetChargerPower())
		fmt.Printf("  charger_voltage:      %v V\n", cs.GetChargerVoltage())
		fmt.Printf("  charger_actual_curr:  %v A\n", cs.GetChargerActualCurrent())
		fmt.Printf("  minutes_to_full:      %v min\n", cs.GetMinutesToFullCharge())
		fmt.Printf("  charge_port_door:     open=%v\n", cs.GetChargePortDoorOpen())
		fmt.Printf("  fast_charger_present: %v\n", cs.GetFastChargerPresent())
	} else {
		log.Println("  (no charge_state in response — that's the answer we need to know)")
	}

	// Step 7: climate.
	log.Println("reading climate state…")
	t6 := time.Now()
	climCtx, climCancel := context.WithTimeout(context.Background(), commandTimeout)
	defer climCancel()
	climateData, err := car.GetState(climCtx, vehicle.StateCategoryClimate)
	if err != nil {
		log.Printf("GetState(climate): %v (charge worked though — partial success is informative)", err)
		return
	}
	log.Printf("climate state in %s", time.Since(t6).Round(time.Millisecond))
	if cl := climateData.GetClimateState(); cl != nil {
		fmt.Printf("  inside_temp:          %v °C\n", cl.GetInsideTempCelsius())
		fmt.Printf("  outside_temp:         %v °C\n", cl.GetOutsideTempCelsius())
		fmt.Printf("  driver_temp_setting:  %v °C\n", cl.GetDriverTempSetting())
		fmt.Printf("  is_climate_on:        %v\n", cl.GetIsClimateOn())
		fmt.Printf("  fan_status:           %v\n", cl.GetFanStatus())
		fmt.Printf("  seat_heater_left:     %v\n", cl.GetSeatHeaterLeft())
		fmt.Printf("  seat_heater_right:    %v\n", cl.GetSeatHeaterRight())
	}

	log.Println()
	log.Println("SPIKE COMPLETE — if every section above produced data, V4 Tier A is a go.")
}

// loadOrGenerateKey returns the operator's BLE private key, creating it
// on first run. We generate a vanilla P-256 ECDSA key with crypto/ecdsa
// and write it as SEC1 PEM ("EC PRIVATE KEY") — the same format the
// vehicle-command SDK's protocol.LoadPrivateKey expects (see the
// SavePrivateKey implementation in pkg/protocol/key.go). This avoids
// the SDK's internal NewECDHPrivateKey, which lives in an internal
// package and isn't reachable from here.
func loadOrGenerateKey(path string) (priv protocol.ECDHPrivateKey, generated bool, err error) {
	if _, statErr := os.Stat(path); statErr == nil {
		k, err := protocol.LoadPrivateKey(path)
		return k, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("mkdir key dir: %w", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate ECDSA P-256 key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return nil, false, fmt.Errorf("marshal EC private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, false, fmt.Errorf("write key: %w", err)
	}
	k, err := protocol.LoadPrivateKey(path)
	if err != nil {
		return nil, false, fmt.Errorf("reload generated key: %w", err)
	}
	return k, true, nil
}

// publicKeyPEM extracts the public component from the SDK's
// ECDHPrivateKey and returns it as a PEM "PUBLIC KEY" block — the form
// the Tesla mobile app's Add Key flow accepts.
func publicKeyPEM(priv protocol.ECDHPrivateKey) (string, error) {
	pubBytes := priv.PublicBytes()
	if len(pubBytes) == 0 {
		return "", fmt.Errorf("empty public bytes")
	}
	// PublicBytes is the SEC1 uncompressed point (0x04 || X || Y); we
	// re-pack as an X.509 SubjectPublicKeyInfo for PEM consumers like
	// the Tesla app.
	x, y := elliptic.Unmarshal(elliptic.P256(), pubBytes)
	if x == nil {
		return "", fmt.Errorf("unmarshal SEC1 public point failed")
	}
	pubEC := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	der, err := x509.MarshalPKIXPublicKey(pubEC)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func rssiVerdict(rssi int) {
	switch {
	case rssi >= -55:
		log.Printf("RSSI verdict: EXCELLENT (≥ -55dBm) — well within usable range")
	case rssi >= -65:
		log.Printf("RSSI verdict: GOOD (-55 to -65dBm) — comfortable for V4")
	case rssi >= -75:
		log.Printf("RSSI verdict: MARGINAL (-65 to -75dBm) — works but may drop under load; consider repositioning")
	default:
		log.Printf("RSSI verdict: POOR (< -75dBm) — V4 needs either repositioning or a USB BLE dongle with external antenna")
	}
}
