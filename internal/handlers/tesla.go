// Tesla BLE HTTP surface.
//
// The handler is intentionally thin — every method is the same shape:
// pull (ctx, userID), call the service, JSON the result. The BLE
// machinery (key gen, scan, session, retry-after-wake) all lives in
// services/tesla.go where it can be unit-tested without HTTP.
//
// One ergonomic decision worth flagging: state reads return a single
// "snapshot" object that always contains every field /garage needs,
// with per-section freshness in milliseconds. The UI uses freshness
// to decide what to render — e.g. battery card hides if no charge
// data has been collected, since /garage starts cold on a fresh
// install.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// decodeJSON reads + decodes a single JSON body into v with the standard
// guards: cap body size at 64KB, reject unknown fields so a typo in the
// client doesn't silently no-op.
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

type TeslaHandler struct {
	tesla    *services.TeslaService
	audit    *services.AuditService
	renderer *Renderer
}

func NewTeslaHandler(svc *services.Services, renderer *Renderer) *TeslaHandler {
	return &TeslaHandler{
		tesla:    svc.Tesla,
		audit:    svc.Audit,
		renderer: renderer,
	}
}

// Page renders /garage. The template gets nothing from the handler —
// it pulls every dynamic field via /api/tesla/* on mount.
func (h *TeslaHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "garage.html", map[string]string{"page": "garage"})
}

// ── Pairing flow ──────────────────────────────────────────────────

// PairingInfo returns the public key the operator must enrol in the
// Tesla mobile app, plus the current pairing state. The key is
// generated on first call and persists from there on — calling this
// repeatedly is safe.
func (h *TeslaHandler) PairingInfo(w http.ResponseWriter, r *http.Request) {
	pub, err := h.tesla.PublicKeyPEM()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]any{
		"vin":            h.tesla.VIN(),
		"paired":         h.tesla.IsPaired(),
		"public_key_pem": pub,
	})
}

// SetVIN accepts the user's VIN. Validation is in the service layer
// (17 chars, alphanumeric upper). After this, ConfirmPairing can run.
func (h *TeslaHandler) SetVIN(w http.ResponseWriter, r *http.Request) {
	var body struct {
		VIN string `json:"vin"`
	}
	if err := decodeJSON(r, &body); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.tesla.SetVIN(body.VIN); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	user := GetUser(r)
	if user != nil {
		h.audit.Log("tesla.set_vin", user.Username+" set VIN to "+body.VIN)
	}
	JSON(w, http.StatusOK, map[string]string{"vin": body.VIN})
}

// RequestPairing sends the add-key-request to the car. The car then
// prompts the operator on the centre-console screen to tap a physical
// NFC key card; that's the human gesture that authorises the new key.
// The handler returns as soon as the request is on the wire — the UI
// then polls ConfirmPairing to detect when the car has accepted.
func (h *TeslaHandler) RequestPairing(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := teslaCtx(r, 45*time.Second)
	defer cancel()
	if err := h.tesla.RequestPairing(ctx); err != nil {
		JSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	user := GetUser(r)
	if user != nil {
		h.audit.Log("tesla.pair_request", user.Username+" sent add-key-request to the car")
	}
	JSON(w, http.StatusOK, map[string]bool{"requested": true})
}

// ConfirmPairing tries a signed VCSEC session — succeeds only after the
// operator has tapped the NFC card on the centre console. The UI calls
// this in a polling loop after RequestPairing returns. Returns 4xx
// while the key is still pending approval; 200 once enrolled.
func (h *TeslaHandler) ConfirmPairing(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := teslaCtx(r, 45*time.Second)
	defer cancel()
	if err := h.tesla.ConfirmPairing(ctx); err != nil {
		JSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	user := GetUser(r)
	if user != nil {
		h.audit.Log("tesla.pair", user.Username+" confirmed pairing via VCSEC handshake")
	}
	JSON(w, http.StatusOK, map[string]bool{"paired": true})
}

// ── State reads ──────────────────────────────────────────────────

// State returns the cached snapshot. Cheap; safe to poll from the UI
// every few seconds. Add ?refresh=bcs|full to force a fresh BLE round-
// trip first — useful for the /garage pull-to-refresh affordance.
func (h *TeslaHandler) State(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("refresh") {
	case "bcs":
		ctx, cancel := teslaCtx(r, 30*time.Second)
		defer cancel()
		if err := h.tesla.PollBodyControllerState(ctx); err != nil {
			// Return the (possibly-stale) snapshot anyway — UI handles
			// "n seconds ago" rendering on its own.
			snap := h.tesla.Snapshot()
			JSON(w, http.StatusOK, map[string]any{
				"snapshot": serializeSnapshot(snap),
				"error":    err.Error(),
			})
			return
		}
	case "full":
		ctx, cancel := teslaCtx(r, 45*time.Second)
		defer cancel()
		// Best-effort: BCS first, then charge+climate. Don't fail the
		// whole thing if just one sub-fetch trips.
		_ = h.tesla.PollBodyControllerState(ctx)
		if err := h.tesla.PollChargeAndClimate(ctx, true); err != nil {
			snap := h.tesla.Snapshot()
			JSON(w, http.StatusOK, map[string]any{
				"snapshot": serializeSnapshot(snap),
				"error":    err.Error(),
			})
			return
		}
	}
	snap := h.tesla.Snapshot()
	JSON(w, http.StatusOK, map[string]any{
		"snapshot": serializeSnapshot(snap),
	})
}

// CommandLog returns the most recent N command entries for the
// /garage activity strip. Default 20, max 200.
func (h *TeslaHandler) CommandLog(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	type entry struct {
		At        string `json:"at"`
		Command   string `json:"command"`
		Succeeded bool   `json:"succeeded"`
		LatencyMs int64  `json:"latency_ms"`
		Error     string `json:"error,omitempty"`
	}
	rows, err := h.tesla.CommandLog(limit)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]entry, 0, len(rows))
	for _, r := range rows {
		out = append(out, entry{
			At: r.At, Command: r.Command, Succeeded: r.Succeeded,
			LatencyMs: r.LatencyMs, Error: r.Error,
		})
	}
	JSON(w, http.StatusOK, out)
}

// ── Commands ──────────────────────────────────────────────────────

// commandRouter dispatches to the right TeslaService method by URL
// param. Centralising it here means routes are uniform and the audit
// log lands consistently inside the service.
func (h *TeslaHandler) Command(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	user := GetUser(r)
	var userID int64
	if user != nil {
		userID = user.ID
	}

	ctx, cancel := teslaCtx(r, 45*time.Second)
	defer cancel()

	var err error
	switch name {
	case "lock":
		err = h.tesla.Lock(ctx, userID)
	case "unlock":
		err = h.tesla.Unlock(ctx, userID)
	case "wake":
		err = h.tesla.Wakeup(ctx, userID)
	case "honk":
		err = h.tesla.Honk(ctx, userID)
	case "flash-lights":
		err = h.tesla.FlashLights(ctx, userID)
	case "open-frunk":
		err = h.tesla.OpenFrunk(ctx, userID)
	case "open-trunk":
		err = h.tesla.OpenTrunk(ctx, userID)
	case "close-trunk":
		err = h.tesla.CloseTrunk(ctx, userID)
	case "open-charge-port":
		err = h.tesla.OpenChargePort(ctx, userID)
	case "close-charge-port":
		err = h.tesla.CloseChargePort(ctx, userID)
	case "climate-on":
		err = h.tesla.ClimateOn(ctx, userID)
	case "climate-off":
		err = h.tesla.ClimateOff(ctx, userID)
	case "set-climate-temp":
		// JSON body: {"celsius": 22.5}
		var body struct {
			Celsius float32 `json:"celsius"`
		}
		if derr := decodeJSON(r, &body); derr != nil {
			JSONError(w, http.StatusBadRequest, derr.Error())
			return
		}
		err = h.tesla.SetClimateTemp(ctx, userID, body.Celsius)
	case "set-charging-limit":
		var body struct {
			Percent int32 `json:"percent"`
		}
		if derr := decodeJSON(r, &body); derr != nil {
			JSONError(w, http.StatusBadRequest, derr.Error())
			return
		}
		err = h.tesla.SetChargingLimit(ctx, userID, body.Percent)
	case "start-charging":
		err = h.tesla.StartCharging(ctx, userID)
	case "stop-charging":
		err = h.tesla.StopCharging(ctx, userID)
	case "sentry-on":
		err = h.tesla.SetSentryMode(ctx, userID, true)
	case "sentry-off":
		err = h.tesla.SetSentryMode(ctx, userID, false)
	case "homelink":
		err = h.tesla.TriggerHomelink(ctx, userID)
	case "vent-windows":
		err = h.tesla.VentWindows(ctx, userID)
	case "close-windows":
		err = h.tesla.CloseWindows(ctx, userID)
	case "defrost-on":
		err = h.tesla.SetDefrost(ctx, userID, true)
	case "defrost-off":
		err = h.tesla.SetDefrost(ctx, userID, false)
	case "cabin-overheat-on":
		err = h.tesla.SetCabinOverheatProtection(ctx, userID, true)
	case "cabin-overheat-off":
		err = h.tesla.SetCabinOverheatProtection(ctx, userID, false)
	case "keep-accessory-power-on":
		err = h.tesla.SetKeepAccessoryPower(ctx, userID, true)
	case "keep-accessory-power-off":
		err = h.tesla.SetKeepAccessoryPower(ctx, userID, false)
	case "steering-wheel-heater-on":
		err = h.tesla.SetSteeringWheelHeater(ctx, userID, true)
	case "steering-wheel-heater-off":
		err = h.tesla.SetSteeringWheelHeater(ctx, userID, false)
	case "set-seat-heater":
		// JSON body: {"position": "front-left", "level": 2}
		var body struct {
			Position string `json:"position"`
			Level    int    `json:"level"`
		}
		if derr := decodeJSON(r, &body); derr != nil {
			JSONError(w, http.StatusBadRequest, derr.Error())
			return
		}
		err = h.tesla.SetSeatHeater(ctx, userID, body.Position, body.Level)
	default:
		JSONError(w, http.StatusNotFound, "unknown command")
		return
	}

	if err != nil {
		JSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── helpers ──────────────────────────────────────────────────────

// teslaCtx returns a request-scoped context with a hard timeout. We
// don't rely solely on the inbound r.Context() because reverse proxies
// can hold open requests indefinitely; commands need a bounded BLE
// budget regardless.
func teslaCtx(r *http.Request, max time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), max)
}

// serializeSnapshot flattens the VehicleSnapshot into the JSON the
// /garage UI expects. Freshness fields go out as integer milliseconds
// (or null when never polled) so the front-end can render
// "x seconds ago" / "fresh".
func serializeSnapshot(s services.VehicleSnapshot) map[string]any {
	freshness := func(d time.Duration) any {
		if d == 0 {
			return nil
		}
		return d.Milliseconds()
	}
	return map[string]any{
		"vin":    s.VIN,
		"paired": s.Paired,
		"vcsec": map[string]any{
			"lock_state":   s.LockState,
			"sleep_status": s.SleepStatus,
			"user_present": s.UserPresent,
			"closures": map[string]any{
				"front_driver_door":    s.Closures.FrontDriverDoor,
				"front_passenger_door": s.Closures.FrontPassengerDoor,
				"rear_driver_door":     s.Closures.RearDriverDoor,
				"rear_passenger_door":  s.Closures.RearPassengerDoor,
				"front_trunk":          s.Closures.FrontTrunk,
				"rear_trunk":           s.Closures.RearTrunk,
				"charge_port":          s.Closures.ChargePort,
				"tonneau":              s.Closures.Tonneau,
				// Windows + sentry come from the Infotainment ClosuresState;
				// surfaced here so the UI has one homogeneous "closures"
				// blob to read from.
				"window_driver_front":    s.Closures.WindowDriverFront,
				"window_passenger_front": s.Closures.WindowPassengerFront,
				"window_driver_rear":     s.Closures.WindowDriverRear,
				"window_passenger_rear":  s.Closures.WindowPassengerRear,
				"sentry_available":       s.Closures.SentryAvailable,
				"sentry_on":              s.Closures.SentryOn,
			},
			"freshness_ms": freshness(s.BCSFreshness),
		},
		"charge": map[string]any{
			"battery_pct":          s.BatteryPct,
			"usable_battery_pct":   s.UsableBatteryPct,
			"battery_range_km":     s.BatteryRangeKm,
			"est_battery_range_km": s.EstBatteryRangeKm,
			"charge_limit_soc":     s.ChargeLimitSOC,
			"charging_state":       s.ChargingState,
			"charger_power_kw":     s.ChargerPowerKW,
			"minutes_to_full":      s.MinutesToFull,
			"charge_port_open":     s.ChargePortOpen,
			"fast_charger_present": s.FastChargerPresent,
			"freshness_ms":         freshness(s.ChargeFreshness),
		},
		"climate": map[string]any{
			"inside_temp_c":            s.InsideTempC,
			"outside_temp_c":           s.OutsideTempC,
			"driver_temp_set_c":        s.DriverTempSetC,
			"is_climate_on":            s.IsClimateOn,
			"is_preconditioning":       s.IsPreconditioning,
			"fan_status":               s.FanStatus,
			"seat_heater_left":         s.SeatHeaterLeft,
			"seat_heater_right":        s.SeatHeaterRight,
			"seat_heater_rear_left":    s.SeatHeaterRearLeft,
			"seat_heater_rear_center":  s.SeatHeaterRearCenter,
			"seat_heater_rear_right":   s.SeatHeaterRearRight,
			"steering_wheel_heater":    s.SteeringWheelHeater,
			"front_defroster_on":       s.FrontDefrosterOn,
			"rear_defroster_on":        s.RearDefrosterOn,
			"cabin_overheat_protection": s.CabinOverheatProtection,
			"freshness_ms":             freshness(s.ClimateFreshness),
		},
		"tires": map[string]any{
			"front_left_bar":  s.TirePressure.FrontLeftBar,
			"front_right_bar": s.TirePressure.FrontRightBar,
			"rear_left_bar":   s.TirePressure.RearLeftBar,
			"rear_right_bar":  s.TirePressure.RearRightBar,
			"warn_front_left":  s.TirePressure.HardWarningFrontLeft,
			"warn_front_right": s.TirePressure.HardWarningFrontRight,
			"warn_rear_left":   s.TirePressure.HardWarningRearLeft,
			"warn_rear_right":  s.TirePressure.HardWarningRearRight,
			"freshness_ms":     freshness(s.TPFreshness),
		},
		"location": map[string]any{
			"latitude":     s.Location.Latitude,
			"longitude":    s.Location.Longitude,
			"freshness_ms": freshness(s.LocationFreshness),
		},
	}
}
