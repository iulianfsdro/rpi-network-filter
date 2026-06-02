// services/remote.go — Tailscale wrapper.
//
// V4 Tier D's remote-access story is "let Tailscale do the hard work."
// The Pi is behind CGNAT (carrier-grade NAT on the LTE modem), so we
// need a third party to broker NAT traversal — that's Tailscale's
// DERP relays. Tailscale also handles WireGuard key exchange and gives
// the Pi a stable .ts.net hostname the user can reach from anywhere.
//
// This file doesn't reimplement any of that. It shells out to the
// `tailscale` CLI, parses `tailscale status --json`, and persists the
// auth key the user pastes in. Lifecycle of the tailscaled daemon
// itself stays under systemctl — we never touch the unit file beyond
// `systemctl is-active`.
//
// Three opinions baked in:
//
//   1. We don't store the auth key. `tailscale up --authkey=...` hands
//      it to tailscaled which keeps its own state in /var/lib/tailscale;
//      we never need to remember it. The /remote-access page is the
//      one-shot input, then forget.
//
//   2. We auto-install on first use. apt-get install tailscale (with
//      the apt source from packagecloud) is one HTTP fetch + one apt
//      install. Doing this from the UI on click instead of forcing the
//      operator into ssh is the whole point of being non-tech friendly.
//
//   3. Hostname is the Pi's hostname (rasperrypi by default → user
//      can change in /etc/hostname). Tailscale takes it as-is. Good
//      enough — the user gets pi.<tailnet>.ts.net.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// RemoteStatus is what /api/remote/status returns to the UI. Flat,
// minimal — the UI only needs to render five states (not installed /
// installing / not authenticated / connecting / connected).
type RemoteStatus struct {
	// Installed is true if the `tailscale` CLI is present in $PATH.
	// We don't rely on tailscaled's process state for this because the
	// daemon may be stopped intentionally.
	Installed bool `json:"installed"`

	// DaemonActive is true if `systemctl is-active tailscaled` returns
	// "active". Distinct from Installed — the package can be present
	// while the unit is masked or stopped.
	DaemonActive bool `json:"daemon_active"`

	// Authenticated is true when `tailscale status --json`'s BackendState
	// is "Running". Other states ("NeedsLogin", "Starting", "Stopped")
	// surface to the UI verbatim.
	Authenticated bool   `json:"authenticated"`
	BackendState  string `json:"backend_state"`

	// Hostname is the Pi's tailnet hostname (e.g. `pi.tail1234.ts.net`).
	// Empty until tailscaled has logged in. This is the value the user
	// types on their phone.
	TailnetHostname string `json:"tailnet_hostname"`

	// TailnetIPv4 is the 100.64.0.0/10 address the Pi reaches the rest
	// of the tailnet on. UI shows it as a fallback in case MagicDNS
	// isn't configured (rare).
	TailnetIPv4 string `json:"tailnet_ipv4"`

	// BLEFunnel is true if Tailscale Funnel currently exposes
	// /api/ble on the public internet. Funnel terminates TLS at
	// Tailscale's globally-distributed edge with a Let's Encrypt
	// cert, and tunnels the request back to this Pi over WireGuard
	// before re-issuing it against localhost:8443 (self-signed,
	// accepted via the `https+insecure://` upstream form).
	//
	// Only /api/ble/* is exposed via Funnel — the admin web UI
	// (/login, /traffic, /settings, etc.) stays Tailscale-only. The
	// path-based split is the load-bearing safety property.
	BLEFunnel bool `json:"ble_funnel"`

	// BLEFunnelURL is the public URL clients hit when BLEFunnel is on,
	// e.g. https://pi.tailXXXX.ts.net/api/ble. Empty when off.
	BLEFunnelURL string `json:"ble_funnel_url"`
}

// bleFunnelPath is the URL prefix exposed via Funnel. The Pi's chi
// router mounts the bearer-authed sub-router under /api/ble, so this
// is what gets selectively published. Centralised here so the enable /
// disable / detect paths stay in sync.
const bleFunnelPath = "/api/ble"

// RemoteService manages the tailscaled lifecycle.
//
// We shell out to the tailscale CLI directly rather than going through
// the central executor.Executor — those calls don't benefit from
// dry-run mode (they're already idempotent) and they need raw stdout
// for JSON parsing.
type RemoteService struct {
	mu sync.Mutex // serialise install / up / logout operations
}

func NewRemoteService() *RemoteService {
	return &RemoteService{}
}

// Status returns the current state. Safe to call frequently from the
// /remote-access UI — the underlying tailscale calls are sub-100ms.
func (s *RemoteService) Status(ctx context.Context) (RemoteStatus, error) {
	out := RemoteStatus{}

	if _, err := exec.LookPath("tailscale"); err == nil {
		out.Installed = true
	}
	if !out.Installed {
		return out, nil
	}

	// Daemon liveness — keep this separate from `tailscale status`
	// because that command will block forever waiting for the daemon
	// if the unit isn't running.
	if err := exec.CommandContext(ctx, "systemctl", "is-active", "tailscaled").Run(); err == nil {
		out.DaemonActive = true
	}
	if !out.DaemonActive {
		return out, nil
	}

	// Pull the rich JSON status. We only need a subset of its fields.
	cmd := exec.CommandContext(ctx, "tailscale", "status", "--json")
	stdout, err := cmd.Output()
	if err != nil {
		// Daemon up but `tailscale status` failed — most often "not
		// logged in". Return the partial state we already have so the
		// UI shows "needs auth" instead of "broken".
		return out, nil
	}

	var raw struct {
		BackendState string `json:"BackendState"`
		Self         struct {
			DNSName string   `json:"DNSName"`
			TailscaleIPs []string `json:"TailscaleIPs"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(stdout, &raw); err != nil {
		return out, fmt.Errorf("parse tailscale status: %w", err)
	}
	out.BackendState = raw.BackendState
	out.Authenticated = raw.BackendState == "Running"
	out.TailnetHostname = strings.TrimSuffix(raw.Self.DNSName, ".")
	if len(raw.Self.TailscaleIPs) > 0 {
		out.TailnetIPv4 = raw.Self.TailscaleIPs[0]
	}

	// Funnel detection. `tailscale serve status --json` returns the
	// current serve+funnel config; we look for a Web[<host>:443] entry
	// that handles /api/ble AND has AllowFunnel == true. A serve entry
	// without funnel (i.e. tailnet-only) doesn't count — the whole
	// point of the toggle is making /api/ble public.
	//
	// If `serve status` errors (older tailscale, daemon issue, no
	// serve config yet), we report BLEFunnel: false silently — the UI
	// will offer the operator to enable it.
	if out.Authenticated {
		serveCmd := exec.CommandContext(ctx, "tailscale", "serve", "status", "--json")
		if serveOut, err := serveCmd.Output(); err == nil {
			out.BLEFunnel, out.BLEFunnelURL = parseServeStatus(serveOut, out.TailnetHostname)
		}
	}
	return out, nil
}

// parseServeStatus inspects the tailscale serve JSON for an active
// Funnel handler on the BLE path. Returned URL is empty when not on.
//
// Extracted as a free function so unit tests can drive it without
// shelling out.
func parseServeStatus(jsonBytes []byte, hostname string) (bool, string) {
	var st struct {
		Web         map[string]struct {
			Handlers map[string]any `json:"Handlers"`
		} `json:"Web"`
		AllowFunnel map[string]bool `json:"AllowFunnel"`
	}
	if err := json.Unmarshal(jsonBytes, &st); err != nil {
		return false, ""
	}
	for hostPort, web := range st.Web {
		if _, ok := web.Handlers[bleFunnelPath]; !ok {
			continue
		}
		if !st.AllowFunnel[hostPort] {
			continue
		}
		// hostPort is e.g. "pi.tail1234.ts.net:443" — strip the port
		// for the URL we surface to the operator.
		host := hostPort
		if i := strings.LastIndex(hostPort, ":"); i > 0 {
			host = hostPort[:i]
		}
		return true, "https://" + host + bleFunnelPath
	}
	_ = hostname // accepted for callers that may want it later
	return false, ""
}

// EnableBLEFunnel exposes /api/ble publicly via Tailscale Funnel. The
// Pi's local listener stays self-signed on :8443; Tailscale's edge
// terminates the public Let's Encrypt TLS and proxies inwards over the
// existing WireGuard tunnel. We use `https+insecure://localhost:8443`
// as the upstream so Funnel accepts the Pi's self-signed cert.
//
// Path scope: --set-path=/api/ble — only this prefix is published.
// Everything else on :8443 (admin UI, /garage, …) stays Tailscale-only.
//
// Prerequisites the operator must have satisfied OUTSIDE this code:
//   - tailscaled installed + authenticated to a tailnet (covered by
//     the existing Install/Up flow).
//   - Funnel enabled for the tailnet at
//     https://login.tailscale.com/admin/dns/feature-flags. If not,
//     the CLI returns an explicit "funnel is not enabled" error which
//     we surface verbatim.
func (s *RemoteService) EnableBLEFunnel(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd := exec.CommandContext(ctx,
		"tailscale", "funnel",
		"--bg",
		"--set-path="+bleFunnelPath,
		"https+insecure://localhost:8443",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("enable BLE funnel: %w\n%s", err, string(out))
	}
	return nil
}

// DisableBLEFunnel removes the /api/ble Funnel handler. The Pi's
// local :8443 listener is untouched; only the public-edge exposure
// goes away. Other serve handlers (if the operator has set any) are
// preserved — we target only our path.
func (s *RemoteService) DisableBLEFunnel(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd := exec.CommandContext(ctx,
		"tailscale", "funnel",
		"--set-path="+bleFunnelPath,
		"off",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("disable BLE funnel: %w\n%s", err, string(out))
	}
	return nil
}

// Install runs Tailscale's official install script. ~30s, idempotent
// — re-running is a no-op if the apt source + package are already in
// place. Caller is expected to enforce auth before letting any operator
// trigger this.
//
// We pipe their official `curl -fsSL https://tailscale.com/install.sh
// | sh` rather than rolling our own apt-source/install because their
// installer maintains the version pinning and arch detection for us.
// The script logs to stderr; we surface failures via error return.
func (s *RemoteService) Install(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// install.sh exits non-zero on any failure step; we let the
	// installer's own stderr propagate via combined output for the
	// API caller to surface.
	cmd := exec.CommandContext(ctx, "bash", "-c",
		"curl -fsSL https://tailscale.com/install.sh | sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install failed: %w\n%s", err, string(out))
	}
	// The installer enables + starts tailscaled by default, but it
	// doesn't hurt to be defensive.
	_ = exec.CommandContext(ctx, "systemctl", "enable", "--now", "tailscaled").Run()
	return nil
}

// Up logs the daemon into the tailnet using the provided auth key.
// Pre-auth keys are issued from https://login.tailscale.com/admin/settings/keys
// — they're scoped, expiring tokens that look like `tskey-auth-...`.
//
// We set --hostname to the Pi's /etc/hostname so the user lands at a
// predictable name in their tailnet. Auth keys are NOT stored locally;
// tailscaled persists its own state under /var/lib/tailscale.
func (s *RemoteService) Up(ctx context.Context, authKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	authKey = strings.TrimSpace(authKey)
	if authKey == "" {
		return fmt.Errorf("auth key required (paste from https://login.tailscale.com/admin/settings/keys)")
	}
	if !strings.HasPrefix(authKey, "tskey-") {
		return fmt.Errorf("auth key must start with `tskey-` (got %q)", redactKey(authKey))
	}

	// `--reset` clears any previous up-flags so re-running with a fresh
	// key doesn't inherit yesterday's settings. `--accept-routes=false`
	// keeps the Pi from learning routes from the rest of the tailnet
	// (we want to be reachable, not act as a gateway).
	args := []string{
		"up",
		"--authkey", authKey,
		"--reset",
		"--accept-routes=false",
		"--accept-dns=false",
	}
	cmd := exec.CommandContext(ctx, "tailscale", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tailscale up: %w\n%s", err, redactOutput(string(out)))
	}
	return nil
}

// Logout disconnects from the tailnet. The next caller will need a
// fresh auth key. Doesn't uninstall tailscale itself — just the auth.
func (s *RemoteService) Logout(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd := exec.CommandContext(ctx, "tailscale", "logout")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tailscale logout: %w\n%s", err, string(out))
	}
	return nil
}

// redactKey returns the first six and last four chars with a middle
// asterisked, so error messages can reference "the key the user typed"
// without leaking it into logs / audit rows.
func redactKey(k string) string {
	if len(k) <= 10 {
		return "***"
	}
	return k[:6] + "***" + k[len(k)-4:]
}

// redactOutput scrubs auth-key-shaped substrings from CLI output before
// returning them to the API caller. `tailscale up` doesn't usually echo
// the key but defensive scrubbing keeps any future regression from
// leaking it through netfilterd's JSON error path.
func redactOutput(s string) string {
	const prefix = "tskey-"
	var b strings.Builder
	for {
		i := strings.Index(s, prefix)
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		b.WriteString("tskey-***")
		// Skip past the matched key (whitespace-terminated).
		end := i + len(prefix)
		for end < len(s) && !isSpace(s[end]) {
			end++
		}
		s = s[end:]
	}
	return b.String()
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\n' || b == '\r' || b == '\t'
}

