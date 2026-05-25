// Preview-only dev server for the AIRGAP admin UI.
//
//	go run ./cmd/preview
//	open http://localhost:8080
//
// Stubs every /api/* route with realistic mock data so the Alpine
// controllers in the templates can wire up without a real backend.
// State changes (status flips, toggle adds) persist in memory for the
// life of the process.
//
// Not built into the production binary. Delete this directory before
// shipping if you want.
package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	web "github.com/iulianfsdro/rpi-network-filter/web"
)

// ── Mock state ─────────────────────────────────────────────

type kv map[string]any
type mockState struct {
	mu        sync.Mutex
	devices   []kv
	filters   []kv
	domains   map[int64][]kv // filter id -> domains
	traffic   []kv
	muted     []kv
	firewall  []kv
	bandwidth []kv
	settings  kv
	nextID    int64
}

var state = newMockState()

func newMockState() *mockState {
	now := time.Now()
	t := func(off time.Duration) string { return now.Add(-off).UTC().Format("2006-01-02 15:04:05") }
	s := &mockState{
		nextID: 100,
		devices: []kv{
			{"id": 1, "mac_address": "F4:F5:D8:1A:22:C7", "alias": "Tesla M3 — Garage", "hostname": "TeslaModel3-DC22", "ip_address": "192.168.4.42", "status": "filtered", "online": true, "ignore_traffic_log": false},
			{"id": 2, "mac_address": "AC:DE:48:00:11:22", "alias": "iPhone (Pavel)", "hostname": "Pavel-iPhone", "ip_address": "192.168.4.31", "status": "open", "online": true, "ignore_traffic_log": false},
			{"id": 3, "mac_address": "98:01:A7:9B:0C:14", "alias": "MBP — work", "hostname": "pavel-mbp", "ip_address": "192.168.4.22", "status": "open", "online": true, "ignore_traffic_log": false},
			{"id": 4, "mac_address": "5C:CF:7F:8E:A4:11", "alias": "Sonos Beam", "hostname": "Sonos-BEAM", "ip_address": "192.168.4.51", "status": "blocked", "online": true, "ignore_traffic_log": true},
			{"id": 5, "mac_address": "B8:27:EB:33:9D:18", "alias": "", "hostname": "raspberrypi-cam", "ip_address": "192.168.4.61", "status": "blocked", "online": true, "ignore_traffic_log": false},
			{"id": 6, "mac_address": "DC:A6:32:71:5B:0E", "alias": "Roomba j7", "hostname": "iRobot-J7", "ip_address": "192.168.4.55", "status": "blocked", "online": false, "ignore_traffic_log": true},
			{"id": 7, "mac_address": "00:17:88:7E:12:6A", "alias": "Hue bridge", "hostname": "Philips-hue", "ip_address": "192.168.4.71", "status": "blocked", "online": true, "ignore_traffic_log": true},
		},
		filters: []kv{
			{"id": 1, "name": "Tesla AP/Nav", "description": "Autopilot map tiles + nav backend. Excludes auth, OTA, telemetry.", "is_system": true, "enabled": true},
			{"id": 2, "name": "YouTube", "description": "Theater mode playback. Audio + video CDN + thumbnails.", "is_system": true, "enabled": false},
			{"id": 3, "name": "Netflix", "description": "Streaming playback + UI.", "is_system": true, "enabled": false},
			{"id": 4, "name": "Disney+", "description": "Streaming playback + UI.", "is_system": true, "enabled": false},
			{"id": 5, "name": "Spotify", "description": "Music playback.", "is_system": false, "enabled": false},
		},
		domains: map[int64][]kv{
			1: {
				{"id": 11, "domain": "daws.tesla.services", "description": "Map tile authoritative DNS for AP nav stack.", "enabled": true},
				{"id": 12, "domain": "apmv3.go.tesla.services", "description": "Autopilot maps v3 tile fetch.", "enabled": true},
				{"id": 13, "domain": "maps-eu-prd.go.tesla.services", "description": "EU production map tile CDN.", "enabled": true},
				{"id": 14, "domain": "maps.googleapis.com", "description": "Geocoding + place search used by nav.", "enabled": true},
			},
			2: {
				{"id": 21, "domain": "youtube.com", "description": "Page shell + login state.", "enabled": true},
				{"id": 22, "domain": "googlevideo.com", "description": "Video segment CDN (DASH).", "enabled": true},
				{"id": 23, "domain": "ytimg.com", "description": "Thumbnail CDN.", "enabled": true},
				{"id": 24, "domain": "ggpht.com", "description": "Avatar / profile image CDN.", "enabled": false},
				{"id": 25, "domain": "youtu.be", "description": "Short-link redirector.", "enabled": true},
			},
			3: {
				{"id": 31, "domain": "netflix.com", "description": "App shell + auth.", "enabled": true},
				{"id": 32, "domain": "nflxvideo.net", "description": "Video segment CDN.", "enabled": true},
				{"id": 33, "domain": "nflximg.com", "description": "Cover art CDN.", "enabled": true},
				{"id": 34, "domain": "nflxext.com", "description": "Static assets.", "enabled": false},
				{"id": 35, "domain": "nflxso.net", "description": "Suspect: pulls extra telemetry. Review.", "enabled": false},
			},
			4: {
				{"id": 41, "domain": "disneyplus.com", "description": "App shell.", "enabled": true},
				{"id": 42, "domain": "disney-plus.net", "description": "Edge endpoints.", "enabled": true},
				{"id": 43, "domain": "dssott.com", "description": "Video CDN.", "enabled": true},
				{"id": 44, "domain": "bamgrid.com", "description": "Account / entitlements.", "enabled": true},
			},
			5: {
				{"id": 51, "domain": "spotify.com", "description": "App shell + auth.", "enabled": true},
				{"id": 52, "domain": "scdn.co", "description": "Album art + audio segment CDN.", "enabled": true},
			},
		},
		traffic: []kv{
			{"id": 1, "timestamp": t(2 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "23.45.221.18", "dst_port": "443", "protocol": "TLS", "action": "allowed", "domain": "apmv3.go.tesla.services", "source": "forward"},
			{"id": 2, "timestamp": t(3 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "", "dst_port": "53", "protocol": "DNS", "action": "query", "domain": "maps-eu-prd.go.tesla.services", "source": "dns"},
			{"id": 3, "timestamp": t(6 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "199.66.11.9", "dst_port": "443", "protocol": "TLS", "action": "blocked", "domain": "hermes-prd.ap.tesla.services", "source": "forward"},
			{"id": 4, "timestamp": t(9 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "52.84.221.2", "dst_port": "443", "protocol": "TLS", "action": "blocked", "domain": "ota.vn.tesla.services", "source": "forward"},
			{"id": 5, "timestamp": t(12 * time.Second), "src_ip": "192.168.4.31", "src_mac": "AC:DE:48:00:11:22", "dst_ip": "17.253.144.10", "dst_port": "443", "protocol": "TLS", "action": "allowed", "domain": "icloud.com", "source": "forward"},
			{"id": 6, "timestamp": t(14 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "13.225.18.5", "dst_port": "443", "protocol": "TLS", "action": "blocked", "domain": "telemetry-prd.ap.tesla.services", "source": "forward"},
			{"id": 7, "timestamp": t(17 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "104.18.32.97", "dst_port": "443", "protocol": "TLS", "action": "allowed", "domain": "maps.googleapis.com", "source": "forward"},
			{"id": 8, "timestamp": t(20 * time.Second), "src_ip": "192.168.4.22", "src_mac": "98:01:A7:9B:0C:14", "dst_ip": "142.250.180.46", "dst_port": "443", "protocol": "TLS", "action": "allowed", "domain": "google.com", "source": "forward"},
			{"id": 9, "timestamp": t(23 * time.Second), "src_ip": "192.168.4.51", "src_mac": "5C:CF:7F:8E:A4:11", "dst_ip": "184.169.218.45", "dst_port": "443", "protocol": "TLS", "action": "blocked", "domain": "sonos.com", "source": "forward"},
		},
		muted: []kv{
			{"id": 901, "pattern": "captive.apple.com", "match_type": "suffix"},
			{"id": 902, "pattern": "msftconnecttest.com", "match_type": "suffix"},
		},
		firewall: []kv{
			{"id": 1, "description": "Forward chain default-drop floor", "direction": "forward", "protocol": "all", "dest_ip": "", "dest_port": "", "action": "drop", "device_mac": "", "enabled": true, "priority": 1000},
			{"id": 2, "description": "Allow established + related", "direction": "forward", "protocol": "all", "dest_ip": "", "dest_port": "", "action": "accept", "device_mac": "", "enabled": true, "priority": 10},
			{"id": 3, "description": "Block all UDP/443 (QUIC) from Tesla", "direction": "forward", "protocol": "udp", "dest_ip": "", "dest_port": "443", "action": "drop", "device_mac": "F4:F5:D8:1A:22:C7", "enabled": true, "priority": 100},
		},
		bandwidth: []kv{
			{"id": 1, "device_mac": "F4:F5:D8:1A:22:C7", "download_kbps": 8000, "upload_kbps": 2000, "enabled": true},
			{"id": 2, "device_mac": "5C:CF:7F:8E:A4:11", "download_kbps": 2000, "upload_kbps": 512, "enabled": false},
		},
		settings: kv{
			"ap_ssid":      "ivanchokara",
			"ap_password":  "•••••••••••",
			"ap_channel":   "6",
			"dns_upstream": "1.1.1.1,8.8.8.8",
		},
	}
	return s
}

// ── HTTP helpers ──────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func okJSON(w http.ResponseWriter) { writeJSON(w, kv{"status": "ok"}) }

func extractIDFromTail(path string) int64 {
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	n, _ := strconv.ParseInt(last, 10, 64)
	return n
}

// ── Template renderer ─────────────────────────────────────

type renderer struct{ tmplFS fs.FS }

func (r *renderer) renderPage(w http.ResponseWriter, page string, data map[string]string) {
	tmpl, err := template.ParseFS(r.tmplFS, "layout.html", page)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

func (r *renderer) renderLogin(w http.ResponseWriter) {
	tmpl, err := template.ParseFS(r.tmplFS, "login.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := tmpl.ExecuteTemplate(w, filepath.Base("login.html"), nil); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

// ── Main ──────────────────────────────────────────────────

func main() {
	rand.Seed(time.Now().UnixNano())
	tmplFS, _ := fs.Sub(web.Content, "templates")
	staticFS, _ := fs.Sub(web.Content, "static")
	r := &renderer{tmplFS: tmplFS}

	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("/netfilter-ca.crt", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write([]byte("-----BEGIN CERTIFICATE-----\nMOCK PREVIEW CERT — not a real CA\n-----END CERTIFICATE-----\n"))
	})

	// ── Pages ─────────────────────────────────────────
	mux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) { r.renderLogin(w) })
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		r.renderPage(w, "dashboard.html", map[string]string{"page": "dashboard"})
	})
	for _, page := range []string{"devices", "traffic", "stats", "filters", "firewall", "bandwidth", "settings"} {
		p := page
		mux.HandleFunc("/"+p, func(w http.ResponseWriter, req *http.Request) {
			r.renderPage(w, p+".html", map[string]string{"page": p})
		})
	}

	// ── API stubs ─────────────────────────────────────
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Set-Cookie", "netfilter_session=preview; Path=/; SameSite=Lax")
		okJSON(w)
	})
	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Set-Cookie", "netfilter_session=; Path=/; Max-Age=0")
		okJSON(w)
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, kv{"username": "admin"})
	})

	mux.HandleFunc("/api/dashboard", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		online := 0
		for _, d := range state.devices {
			if d["online"].(bool) {
				online++
			}
		}
		fEn := 0
		for _, f := range state.filters {
			if f["enabled"].(bool) {
				fEn++
			}
		}
		writeJSON(w, kv{
			"devices_online":  online,
			"devices_total":   len(state.devices),
			"firewall_rules":  countEnabled(state.firewall),
			"filters_total":   len(state.filters),
			"filters_enabled": fEn,
			"protected_deny":  15,
			"blocked_24h":     1422,
			"allowed_24h":     24108,
			"wan_reachable":   true,
			"system": kv{
				"uptime":         float64(14*86400 + 6*3600 + 42*60 + 18),
				"load_avg":       "0.18 0.22 0.20",
				"wan_interface":  "usb0",
				"wan_ip":         "100.64.18.42",
				"wan_rx_bytes":   uint64(8_420_000_000),
				"wan_tx_bytes":   uint64(930_000_000),
				"lan_interface":  "wlan0",
				"lan_ip":         "192.168.4.1",
				"mem_total":      "1.9 GB",
				"mem_free":       "1.2 GB",
			},
		})
	})

	mux.HandleFunc("/api/devices", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		writeJSON(w, state.devices)
	})
	mux.HandleFunc("/api/devices/", func(w http.ResponseWriter, req *http.Request) {
		// /api/devices/{mac}, /api/devices/{mac}/status
		path := strings.TrimPrefix(req.URL.Path, "/api/devices/")
		segs := strings.Split(path, "/")
		state.mu.Lock()
		defer state.mu.Unlock()
		mac := strings.ToUpper(segs[0])
		switch req.Method {
		case http.MethodDelete:
			state.devices = filterOut(state.devices, "mac_address", mac)
			okJSON(w)
		case http.MethodPut:
			if len(segs) >= 2 && segs[1] == "status" {
				var body struct{ Status string }
				_ = json.NewDecoder(req.Body).Decode(&body)
				for _, d := range state.devices {
					if strings.EqualFold(d["mac_address"].(string), mac) {
						d["status"] = body.Status
					}
				}
				okJSON(w)
				return
			}
			var body struct {
				Alias            string `json:"alias"`
				IgnoreTrafficLog bool   `json:"ignore_traffic_log"`
			}
			_ = json.NewDecoder(req.Body).Decode(&body)
			for _, d := range state.devices {
				if strings.EqualFold(d["mac_address"].(string), mac) {
					d["alias"] = body.Alias
					d["ignore_traffic_log"] = body.IgnoreTrafficLog
				}
			}
			okJSON(w)
		default:
			http.NotFound(w, req)
		}
	})

	mux.HandleFunc("/api/filters", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.Method == http.MethodPost {
			var body struct{ Name, Description string }
			_ = json.NewDecoder(req.Body).Decode(&body)
			id := state.nextID
			state.nextID++
			f := kv{"id": id, "name": body.Name, "description": body.Description, "is_system": false, "enabled": false}
			state.filters = append(state.filters, f)
			state.domains[id] = []kv{}
			writeJSON(w, kv{"id": id})
			return
		}
		writeJSON(w, state.filters)
	})
	mux.HandleFunc("/api/filters/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/api/filters/")
		segs := strings.Split(path, "/")
		state.mu.Lock()
		defer state.mu.Unlock()

		// /api/filters/domains/{id} -- update domain enabled/desc / delete domain
		if segs[0] == "domains" && len(segs) == 2 {
			id, _ := strconv.ParseInt(segs[1], 10, 64)
			switch req.Method {
			case http.MethodPut:
				var body struct {
					Description string `json:"description"`
					Enabled     bool   `json:"enabled"`
				}
				_ = json.NewDecoder(req.Body).Decode(&body)
				for fid := range state.domains {
					for _, d := range state.domains[fid] {
						if int64(toInt(d["id"])) == id {
							d["description"] = body.Description
							d["enabled"] = body.Enabled
						}
					}
				}
				okJSON(w)
			case http.MethodDelete:
				for fid := range state.domains {
					state.domains[fid] = filterOutInt(state.domains[fid], "id", id)
				}
				okJSON(w)
			}
			return
		}

		fid, _ := strconv.ParseInt(segs[0], 10, 64)
		// /api/filters/{id} -- get/update/delete
		if len(segs) == 1 {
			switch req.Method {
			case http.MethodDelete:
				state.filters = filterOutInt(state.filters, "id", fid)
				delete(state.domains, fid)
				okJSON(w)
			case http.MethodPut:
				var body kv
				_ = json.NewDecoder(req.Body).Decode(&body)
				for _, f := range state.filters {
					if int64(toInt(f["id"])) == fid {
						if v, ok := body["name"]; ok {
							f["name"] = v
						}
						if v, ok := body["description"]; ok {
							f["description"] = v
						}
					}
				}
				okJSON(w)
			}
			return
		}

		// /api/filters/{id}/enabled
		if len(segs) == 2 && segs[1] == "enabled" {
			var body struct{ Enabled bool }
			_ = json.NewDecoder(req.Body).Decode(&body)
			for _, f := range state.filters {
				if int64(toInt(f["id"])) == fid {
					f["enabled"] = body.Enabled
				}
			}
			okJSON(w)
			return
		}

		// /api/filters/{id}/domains
		if len(segs) == 2 && segs[1] == "domains" {
			if req.Method == http.MethodPost {
				var body struct{ Domain, Description string }
				_ = json.NewDecoder(req.Body).Decode(&body)
				if strings.HasSuffix(body.Domain, "tesla.services") && strings.Contains(body.Domain, "hermes") {
					http.Error(w, `"`+body.Domain+`" is a protected Tesla endpoint and cannot be allow-listed`, http.StatusBadRequest)
					return
				}
				id := state.nextID
				state.nextID++
				d := kv{"id": id, "filter_id": fid, "domain": strings.ToLower(strings.TrimSpace(body.Domain)), "description": body.Description, "enabled": false}
				state.domains[fid] = append(state.domains[fid], d)
				writeJSON(w, kv{"id": id})
				return
			}
			writeJSON(w, state.domains[fid])
			return
		}
		http.NotFound(w, req)
	})

	mux.HandleFunc("/api/system/traffic", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.URL.Path == "/api/system/traffic/clear" || strings.HasSuffix(req.URL.Path, "/clear") {
			state.traffic = []kv{}
			okJSON(w)
			return
		}
		page, _ := strconv.Atoi(req.URL.Query().Get("page"))
		if page <= 0 {
			page = 1
		}
		writeJSON(w, kv{
			"entries": state.traffic,
			"total":   len(state.traffic),
			"page":    page,
			"pages":   1,
		})
	})
	mux.HandleFunc("/api/system/traffic/clear", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.traffic = []kv{}
		okJSON(w)
	})
	mux.HandleFunc("/api/system/traffic/muted", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.Method == http.MethodPost {
			var body struct{ Domain string }
			_ = json.NewDecoder(req.Body).Decode(&body)
			id := state.nextID
			state.nextID++
			state.muted = append(state.muted, kv{"id": id, "pattern": strings.ToLower(strings.TrimSpace(body.Domain)), "match_type": "suffix"})
			writeJSON(w, kv{"id": id})
			return
		}
		writeJSON(w, state.muted)
	})
	mux.HandleFunc("/api/system/traffic/muted/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodDelete {
			http.NotFound(w, req)
			return
		}
		id := extractIDFromTail(req.URL.Path)
		state.mu.Lock()
		defer state.mu.Unlock()
		state.muted = filterOutInt(state.muted, "id", id)
		okJSON(w)
	})

	mux.HandleFunc("/api/firewall/rules", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.Method == http.MethodPost {
			var body kv
			_ = json.NewDecoder(req.Body).Decode(&body)
			body["id"] = state.nextID
			state.nextID++
			state.firewall = append(state.firewall, body)
			okJSON(w)
			return
		}
		writeJSON(w, state.firewall)
	})
	mux.HandleFunc("/api/firewall/rules/", func(w http.ResponseWriter, req *http.Request) {
		id := extractIDFromTail(req.URL.Path)
		state.mu.Lock()
		defer state.mu.Unlock()
		switch req.Method {
		case http.MethodDelete:
			state.firewall = filterOutInt(state.firewall, "id", id)
		case http.MethodPut:
			var body kv
			_ = json.NewDecoder(req.Body).Decode(&body)
			for _, r := range state.firewall {
				if int64(toInt(r["id"])) == id {
					for k, v := range body {
						r[k] = v
					}
				}
			}
		}
		okJSON(w)
	})

	mux.HandleFunc("/api/bandwidth/limits", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.Method == http.MethodPost {
			var body kv
			_ = json.NewDecoder(req.Body).Decode(&body)
			body["id"] = state.nextID
			state.nextID++
			state.bandwidth = append(state.bandwidth, body)
			okJSON(w)
			return
		}
		writeJSON(w, state.bandwidth)
	})
	mux.HandleFunc("/api/bandwidth/limits/", func(w http.ResponseWriter, req *http.Request) {
		id := extractIDFromTail(req.URL.Path)
		state.mu.Lock()
		defer state.mu.Unlock()
		switch req.Method {
		case http.MethodDelete:
			state.bandwidth = filterOutInt(state.bandwidth, "id", id)
		case http.MethodPut:
			var body kv
			_ = json.NewDecoder(req.Body).Decode(&body)
			for _, r := range state.bandwidth {
				if int64(toInt(r["id"])) == id {
					for k, v := range body {
						r[k] = v
					}
				}
			}
		}
		okJSON(w)
	})

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.Method == http.MethodPut {
			var body kv
			_ = json.NewDecoder(req.Body).Decode(&body)
			for k, v := range body {
				state.settings[k] = v
			}
			okJSON(w)
			return
		}
		writeJSON(w, state.settings)
	})
	mux.HandleFunc("/api/settings/password", func(w http.ResponseWriter, req *http.Request) { okJSON(w) })

	mux.HandleFunc("/api/system/audit", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, []kv{
			{"id": 1, "timestamp": time.Now().Add(-2 * time.Minute).Format(time.RFC3339), "action": "device.status", "details": "MAC=F4:F5:D8:1A:22:C7 status=filtered"},
			{"id": 2, "timestamp": time.Now().Add(-7 * time.Minute).Format(time.RFC3339), "action": "filter.enabled", "details": "Tesla AP/Nav · ON"},
			{"id": 3, "timestamp": time.Now().Add(-15 * time.Minute).Format(time.RFC3339), "action": "session.login", "details": "user=admin ip=192.168.4.22"},
		})
	})
	mux.HandleFunc("/api/system/connectivity", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, []kv{
			{"host": "1.1.1.1:53",  "success": true,  "latency": "38 ms"},
			{"host": "8.8.8.8:53",  "success": true,  "latency": "42 ms"},
			{"host": "google.com:443", "success": true, "latency": "62 ms"},
		})
	})
	mux.HandleFunc("/api/system/stats/summary", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, kv{"total": 28530, "queries": 12044, "allowed": 16486, "blocked": 1422, "unique_domains": 412, "unique_clients": 7})
	})
	mux.HandleFunc("/api/system/stats/timeseries", func(w http.ResponseWriter, req *http.Request) {
		out := make([]kv, 60)
		for i := 0; i < 60; i++ {
			out[i] = kv{
				"time":    time.Now().Add(time.Duration(-60+i) * time.Minute).Format("15:04"),
				"queries": 80 + rand.Intn(40),
				"allowed": 120 + rand.Intn(50),
				"blocked": rand.Intn(8),
			}
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/system/stats/top-domains", func(w http.ResponseWriter, req *http.Request) {
		action := req.URL.Query().Get("action")
		var src []kv
		switch action {
		case "blocked":
			src = []kv{
				{"domain": "hermes-prd.ap.tesla.services", "count": 412},
				{"domain": "ota.vn.tesla.services", "count": 386},
				{"domain": "telemetry-prd.ap.tesla.services", "count": 284},
				{"domain": "logupload-prod.vn.tesla.services", "count": 116},
				{"domain": "fake.hypnos.vn.tesla.services", "count": 88},
			}
		case "allowed":
			src = []kv{
				{"domain": "apmv3.go.tesla.services", "count": 4_212},
				{"domain": "daws.tesla.services", "count": 3_087},
				{"domain": "maps-eu-prd.go.tesla.services", "count": 2_488},
				{"domain": "maps.googleapis.com", "count": 1_966},
				{"domain": "connman.vn.tesla.services", "count": 412},
			}
		case "query":
			src = []kv{
				{"domain": "apmv3.go.tesla.services", "count": 5_122},
				{"domain": "daws.tesla.services", "count": 4_088},
				{"domain": "google.com", "count": 2_312},
				{"domain": "icloud.com", "count": 1_544},
				{"domain": "captive.apple.com", "count": 1_018},
			}
		}
		writeJSON(w, src)
	})
	mux.HandleFunc("/api/system/stats/top-clients", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, []kv{
			{"client": "192.168.4.42", "count": 12_402},
			{"client": "192.168.4.31", "count": 5_812},
			{"client": "192.168.4.22", "count": 4_088},
			{"client": "192.168.4.71", "count": 612},
		})
	})

	addr := ":8080"
	fmt.Printf("AIRGAP preview · open http://localhost%s\n", addr)
	fmt.Println("Stub data resets on every restart. State changes are in-memory only.")
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ── helpers ───────────────────────────────────────────────

func filterOut(in []kv, key string, val string) []kv {
	out := in[:0]
	for _, m := range in {
		if !strings.EqualFold(fmt.Sprint(m[key]), val) {
			out = append(out, m)
		}
	}
	return out
}
func filterOutInt(in []kv, key string, val int64) []kv {
	out := []kv{}
	for _, m := range in {
		if int64(toInt(m[key])) != val {
			out = append(out, m)
		}
	}
	return out
}
func toInt(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}
func countEnabled(rs []kv) int {
	n := 0
	for _, r := range rs {
		if r["enabled"] == true {
			n++
		}
	}
	return n
}
