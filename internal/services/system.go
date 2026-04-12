package services

import (
	"fmt"
	"os"
	"strings"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

type SystemService struct {
	exec *executor.Executor
	cfg  config.Config
}

type SystemInfo struct {
	Uptime      string `json:"uptime"`
	LoadAvg     string `json:"load_avg"`
	MemTotal    string `json:"mem_total"`
	MemFree     string `json:"mem_free"`
	MemUsed     string `json:"mem_used"`
	WANInterface string `json:"wan_interface"`
	LANInterface string `json:"lan_interface"`
	WANIP       string `json:"wan_ip"`
	LANIP       string `json:"lan_ip"`
	WANRxBytes  string `json:"wan_rx_bytes"`
	WANTxBytes  string `json:"wan_tx_bytes"`
}

func NewSystemService(exec *executor.Executor, cfg config.Config) *SystemService {
	return &SystemService{exec: exec, cfg: cfg}
}

func (s *SystemService) GetInfo() SystemInfo {
	info := SystemInfo{
		WANInterface: s.cfg.WANInterface,
		LANInterface: s.cfg.LANInterface,
		LANIP:        s.cfg.LANGateway,
	}

	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			info.Uptime = fields[0] + "s"
		}
	}

	// Load average
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			info.LoadAvg = strings.Join(fields[:3], " ")
		}
	}

	// Memory
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		memMap := parseMeminfo(string(data))
		info.MemTotal = memMap["MemTotal"]
		info.MemFree = memMap["MemAvailable"]
		if info.MemFree == "" {
			info.MemFree = memMap["MemFree"]
		}
	}

	// WAN IP
	if result, err := s.exec.Run("ip", "-4", "-o", "addr", "show", s.cfg.WANInterface); err == nil {
		fields := strings.Fields(result.Stdout)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				info.WANIP = strings.Split(fields[i+1], "/")[0]
				break
			}
		}
	}

	// WAN traffic stats
	info.WANRxBytes = readStat(s.cfg.WANInterface, "rx_bytes")
	info.WANTxBytes = readStat(s.cfg.WANInterface, "tx_bytes")

	return info
}

func (s *SystemService) Reboot() error {
	_, err := s.exec.Run("systemctl", "reboot")
	return err
}

type ConnectivityResult struct {
	Host    string `json:"host"`
	Success bool   `json:"success"`
	Latency string `json:"latency"`
	Error   string `json:"error,omitempty"`
}

func (s *SystemService) TestConnectivity() []ConnectivityResult {
	hosts := []string{"1.1.1.1", "8.8.8.8", "google.com"}
	results := make([]ConnectivityResult, 0, len(hosts))

	for _, host := range hosts {
		r := ConnectivityResult{Host: host}
		result, err := s.exec.Run("ping", "-c", "1", "-W", "3", host)
		if err != nil {
			r.Success = false
			r.Error = err.Error()
		} else {
			r.Success = true
			// Extract latency from ping output
			for _, line := range strings.Split(result.Stdout, "\n") {
				if strings.Contains(line, "time=") {
					parts := strings.Split(line, "time=")
					if len(parts) > 1 {
						r.Latency = strings.Fields(parts[1])[0]
					}
				}
			}
		}
		results = append(results, r)
	}
	return results
}

func readStat(iface, stat string) string {
	path := fmt.Sprintf("/sys/class/net/%s/statistics/%s", iface, stat)
	data, err := os.ReadFile(path)
	if err != nil {
		return "0"
	}
	return strings.TrimSpace(string(data))
}

func parseMeminfo(data string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}
