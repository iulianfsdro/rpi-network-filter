package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr    string `yaml:"listen_addr"`
	UseTLS        bool   `yaml:"use_tls"`
	TLSCert       string `yaml:"tls_cert"`
	TLSKey        string `yaml:"tls_key"`
	DBPath        string `yaml:"db_path"`
	WANInterface  string `yaml:"wan_interface"`
	LANInterface  string `yaml:"lan_interface"`
	LANSubnet     string `yaml:"lan_subnet"`
	LANGateway    string `yaml:"lan_gateway"`
	DHCPRangeStart string `yaml:"dhcp_range_start"`
	DHCPRangeEnd   string `yaml:"dhcp_range_end"`
	DNSUpstream   string `yaml:"dns_upstream"`
	DryRun        bool   `yaml:"dry_run"`
	LogLevel      string `yaml:"log_level"`
}

func Defaults() Config {
	return Config{
		ListenAddr:     "192.168.4.1:80",
		UseTLS:         false,
		TLSCert:        "/etc/netfilterd/server.crt",
		TLSKey:         "/etc/netfilterd/server.key",
		DBPath:         "/var/lib/netfilterd/netfilter.db",
		WANInterface:   "eth1",
		LANInterface:   "wlan0",
		LANSubnet:      "192.168.4.0/24",
		LANGateway:     "192.168.4.1",
		DHCPRangeStart: "192.168.4.100",
		DHCPRangeEnd:   "192.168.4.250",
		DNSUpstream:    "1.1.1.1,8.8.8.8",
		DryRun:         false,
		LogLevel:       "info",
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnvOverrides(&cfg)
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyEnvOverrides(&cfg)
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	envMap := map[string]*string{
		"NETFILTER_LISTEN_ADDR":     &cfg.ListenAddr,
		"NETFILTER_TLS_CERT":        &cfg.TLSCert,
		"NETFILTER_TLS_KEY":         &cfg.TLSKey,
		"NETFILTER_DB_PATH":         &cfg.DBPath,
		"NETFILTER_WAN_INTERFACE":   &cfg.WANInterface,
		"NETFILTER_LAN_INTERFACE":   &cfg.LANInterface,
		"NETFILTER_LAN_SUBNET":      &cfg.LANSubnet,
		"NETFILTER_LAN_GATEWAY":     &cfg.LANGateway,
		"NETFILTER_DHCP_RANGE_START": &cfg.DHCPRangeStart,
		"NETFILTER_DHCP_RANGE_END":   &cfg.DHCPRangeEnd,
		"NETFILTER_DNS_UPSTREAM":     &cfg.DNSUpstream,
		"NETFILTER_LOG_LEVEL":        &cfg.LogLevel,
	}
	for env, ptr := range envMap {
		if v := os.Getenv(env); v != "" {
			*ptr = v
		}
	}
	if v := os.Getenv("NETFILTER_DRY_RUN"); v != "" {
		cfg.DryRun = strings.EqualFold(v, "true") || v == "1"
	}
}
