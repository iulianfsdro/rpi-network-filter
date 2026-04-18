package services

import (
	"net"
	"regexp"
	"strings"
)

// Input-validation helpers. Every value that flows into nftables / dnsmasq /
// hostapd config files MUST pass one of these before being persisted or
// emitted — the config files are parsed as shell-like DSLs and a newline
// or metacharacter in a string field is a direct rule-injection vector.

var (
	policyNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _-]{0,63}$`)
	domainNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	portSpecRe   = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?$`)
	macStrictRe  = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

	protocolValid = map[string]bool{
		"":     true,
		"all":  true,
		"tcp":  true,
		"udp":  true,
		"icmp": true,
	}
)

// ValidPolicyName: letters, digits, space, underscore, hyphen; first char
// must be alphanumeric; 1-64 chars. Blocks nft metacharacters like `]`,
// `\n`, `"`, `;`, `{`, `}`, `#` that would terminate a log prefix string.
func ValidPolicyName(s string) bool {
	return policyNameRe.MatchString(s)
}

// ValidDomain: strict RFC-ish hostname check, <=253 chars. Rejects `/`,
// whitespace, `#`, and any other character that would break dnsmasq's
// `nftset=` / `address=` directives.
func ValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	return domainNameRe.MatchString(s)
}

// ValidIPv4: net.ParseIP + To4 conversion. Rejects IPv6, CIDR, and any
// string with trailing garbage like "1.2.3.4 extra".
func ValidIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

// ValidIPOrCIDR: a single IPv4 or a CIDR.
func ValidIPOrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return ValidIPv4(s)
}

// ValidPortSpec: single port or hyphen range, each 1-65535. Empty ok.
func ValidPortSpec(s string) bool {
	if s == "" {
		return true
	}
	return portSpecRe.MatchString(s)
}

// ValidProtocol: matches the DB CHECK on firewall_rules.protocol.
func ValidProtocol(s string) bool {
	return protocolValid[s]
}

// ValidMAC: aa:bb:cc:dd:ee:ff exactly (case-insensitive, lowercased).
func ValidMAC(s string) bool {
	return macStrictRe.MatchString(strings.ToLower(s))
}

// SanitizeSingleLine strips newlines, carriage returns, and any ASCII
// control character from a value that ends up on a single line of a
// config file (hostapd SSID, WPA passphrase, etc.). Does not mangle
// printable unicode.
func SanitizeSingleLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || (r >= 0 && r < 32) || r == 127 {
			return -1
		}
		return r
	}, s)
}
