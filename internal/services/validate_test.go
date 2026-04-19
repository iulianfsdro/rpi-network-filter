package services

import "testing"

func TestValidPolicyName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"Tesla", true},
		{"Default", true},
		{"Open", true},
		{"Kids tablet", true},
		{"policy_1", true},
		{"a-b-c", true},
		{"", false},
		{" leading", false},
		{"-dash-start", false},
		{"has\nnewline", false},
		{`has"quote`, false},
		{"drop] drop", false},              // nft log-prefix injection
		{"policy;drop table", false},        // SQL-adjacent junk
		{string(make([]byte, 65)), false},   // too long
	}
	for _, c := range cases {
		if got := ValidPolicyName(c.in); got != c.want {
			t.Errorf("ValidPolicyName(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidDomain(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"a.b.c.d.example.com", true},
		{"connman.vn.tesla.services", true},
		{"x.io", true},
		{"", false},
		{"localhost", true},
		{"ex ample.com", false},                       // space
		{"evil.com\nnftset=/bad/inet#filter", false}, // newline injection
		{"foo/bar", false},                            // slash breaks dnsmasq address=
		{"has#hash.com", false},
		{".leading-dot", false},
		{"trailing-dot.", false},
		{"-startshypen.com", false},
	}
	for _, c := range cases {
		if got := ValidDomain(c.in); got != c.want {
			t.Errorf("ValidDomain(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidIPv4(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"192.168.4.1", true},
		{"1.1.1.1", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"1.2.3.4 extra", false},
		{"::1", false},
		{"2606:4700:4700::1111", false},
		{"", false},
		{"1.2.3", false},
		{"1.2.3.4.5", false},
	}
	for _, c := range cases {
		if got := ValidIPv4(c.in); got != c.want {
			t.Errorf("ValidIPv4(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidMAC(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA:BB:CC:DD:EE:FF", true},  // lowercased internally
		{"4c:fc:aa:17:37:75", true},
		{"aa:bb:cc:dd:ee:gg", false},                     // non-hex
		{"aa%3abb%3acc%3add%3aee%3aff", false},            // URL-encoded (v8 bug regression guard)
		{"aa-bb-cc-dd-ee-ff", false},                      // wrong separator
		{"aabbccddeeff", false},                           // missing separators
		{"aa:bb:cc:dd:ee", false},                         // too short
		{"", false},
	}
	for _, c := range cases {
		if got := ValidMAC(c.in); got != c.want {
			t.Errorf("ValidMAC(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSanitizeSingleLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"NetFilter", "NetFilter"},
		{"hello world", "hello world"},
		{"newline\nhere", "newlinehere"},
		{"cr\rhere", "crhere"},
		{"tab\there", "tabhere"},
		{"bell\x07here", "bellhere"},
		{"del\x7fhere", "delhere"},
		{"", ""},
	}
	for _, c := range cases {
		if got := SanitizeSingleLine(c.in); got != c.want {
			t.Errorf("SanitizeSingleLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidProtocol(t *testing.T) {
	for _, p := range []string{"", "all", "tcp", "udp", "icmp"} {
		if !ValidProtocol(p) {
			t.Errorf("ValidProtocol(%q) should be true", p)
		}
	}
	for _, p := range []string{"ftp", "TCP", "tcp;drop", "\n"} {
		if ValidProtocol(p) {
			t.Errorf("ValidProtocol(%q) should be false", p)
		}
	}
}

func TestValidPortSpec(t *testing.T) {
	good := []string{"", "22", "80", "8443", "1-65535", "80-443"}
	bad := []string{"abc", "22/tcp", "80;drop", "80 443", "1-2-3"}
	for _, s := range good {
		if !ValidPortSpec(s) {
			t.Errorf("ValidPortSpec(%q) should be true", s)
		}
	}
	for _, s := range bad {
		if ValidPortSpec(s) {
			t.Errorf("ValidPortSpec(%q) should be false", s)
		}
	}
}

func TestValidIPOrCIDR(t *testing.T) {
	good := []string{"", "192.168.4.1", "10.0.0.0/8", "172.16.0.0/12"}
	bad := []string{"1.2.3", "1.2.3.4/", "1.2.3.4/33", "foo"}
	for _, s := range good {
		if !ValidIPOrCIDR(s) {
			t.Errorf("ValidIPOrCIDR(%q) should be true", s)
		}
	}
	for _, s := range bad {
		if ValidIPOrCIDR(s) {
			t.Errorf("ValidIPOrCIDR(%q) should be false", s)
		}
	}
}
