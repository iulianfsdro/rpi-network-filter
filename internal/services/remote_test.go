package services

import "testing"

// Tests for parseServeStatus — the JSON-shape detector for Tailscale
// Funnel-on-/api/ble. The CLI output here mirrors what `tailscale serve
// status --json` returns on Tailscale 1.50+; if the shape ever
// changes upstream, these tests will catch the regression before the
// /remote-access UI silently stops detecting the Funnel state.

const sampleFunnelOn = `{
  "Web": {
    "pi.tail1234.ts.net:443": {
      "Handlers": {
        "/api/ble": {
          "Proxy": "https+insecure://localhost:8443"
        }
      }
    }
  },
  "AllowFunnel": {
    "pi.tail1234.ts.net:443": true
  }
}`

const sampleServeOnlyNoFunnel = `{
  "Web": {
    "pi.tail1234.ts.net:443": {
      "Handlers": {
        "/api/ble": {
          "Proxy": "https+insecure://localhost:8443"
        }
      }
    }
  },
  "AllowFunnel": {}
}`

const sampleWrongPath = `{
  "Web": {
    "pi.tail1234.ts.net:443": {
      "Handlers": {
        "/something-else": {
          "Proxy": "http://localhost:3000"
        }
      }
    }
  },
  "AllowFunnel": {
    "pi.tail1234.ts.net:443": true
  }
}`

const sampleEmpty = `{}`

func TestParseServeStatus_FunnelOn(t *testing.T) {
	on, url := parseServeStatus([]byte(sampleFunnelOn), "pi.tail1234.ts.net")
	if !on {
		t.Errorf("expected funnel on, got off")
	}
	if want := "https://pi.tail1234.ts.net/api/ble"; url != want {
		t.Errorf("url = %q, want %q", url, want)
	}
}

func TestParseServeStatus_ServeOnlyIsNotFunnel(t *testing.T) {
	// A serve handler without AllowFunnel=true means tailnet-only, not
	// public. We must report off — the toggle's whole point is public
	// exposure.
	on, url := parseServeStatus([]byte(sampleServeOnlyNoFunnel), "pi.tail1234.ts.net")
	if on {
		t.Errorf("serve-only should not count as funnel")
	}
	if url != "" {
		t.Errorf("url should be empty when off, got %q", url)
	}
}

func TestParseServeStatus_WrongPathIsIgnored(t *testing.T) {
	on, _ := parseServeStatus([]byte(sampleWrongPath), "pi.tail1234.ts.net")
	if on {
		t.Errorf("handler on a different path should not match /api/ble")
	}
}

func TestParseServeStatus_EmptyConfig(t *testing.T) {
	on, _ := parseServeStatus([]byte(sampleEmpty), "pi.tail1234.ts.net")
	if on {
		t.Errorf("empty serve config should be off")
	}
}

func TestParseServeStatus_GarbageJSON(t *testing.T) {
	on, _ := parseServeStatus([]byte("not json"), "pi.tail1234.ts.net")
	if on {
		t.Errorf("garbage JSON should default to off (silent)")
	}
}
