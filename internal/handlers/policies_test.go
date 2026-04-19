package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// makeReq builds an HTTP request whose chi route context carries {mac}=raw,
// which is how extractMAC receives the path parameter in production.
func makeReq(raw string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("mac", raw)
	req := httptest.NewRequest(http.MethodPut, "/", nil)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestExtractMAC(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantMAC string
		wantErr bool
	}{
		{"lowercase colon-separated", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", false},
		{"uppercase normalised", "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff", false},
		{"real-world Tesla MAC", "4C:FC:AA:17:37:75", "4c:fc:aa:17:37:75", false},
		{"URL-encoded colon — v8 regression guard", "aa%3abb%3acc%3add%3aee%3aff", "aa:bb:cc:dd:ee:ff", false},
		{"URL-encoded uppercase", "AA%3ABB%3ACC%3ADD%3AEE%3AFF", "aa:bb:cc:dd:ee:ff", false},
		{"too short", "aa:bb:cc:dd:ee", "", true},
		{"non-hex char", "aa:bb:cc:dd:ee:gg", "", true},
		{"wrong separator", "aa-bb-cc-dd-ee-ff", "", true},
		{"not a mac", "not-a-mac", "", true},
		{"empty", "", "", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := extractMAC(makeReq(c.raw))
			if c.wantErr {
				if err == nil {
					t.Errorf("extractMAC(%q) want error, got MAC=%q", c.raw, got)
				}
				return
			}
			if err != nil {
				t.Errorf("extractMAC(%q) unexpected error: %v", c.raw, err)
				return
			}
			if got != c.wantMAC {
				t.Errorf("extractMAC(%q) = %q, want %q", c.raw, got, c.wantMAC)
			}
		})
	}
}
