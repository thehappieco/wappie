package config

import (
	"strings"
	"testing"
)

func TestPasskeyConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   Passkeys
		prod  bool
		valid bool
	}{
		{"disabled", Passkeys{}, true, true},
		{"hosted", Passkeys{"wappie.thehappie.co", []string{"https://app.wappie.thehappie.co", "https://console.wappie.thehappie.co"}}, true, true},
		{"self-host", Passkeys{"messaging.example.net", []string{"https://messaging.example.net:8443"}}, true, true},
		{"localhost-dev", Passkeys{"localhost", []string{"http://localhost:5173"}}, false, true},
		{"localhost-prod", Passkeys{"localhost", []string{"http://localhost:5173"}}, true, false},
		{"partial-rp", Passkeys{"example.com", nil}, true, false},
		{"partial-origins", Passkeys{"", []string{"https://example.com"}}, true, false},
		{"public-suffix", Passkeys{"co.uk", []string{"https://example.co.uk"}}, true, false},
		{"wildcard", Passkeys{"*.example.com", []string{"https://app.example.com"}}, true, false},
		{"sibling", Passkeys{"app.example.com", []string{"https://other.example.com"}}, true, false},
		{"suffix-confusion", Passkeys{"example.com", []string{"https://evil-example.com"}}, true, false},
		{"userinfo", Passkeys{"example.com", []string{"https://user@example.com"}}, true, false},
		{"path", Passkeys{"example.com", []string{"https://example.com/app"}}, true, false},
		{"insecure", Passkeys{"example.com", []string{"http://example.com"}}, false, false},
		{"ip", Passkeys{"127.0.0.1", []string{"https://127.0.0.1"}}, false, false},
		{"trailing-dot", Passkeys{"example.com.", []string{"https://example.com."}}, true, false},
		{"invalid-label", Passkeys{"-app.example.com", []string{"https://-app.example.com"}}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(tc.prod); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

// A relying party id that ends in a number is refused by the kit's
// passkey.EndsInANumber, whatever else would let it through: a browser reads
// it as an IPv4 address or refuses it. A number in another label, or a last
// label that only looks like one, is a domain.
func TestPasskeyRPIDEndsInANumber(t *testing.T) {
	for _, rpID := range []string{"0x7f000001", "1.2.3.0x4", "id.0xff", "app.0x", "app.wappie.123"} {
		t.Run(rpID, func(t *testing.T) {
			err := Passkeys{rpID, []string{"https://" + rpID}}.Validate(true)
			if err == nil || !strings.Contains(err.Error(), "ends in a number") {
				t.Fatalf("%q: %v", rpID, err)
			}
		})
	}
	for _, rpID := range []string{"app.wappie.thehappie.co", "0x7f.example.com", "id.0x1g", "id.00x1"} {
		t.Run(rpID, func(t *testing.T) {
			if err := (Passkeys{rpID, []string{"https://" + rpID}}).Validate(true); err != nil {
				t.Fatalf("%q: %v", rpID, err)
			}
		})
	}
}

func TestLoadPasskeyConfiguration(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_PASSKEY_RP_ID", "wappie.example.com")
	t.Setenv("WS_PASSKEY_ORIGINS", " https://app.wappie.example.com , https://console.wappie.example.com ")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Passkeys.RPID != "wappie.example.com" || len(cfg.Passkeys.Origins) != 2 || cfg.Passkeys.Origins[0] != "https://app.wappie.example.com" {
		t.Fatalf("bad passkey config: %+v", cfg.Passkeys)
	}
}
