package config

import "testing"

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
