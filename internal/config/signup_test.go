package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestSignupRequiresVerifiedMailTransport(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_PUBLIC_SIGNUP", "true")
	if _, err := Load(); err == nil {
		t.Fatal("enabled signup without verification mail")
	}
	t.Setenv("WS_APP_URL", "https://app.example.com")
	t.Setenv("WS_SMTP_ADDR", "smtp.example.com:587")
	t.Setenv("WS_MAIL_FROM", "Wappie <accounts@example.com>")
	t.Setenv("WS_SMTP_USERNAME", "smtp-user")
	t.Setenv("WS_SMTP_PASSWORD", "do-not-print")
	t.Setenv("WS_INVITE_ENCRYPTION_KEY_HEX", strings.Repeat("ab", 32))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Signup.Enabled || len(cfg.Signup.InviteEncryptionKey) != 32 {
		t.Fatal("configuration missing")
	}
	for _, value := range []string{fmt.Sprint(cfg), fmt.Sprint(cfg.Signup), fmt.Sprint(cfg.Signup.SMTP)} {
		if strings.Contains(value, "do-not-print") || strings.Contains(value, strings.Repeat("ab", 32)) {
			t.Fatal("secret exposed")
		}
	}
	for _, base := range []string{"http://app.example.com", "https://evil@trusted.example", "https://app.example.com/?redirect=evil", "https://app.example.com/#hash", "https://app.example.com/path"} {
		t.Setenv("WS_APP_URL", base)
		if _, err := Load(); err == nil {
			t.Fatalf("accepted unsafe app URL %s", base)
		}
	}
}

func TestSignupRejectsMailDowngradeAndMalformedKey(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_APP_URL", "https://app.example.com")
	t.Setenv("WS_SMTP_ADDR", "smtp.example.com:587")
	t.Setenv("WS_MAIL_FROM", "accounts@example.com")
	t.Setenv("WS_SMTP_TLS", "none")
	if _, err := Load(); err == nil {
		t.Fatal("accepted cleartext mail")
	}
	t.Setenv("WS_SMTP_TLS", "implicit")
	t.Setenv("WS_INVITE_ENCRYPTION_KEY_HEX", "secret")
	if _, err := Load(); err == nil {
		t.Fatal("accepted malformed key")
	}
	t.Setenv("WS_INVITE_ENCRYPTION_KEY_HEX", "")
	t.Setenv("WS_MAIL_FROM", "a@example.com\r\nBcc: evil@example.com")
	if _, err := Load(); err == nil {
		t.Fatal("accepted injected header")
	}
}

func TestMailLinksNeverUseLocalOrigins(t *testing.T) {
	for _, origin := range []string{"http://localhost:5173", "https://localhost", "https://dev.localhost", "https://127.0.0.1", "https://[::1]", "https://0.0.0.0", "https://127.1", "https://0x7f000001"} {
		for _, prod := range []bool{false, true} {
			signup := Signup{AppURL: origin, SMTP: SMTP{Address: "smtp.example.com:465", From: "accounts@example.com", TLSMode: "implicit"}}
			if err := signup.Validate(prod); err == nil {
				t.Errorf("accepted emailed local origin %s, prod=%v", origin, prod)
			}
		}
	}
	if err := (Signup{AppURL: "http://localhost:5173"}).Validate(false); err != nil {
		t.Fatal("mail-free local development rejected:", err)
	}
	if err := (Signup{AppURL: "https://localhost"}).Validate(true); err == nil {
		t.Fatal("production localhost accepted")
	}
	for _, origin := range []string{"https://app.wappie.thehappie.co", "https://self-hosted.example.org:8443/"} {
		if _, err := AccountBrowserOrigin(origin, false); err != nil {
			t.Fatalf("valid public origin rejected: %v", err)
		}
	}
}
