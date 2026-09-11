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
