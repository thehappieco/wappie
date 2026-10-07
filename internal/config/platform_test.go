package config

import (
	"strings"
	"testing"
)

func TestPlatformLoginIsOffByDefault(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Platform.Enabled() || cfg.Platform.LocalLogin != LocalLoginOn {
		t.Fatalf("defaults: %+v", cfg.Platform)
	}
	if !strings.Contains(cfg.String(), "platform_login=off local_login=on") {
		t.Fatalf("startup line: %s", cfg.String())
	}
}

func TestPlatformLoginInDevelopment(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_PLATFORM_ISSUER", "http://id.thehappie.localhost:8290")
	t.Setenv("WS_PLATFORM_CLIENT_ID", "wappie-app")
	t.Setenv("WS_PLATFORM_APP_ORIGIN", "http://app.wappie.thehappie.localhost:5173")
	t.Setenv("WS_PLATFORM_ID_ADDR", "127.0.0.1:8290")
	t.Setenv("WS_LOCAL_LOGIN", "link_only")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Platform.Enabled() || cfg.Platform.LocalLogin != LocalLoginLinkOnly || cfg.Platform.IDAddr != "127.0.0.1:8290" {
		t.Fatalf("%+v", cfg.Platform)
	}
	if !strings.Contains(cfg.String(), "platform_login=on platform_issuer=http://id.thehappie.localhost:8290 local_login=link_only") {
		t.Fatalf("startup line: %s", cfg.String())
	}
}

func TestPlatformAppOriginDefaultsToTheAppURL(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_ENV", "prod")
	t.Setenv("WS_POSTGRES_DSN", "postgres://user:hunter2@db/whatserver2")
	t.Setenv("WS_APP_URL", "https://app.wappie.thehappie.co")
	t.Setenv("WS_PLATFORM_ISSUER", "https://id.thehappie.co")
	t.Setenv("WS_PLATFORM_CLIENT_ID", "wappie-app")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Platform.AppOrigin != "https://app.wappie.thehappie.co" {
		t.Fatalf("app origin %q", cfg.Platform.AppOrigin)
	}
}

func TestPlatformLoginRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		prod bool
		env  map[string]string
		want string
	}{
		"narrowed with no provider": {false, map[string]string{"WS_LOCAL_LOGIN": "off"}, "WS_LOCAL_LOGIN=link_only or off needs WS_PLATFORM_ISSUER"},
		"unknown mode":              {false, map[string]string{"WS_LOCAL_LOGIN": "maybe"}, "want on, link_only or off"},
		"client without issuer":     {false, map[string]string{"WS_PLATFORM_CLIENT_ID": "wappie-app"}, "need WS_PLATFORM_ISSUER"},
		"no client id": {false, map[string]string{"WS_PLATFORM_ISSUER": "https://id.thehappie.co",
			"WS_PLATFORM_APP_ORIGIN": "https://app.wappie.thehappie.co"}, "client id"},
		"issuer with a path": {false, map[string]string{"WS_PLATFORM_ISSUER": "https://id.thehappie.co/", "WS_PLATFORM_CLIENT_ID": "wappie-app",
			"WS_PLATFORM_APP_ORIGIN": "https://app.wappie.thehappie.co"}, "bare lowercase origin"},
		"cleartext issuer in prod": {true, map[string]string{"WS_PLATFORM_ISSUER": "http://id.thehappie.localhost:8290", "WS_PLATFORM_CLIENT_ID": "wappie-app",
			"WS_PLATFORM_APP_ORIGIN": "https://app.wappie.thehappie.co"}, "https in prod"},
		"cleartext page in prod": {true, map[string]string{"WS_PLATFORM_ISSUER": "https://id.thehappie.co", "WS_PLATFORM_CLIENT_ID": "wappie-app",
			"WS_PLATFORM_APP_ORIGIN": "http://app.wappie.thehappie.localhost:5173"}, "WS_PLATFORM_APP_ORIGIN"},
		"no page origin": {false, map[string]string{"WS_PLATFORM_ISSUER": "https://id.thehappie.co", "WS_PLATFORM_CLIENT_ID": "wappie-app"}, "WS_PLATFORM_APP_ORIGIN"},
		"page origin with a path": {false, map[string]string{"WS_PLATFORM_ISSUER": "https://id.thehappie.co", "WS_PLATFORM_CLIENT_ID": "wappie-app",
			"WS_PLATFORM_APP_ORIGIN": "https://app.wappie.thehappie.co/console"}, "WS_PLATFORM_APP_ORIGIN"},
		"dial address in prod": {true, map[string]string{"WS_PLATFORM_ISSUER": "https://id.thehappie.co", "WS_PLATFORM_CLIENT_ID": "wappie-app",
			"WS_PLATFORM_APP_ORIGIN": "https://app.wappie.thehappie.co", "WS_PLATFORM_ID_ADDR": "127.0.0.1:8290"}, "development only"},
		"alert without mail": {false, map[string]string{"WS_PLATFORM_ISSUER": "https://id.thehappie.co", "WS_PLATFORM_CLIENT_ID": "wappie-app",
			"WS_PLATFORM_APP_ORIGIN": "https://app.wappie.thehappie.co", "WS_SECURITY_ALERT_EMAIL": "ops@example.com"}, "configured mail sender"},
	} {
		t.Run(name, func(t *testing.T) {
			minimalEnv(t)
			if tc.prod {
				t.Setenv("WS_ENV", "prod")
				t.Setenv("WS_POSTGRES_DSN", "postgres://user:hunter2@db/whatserver2")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error with %q, got %v", tc.want, err)
			}
		})
	}
}
