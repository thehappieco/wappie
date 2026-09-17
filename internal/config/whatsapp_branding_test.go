package config

import (
	"strings"
	"testing"
)

func TestWhatsAppDeviceName(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
	}{
		{"default external", "", "whappie"},
		{"explicit external", "whappie", "whappie"},
		{"managed", "whappie cloud", "whappie cloud"},
		{"trimmed", " whappie cloud ", "whappie cloud"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			minimalEnv(t)
			t.Setenv("WS_WA_DEVICE_NAME", tc.value)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.WADeviceName != tc.want {
				t.Fatalf("device name = %q, want %q", cfg.WADeviceName, tc.want)
			}
		})
	}
}

func TestWhatsAppDeviceNameRejectsUnsupportedBrand(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_WA_DEVICE_NAME", "whatsmeow")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "WS_WA_DEVICE_NAME") {
		t.Fatalf("expected device name configuration error, got %v", err)
	}
}
