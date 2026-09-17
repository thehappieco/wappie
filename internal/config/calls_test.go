package config

import (
	"strings"
	"testing"
)

func TestCallsConfiguration(t *testing.T) {
	minimalEnv(t)
	for _, value := range []string{"", "true", "false", "invalid"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("WS_CALLS_ENABLED", value)
			cfg, err := Load()
			if value == "invalid" {
				if err == nil || !strings.Contains(err.Error(), "WS_CALLS_ENABLED") {
					t.Fatalf("invalid calls setting: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.CallsEnabled != (value != "false") {
				t.Fatalf("calls enabled = %v for %q", cfg.CallsEnabled, value)
			}
		})
	}
}
