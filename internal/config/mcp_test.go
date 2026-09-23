package config

import (
	"fmt"
	"strings"
	"testing"
)

// mcpEnv enables the connector with a complete, valid block on top of the
// minimal environment. The secret is a fixed run of characters, not a token.
func mcpEnv(t *testing.T) {
	t.Helper()
	minimalEnv(t)
	t.Setenv("WS_MCP_ENABLED", "true")
	t.Setenv("WS_MCP_READER_URL", "http://127.0.0.1:18093")
	t.Setenv("WS_MCP_RELAY_SECRET", strings.Repeat("relay-", 8))
	t.Setenv("WS_MCP_PUBLIC_ORIGIN", "https://api.example.com")
}

// Off by default, with nothing else required and nothing else inspected: a
// server that does not run the reader must not need to know about it.
func TestMCPDisabledByDefault(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_MCP_READER_URL", "not a url at all")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCP.Enabled {
		t.Fatal("the connector should be off unless asked for")
	}
	if got := strings.Join(cfg.MCP.RedirectHosts, ","); got != "claude.ai,chatgpt.com" {
		t.Errorf("default redirect hosts = %q", got)
	}
	if !strings.Contains(cfg.String(), "mcp=disabled") {
		t.Errorf("the startup line should say the connector is off: %s", cfg.String())
	}
}

func TestMCPEnabledLoads(t *testing.T) {
	mcpEnv(t)
	t.Setenv("WS_MCP_REDIRECT_HOSTS", " Claude.AI , chatgpt.com ,,")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.MCP.Enabled || cfg.MCP.ReaderURL != "http://127.0.0.1:18093" || cfg.MCP.PublicOrigin != "https://api.example.com" {
		t.Fatalf("MCP = %+v", cfg.MCP)
	}
	if got := strings.Join(cfg.MCP.RedirectHosts, ","); got != "claude.ai,chatgpt.com" {
		t.Errorf("redirect hosts = %q, want them trimmed and lower-cased", got)
	}
	if !strings.Contains(cfg.String(), "mcp=enabled") {
		t.Errorf("startup line: %s", cfg.String())
	}
}

// When the connector is on, every value is required; a half-configured relay
// fails at the moment somebody consents, which is the wrong moment.
func TestMCPRequiresEveryValueWhenEnabled(t *testing.T) {
	for _, missing := range []string{"WS_MCP_READER_URL", "WS_MCP_RELAY_SECRET", "WS_MCP_PUBLIC_ORIGIN", "WS_MCP_REDIRECT_HOSTS"} {
		t.Run(missing, func(t *testing.T) {
			mcpEnv(t)
			t.Setenv(missing, " ")
			err := mustFail(t)
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("error does not name %s: %v", missing, err)
			}
		})
	}
}

func TestMCPInvalidValues(t *testing.T) {
	for name, kv := range map[string][2]string{
		"reader over https":     {"WS_MCP_READER_URL", "https://127.0.0.1:18093"},
		"reader off host":       {"WS_MCP_READER_URL", "http://10.0.0.5:18093"},
		"reader with path":      {"WS_MCP_READER_URL", "http://127.0.0.1:18093/internal"},
		"reader with userinfo":  {"WS_MCP_READER_URL", "http://user:pw@127.0.0.1:18093"},
		"reader not a url":      {"WS_MCP_READER_URL", "::not-a-url"},
		"short secret":          {"WS_MCP_RELAY_SECRET", "too-short"},
		"origin with path":      {"WS_MCP_PUBLIC_ORIGIN", "https://api.example.com/mcp"},
		"origin with query":     {"WS_MCP_PUBLIC_ORIGIN", "https://api.example.com/?x=1"},
		"origin with userinfo":  {"WS_MCP_PUBLIC_ORIGIN", "https://evil@api.example.com"},
		"origin plain http":     {"WS_MCP_PUBLIC_ORIGIN", "http://api.example.com"},
		"origin no host":        {"WS_MCP_PUBLIC_ORIGIN", "https://"},
		"host with scheme":      {"WS_MCP_REDIRECT_HOSTS", "https://claude.ai"},
		"host with port":        {"WS_MCP_REDIRECT_HOSTS", "claude.ai:443"},
		"host with wildcard":    {"WS_MCP_REDIRECT_HOSTS", "*.claude.ai"},
		"host with empty label": {"WS_MCP_REDIRECT_HOSTS", "claude..ai"},
		"host with hyphen edge": {"WS_MCP_REDIRECT_HOSTS", "-claude.ai"},
		"host with space":       {"WS_MCP_REDIRECT_HOSTS", "clau de.ai"},
		"host with unicode":     {"WS_MCP_REDIRECT_HOSTS", "claudé.ai"},
		"bad bool":              {"WS_MCP_ENABLED", "maybe"},
	} {
		t.Run(name, func(t *testing.T) {
			mcpEnv(t)
			t.Setenv(kv[0], kv[1])
			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted %s=%q", kv[0], kv[1])
			}
		})
	}
}

// A laptop runs the whole flow over plain http on loopback; production does
// not get to.
func TestMCPLocalOriginsOnlyInDev(t *testing.T) {
	for _, origin := range []string{"http://localhost:18093", "http://127.0.0.1:18093", "http://[::1]:18093"} {
		t.Run(origin, func(t *testing.T) {
			mcpEnv(t)
			t.Setenv("WS_MCP_PUBLIC_ORIGIN", origin)
			if _, err := Load(); err != nil {
				t.Fatalf("dev should allow %s: %v", origin, err)
			}
			t.Setenv("WS_ENV", "prod")
			t.Setenv("WS_POSTGRES_DSN", "postgres://user:pw@db/whatserver2")
			err := mustFail(t)
			if !strings.Contains(err.Error(), "WS_MCP_PUBLIC_ORIGIN") {
				t.Errorf("error = %v", err)
			}
		})
	}
	t.Run("localhost reader in prod", func(t *testing.T) {
		mcpEnv(t)
		t.Setenv("WS_ENV", "prod")
		t.Setenv("WS_POSTGRES_DSN", "postgres://user:pw@db/whatserver2")
		t.Setenv("WS_MCP_READER_URL", "http://localhost:18093")
		if _, err := Load(); err != nil {
			t.Fatalf("the reader is loopback by construction and fine in prod: %v", err)
		}
	})
}

// The relay secret is a credential, and the startup line renders the block.
func TestMCPSecretNeverRendered(t *testing.T) {
	mcpEnv(t)
	const secret = "relay-secret-please-do-not-print"
	t.Setenv("WS_MCP_RELAY_SECRET", secret)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{cfg.String(), cfg.MCP.String(), fmt.Sprint(cfg.MCP), fmt.Sprintf("%+v", cfg)} {
		if strings.Contains(rendered, secret) {
			t.Errorf("rendered config leaks the relay secret:\n%s", rendered)
		}
	}
	if !strings.Contains(cfg.MCP.String(), "relay_secret=set") || !strings.Contains(cfg.MCP.String(), "reader=http://127.0.0.1:18093") {
		t.Errorf("the rendering lost what makes it useful: %s", cfg.MCP)
	}
}

func TestMCPValidateDirect(t *testing.T) {
	if err := (MCP{}).Validate(true); err != nil {
		t.Errorf("a disabled block validates: %v", err)
	}
	unset := MCP{Enabled: true, RelaySecret: ""}
	if err := unset.Validate(false); err == nil {
		t.Error("an enabled block with nothing set validated")
	}
	if got := unset.String(); !strings.Contains(got, "relay_secret=unset") {
		t.Errorf("String = %q", got)
	}
}

// The verification token is served as a response body verbatim, so it is
// held to something that can be: printable, no whitespace, bounded.
func TestMCPOpenAIAppsChallenge(t *testing.T) {
	mcpEnv(t)
	t.Setenv("WS_MCP_OPENAI_APPS_CHALLENGE", "  oa-verify-3f9c2e  ")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCP.OpenAIAppsChallenge != "oa-verify-3f9c2e" {
		t.Errorf("token = %q, want it trimmed", cfg.MCP.OpenAIAppsChallenge)
	}
	for _, bad := range []string{"two words", strings.Repeat("x", 257), "tab\there"} {
		t.Setenv("WS_MCP_OPENAI_APPS_CHALLENGE", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "WS_MCP_OPENAI_APPS_CHALLENGE") {
			t.Errorf("%q: err = %v, want a refusal naming the variable", bad, err)
		}
	}
}
