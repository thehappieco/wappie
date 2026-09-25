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

// Two made-up relay secrets of the required shape.
const (
	enclaveSecret     = "ERERERERERERERERERERERERERERERERERERERERERE"
	enclaveSecretNext = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
	testWorkspace     = "01a08e0e-c546-7db3-9c44-e6352636d330"
)

// enclaveEnv lists the enclave beside the hosted reader, with a complete
// block for it.
func enclaveEnv(t *testing.T) {
	t.Helper()
	mcpEnv(t)
	t.Setenv("WS_MCP_READERS", "hosted,enclave")
	t.Setenv("WS_MCP_READER_ENCLAVE_URL", "https://mcp.wappie.thehappie.co:8443")
	t.Setenv("WS_MCP_READER_ENCLAVE_PUBLIC_ORIGIN", "https://mcp.wappie.thehappie.co")
	t.Setenv("WS_MCP_READER_ENCLAVE_SECRET", enclaveSecret)
	t.Setenv("WS_MCP_READER_ENCLAVE_PEER", "203.0.113.7/32")
	t.Setenv("WS_MCP_READER_ENCLAVE_TENANTS", testWorkspace)
}

// Unless told otherwise the connector has one reader, the hosted one, with
// today's variables and today's rules.
func TestMCPReadersDefaultToHosted(t *testing.T) {
	mcpEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.MCP.Readers, ",") != "hosted" || len(cfg.MCP.Attested) != 0 || !cfg.MCP.Hosted() {
		t.Fatalf("readers = %v, attested = %v", cfg.MCP.Readers, cfg.MCP.Attested)
	}
	if got := cfg.MCP.String(); !strings.HasPrefix(got, "mcp=enabled reader=http://127.0.0.1:18093 origin=https://api.example.com relay_secret=set redirect_hosts=") {
		t.Fatalf("String = %q", got)
	}
}

func TestMCPAttestedReaderLoads(t *testing.T) {
	enclaveEnv(t)
	t.Setenv("WS_MCP_READER_ENCLAVE_SECRET_NEXT", enclaveSecretNext)
	t.Setenv("WS_MCP_READER_ENCLAVE_PEER", " 203.0.113.7/32 , 198.51.100.4 ")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	r, ok := cfg.MCP.Reader("enclave")
	if !ok || !cfg.MCP.Hosted() || strings.Join(cfg.MCP.Readers, ",") != "hosted,enclave" {
		t.Fatalf("readers = %v", cfg.MCP.Readers)
	}
	if r.URL != "https://mcp.wappie.thehappie.co:8443" || r.PublicOrigin != "https://mcp.wappie.thehappie.co" ||
		r.Secret != enclaveSecret || r.SecretNext != enclaveSecretNext || len(r.Peers) != 2 ||
		r.Peers[1].String() != "198.51.100.4/32" || len(r.Tenants) != 1 || r.Tenants[0].String() != testWorkspace || r.AllTenants {
		t.Fatalf("reader = %s %v %v", r, r.Peers, r.Tenants)
	}
	if _, ok := cfg.MCP.Reader("hosted"); ok {
		t.Fatal("the hosted reader is not an attested one")
	}
	want := "reader[enclave]=url:https://mcp.wappie.thehappie.co:8443,origin:https://mcp.wappie.thehappie.co,secret:set,secret_next:set,peers:2,tenants:1"
	if !strings.Contains(cfg.MCP.String(), want) {
		t.Fatalf("String = %q", cfg.MCP.String())
	}

	t.Setenv("WS_MCP_READER_ENCLAVE_TENANTS", " * ")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := cfg.MCP.Reader("enclave"); !r.AllTenants || len(r.Tenants) != 0 || !strings.Contains(r.String(), "tenants:*") {
		t.Fatalf("every workspace: %s", r)
	}
}

// The enclave alone needs none of the hosted reader's variables.
func TestMCPEnclaveWithoutHosted(t *testing.T) {
	enclaveEnv(t)
	t.Setenv("WS_MCP_READERS", "enclave")
	for _, k := range []string{"WS_MCP_READER_URL", "WS_MCP_RELAY_SECRET", "WS_MCP_PUBLIC_ORIGIN"} {
		t.Setenv(k, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCP.Hosted() || len(cfg.MCP.Attested) != 1 {
		t.Fatalf("readers = %v", cfg.MCP.Readers)
	}
	if got := cfg.MCP.String(); strings.Contains(got, "relay_secret=") || !strings.Contains(got, "readers=enclave") {
		t.Fatalf("String = %q", got)
	}
}

func TestMCPAttestedReaderInvalid(t *testing.T) {
	for name, kv := range map[string][2]string{
		"no readers":             {"WS_MCP_READERS", " , "},
		"upper-case id":          {"WS_MCP_READERS", "hosted,Enclave"},
		"hyphen in id":           {"WS_MCP_READERS", "hosted,enclave-staging"},
		"id too long":            {"WS_MCP_READERS", "hosted,abcdefghijklmnopq"},
		"id starts with a digit": {"WS_MCP_READERS", "hosted,1enclave"},
		"duplicate id":           {"WS_MCP_READERS", "hosted,enclave,enclave"},
		"hosted block":           {"WS_MCP_READER_HOSTED_URL", "https://mcp.wappie.thehappie.co:8443"},
		"hosted secret":          {"WS_MCP_READER_HOSTED_SECRET", enclaveSecret},
		"url over http":          {"WS_MCP_READER_ENCLAVE_URL", "http://mcp.wappie.thehappie.co:8443"},
		"url without port":       {"WS_MCP_READER_ENCLAVE_URL", "https://mcp.wappie.thehappie.co"},
		"url with path":          {"WS_MCP_READER_ENCLAVE_URL", "https://mcp.wappie.thehappie.co:8443/internal"},
		"url with slash":         {"WS_MCP_READER_ENCLAVE_URL", "https://mcp.wappie.thehappie.co:8443/"},
		"url with query":         {"WS_MCP_READER_ENCLAVE_URL", "https://mcp.wappie.thehappie.co:8443?x=1"},
		"url with userinfo":      {"WS_MCP_READER_ENCLAVE_URL", "https://u:p@mcp.wappie.thehappie.co:8443"},
		"url on another host":    {"WS_MCP_READER_ENCLAVE_URL", "https://api.wappie.thehappie.co:8443"},
		"url port zero":          {"WS_MCP_READER_ENCLAVE_URL", "https://mcp.wappie.thehappie.co:0"},
		"url port too big":       {"WS_MCP_READER_ENCLAVE_URL", "https://mcp.wappie.thehappie.co:70000"},
		"url missing":            {"WS_MCP_READER_ENCLAVE_URL", ""},
		"origin over http":       {"WS_MCP_READER_ENCLAVE_PUBLIC_ORIGIN", "http://mcp.wappie.thehappie.co"},
		"origin with path":       {"WS_MCP_READER_ENCLAVE_PUBLIC_ORIGIN", "https://mcp.wappie.thehappie.co/mcp"},
		"origin localhost http":  {"WS_MCP_READER_ENCLAVE_PUBLIC_ORIGIN", "http://localhost:5443"},
		"origin missing":         {"WS_MCP_READER_ENCLAVE_PUBLIC_ORIGIN", ""},
		"secret short":           {"WS_MCP_READER_ENCLAVE_SECRET", enclaveSecret[:42]},
		"secret long":            {"WS_MCP_READER_ENCLAVE_SECRET", enclaveSecret + "E"},
		"secret standard base64": {"WS_MCP_READER_ENCLAVE_SECRET", "+" + enclaveSecret[1:]},
		"secret not canonical":   {"WS_MCP_READER_ENCLAVE_SECRET", enclaveSecret[:42] + "F"},
		"secret missing":         {"WS_MCP_READER_ENCLAVE_SECRET", ""},
		"next secret same":       {"WS_MCP_READER_ENCLAVE_SECRET_NEXT", enclaveSecret},
		"next secret bad":        {"WS_MCP_READER_ENCLAVE_SECRET_NEXT", "too-short"},
		"peer missing":           {"WS_MCP_READER_ENCLAVE_PEER", ""},
		"peer not an address":    {"WS_MCP_READER_ENCLAVE_PEER", "parent.example"},
		"tenants missing":        {"WS_MCP_READER_ENCLAVE_TENANTS", ""},
		"tenant not a uuid":      {"WS_MCP_READER_ENCLAVE_TENANTS", "acme"},
		"tenant nil uuid":        {"WS_MCP_READER_ENCLAVE_TENANTS", "00000000-0000-0000-0000-000000000000"},
		"star among tenants":     {"WS_MCP_READER_ENCLAVE_TENANTS", "*," + testWorkspace},
		"tenant without hyphens": {"WS_MCP_READER_ENCLAVE_TENANTS", strings.ReplaceAll(testWorkspace, "-", "")},
		"hosted still checked":   {"WS_MCP_RELAY_SECRET", "too-short"},
	} {
		t.Run(name, func(t *testing.T) {
			enclaveEnv(t)
			t.Setenv(kv[0], kv[1])
			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted %s=%q", kv[0], kv[1])
			}
		})
	}
	// The error names the variable, so the operator knows which to fix.
	enclaveEnv(t)
	t.Setenv("WS_MCP_READER_ENCLAVE_SECRET", "nope")
	if err := mustFail(t); !strings.Contains(err.Error(), "WS_MCP_READER_ENCLAVE_SECRET") {
		t.Fatalf("error = %v", err)
	}
}

// A disabled connector does not look at its readers either.
func TestMCPDisabledIgnoresReaders(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_MCP_READERS", "Not,Valid,,")
	t.Setenv("WS_MCP_READER_HOSTED_URL", "x")
	if _, err := Load(); err != nil {
		t.Fatalf("a disabled connector was inspected: %v", err)
	}
}

// Neither reader secret is ever rendered, however the block is printed.
func TestMCPReaderSecretsNeverRendered(t *testing.T) {
	enclaveEnv(t)
	t.Setenv("WS_MCP_READER_ENCLAVE_SECRET_NEXT", enclaveSecretNext)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{
		cfg.String(), cfg.MCP.String(), fmt.Sprint(cfg.MCP), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%+v", cfg.MCP.Attested),
		fmt.Sprintf("%#v", cfg.MCP.Attested), fmt.Sprintf("%v", cfg.MCP.Attested[0]),
	} {
		if strings.Contains(rendered, enclaveSecret) || strings.Contains(rendered, enclaveSecretNext) {
			t.Errorf("rendered config leaks a reader secret:\n%s", rendered)
		}
	}
}
