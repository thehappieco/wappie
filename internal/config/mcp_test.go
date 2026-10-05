package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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

// Content is off unless switched on, and the startup line says which.
func TestMCPContentOffByDefault(t *testing.T) {
	enclaveEnv(t)
	t.Setenv("WS_MCP_CONTENT_TENANTS", "not even a uuid")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("a retired list was inspected with content off: %v", err)
	}
	if cfg.MCP.ContentEnabled || cfg.MCP.ContentAllowed(uuid.MustParse(testWorkspace)) {
		t.Fatal("content allowed with the switch off")
	}
	if cfg.MCP.WorkspaceDefault || !strings.Contains(cfg.MCP.String(), " content=off workspace_default=off deny_tenants=0") {
		t.Fatalf("String = %q", cfg.MCP.String())
	}
}

// With the switch on, the operator's half of the answer is the enclave's
// TENANTS less the deny list; each workspace's own switch, which its owner
// sets, comes on top (mcpauth.WorkspaceSwitches) and defaults to
// WS_MCP_WORKSPACE_DEFAULT.
func TestMCPContentLoads(t *testing.T) {
	enclaveEnv(t)
	t.Setenv("WS_MCP_CONTENT_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	workspace := uuid.MustParse(testWorkspace)
	if !cfg.MCP.ContentEnabled || !cfg.MCP.ContentAllowed(workspace) || cfg.MCP.ContentAllowed(uuid.New()) {
		t.Fatal("ContentAllowed does not follow the enclave's workspaces")
	}
	if !strings.Contains(cfg.MCP.String(), " content=on workspace_default=off deny_tenants=0") {
		t.Fatalf("String = %q", cfg.MCP.String())
	}
	// An enclave open to every workspace lets every one have text.
	t.Setenv("WS_MCP_READER_ENCLAVE_TENANTS", "*")
	if cfg, err = Load(); err != nil || !cfg.MCP.ContentAllowed(workspace) || !cfg.MCP.ContentAllowed(uuid.New()) {
		t.Fatalf("enclave for every workspace: %v", err)
	}
	// Except those the operator denies.
	other := uuid.MustParse("0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee")
	t.Setenv("WS_MCP_DENY_TENANTS", " "+other.String()+" ,,"+other.String())
	if cfg, err = Load(); err != nil || cfg.MCP.ContentAllowed(other) || !cfg.MCP.ContentAllowed(workspace) || len(cfg.MCP.DenyTenants) != 1 {
		t.Fatalf("deny list: %v %v", err, cfg.MCP.DenyTenants)
	}
	if !strings.Contains(cfg.MCP.String(), " deny_tenants=1") {
		t.Fatalf("String = %q", cfg.MCP.String())
	}
	// Wappie Cloud's default.
	for _, value := range []string{"on", " ON "} {
		t.Setenv("WS_MCP_WORKSPACE_DEFAULT", value)
		if cfg, err = Load(); err != nil || !cfg.MCP.WorkspaceDefault || !strings.Contains(cfg.MCP.String(), " workspace_default=on") {
			t.Fatalf("default %q: %v %q", value, err, cfg.MCP.String())
		}
	}
	t.Setenv("WS_MCP_WORKSPACE_DEFAULT", "off")
	if cfg, err = Load(); err != nil || cfg.MCP.WorkspaceDefault {
		t.Fatalf("default off: %v", err)
	}
	// The connector off turns content off whatever the switch says.
	cfg.MCP.Enabled = false
	if cfg.MCP.ContentAllowed(workspace) {
		t.Fatal("content allowed with the connector off")
	}
}

func TestMCPContentInvalid(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"a retired list":          {"WS_MCP_CONTENT_TENANTS": testWorkspace},
		"deny every workspace":    {"WS_MCP_DENY_TENANTS": "*"},
		"deny not a uuid":         {"WS_MCP_DENY_TENANTS": "acme"},
		"deny the nil uuid":       {"WS_MCP_DENY_TENANTS": "00000000-0000-0000-0000-000000000000"},
		"default neither":         {"WS_MCP_WORKSPACE_DEFAULT": "true"},
		"no enclave reader":       {"WS_MCP_READERS": "hosted"},
		"another attested reader": {"WS_MCP_READERS": "hosted,staging"},
		"switch not a boolean":    {"WS_MCP_CONTENT_ENABLED": "maybe"},
	} {
		t.Run(name, func(t *testing.T) {
			enclaveEnv(t)
			t.Setenv("WS_MCP_CONTENT_ENABLED", "true")
			for k, v := range env {
				t.Setenv(k, v)
			}
			if env["WS_MCP_READERS"] == "hosted,staging" {
				for _, k := range []string{"URL", "PUBLIC_ORIGIN", "SECRET", "PEER", "TENANTS"} {
					t.Setenv("WS_MCP_READER_STAGING_"+k, os.Getenv("WS_MCP_READER_ENCLAVE_"+k))
				}
			}
			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted %v", env)
			}
		})
	}
	// A retired list says what replaced it, so nobody believes it still
	// restricts.
	t.Run("retired list message", func(t *testing.T) {
		enclaveEnv(t)
		t.Setenv("WS_MCP_CONTENT_ENABLED", "true")
		t.Setenv("WS_MCP_CONTENT_TENANTS", testWorkspace)
		if err := mustFail(t); !strings.Contains(err.Error(), "WS_MCP_CONTENT_TENANTS is no longer read") ||
			!strings.Contains(err.Error(), "WS_MCP_WORKSPACE_DEFAULT") || !strings.Contains(err.Error(), "WS_MCP_DENY_TENANTS") {
			t.Fatalf("error = %v", err)
		}
	})
	// A disabled connector does not look at the switch, the default or the
	// deny list either.
	minimalEnv(t)
	t.Setenv("WS_MCP_CONTENT_ENABLED", "true")
	t.Setenv("WS_MCP_WORKSPACE_DEFAULT", "maybe")
	t.Setenv("WS_MCP_DENY_TENANTS", "*")
	if _, err := Load(); err != nil {
		t.Fatalf("a disabled connector's content block was inspected: %v", err)
	}
}

// mediaEnv is enclaveEnv with content on; the enclave admits the test
// workspace only.
func mediaEnv(t *testing.T) {
	t.Helper()
	enclaveEnv(t)
	t.Setenv("WS_MCP_CONTENT_ENABLED", "true")
}

// Attachments are off unless switched on, and the startup line says which.
func TestMCPMediaOffByDefault(t *testing.T) {
	mediaEnv(t)
	t.Setenv("WS_MCP_MEDIA_TENANTS", "not even a uuid")
	t.Setenv("WS_MCP_MEDIA_OFF_KINDS", "slides")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("an unused media block was inspected: %v", err)
	}
	if cfg.MCP.MediaEnabled || cfg.MCP.MediaAllowed(uuid.MustParse(testWorkspace)) {
		t.Fatal("media allowed with the switch off")
	}
	if !cfg.MCP.ContentAllowed(uuid.MustParse(testWorkspace)) {
		t.Fatal("the media switch turned content off")
	}
	if !strings.Contains(cfg.MCP.String(), " content=on workspace_default=off deny_tenants=0 media=off send=") {
		t.Fatalf("String = %q", cfg.MCP.String())
	}
}

func TestMCPMediaLoads(t *testing.T) {
	mediaEnv(t)
	t.Setenv("WS_MCP_MEDIA_ENABLED", "true")
	t.Setenv("WS_MCP_MEDIA_OFF_KINDS", " Zip , pdf,,zip")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	workspace := uuid.MustParse(testWorkspace)
	if !cfg.MCP.MediaEnabled {
		t.Fatal("media off")
	}
	// Lower-cased, once each and sorted: the order the reader is told.
	if got := strings.Join(cfg.MCP.MediaOffKinds, ","); got != "pdf,zip" {
		t.Fatalf("off kinds = %q", got)
	}
	if !cfg.MCP.MediaAllowed(workspace) || cfg.MCP.MediaAllowed(uuid.New()) {
		t.Fatal("MediaAllowed does not follow content")
	}
	if !strings.Contains(cfg.MCP.String(), " media=on media_off=pdf,zip send=") {
		t.Fatalf("String = %q", cfg.MCP.String())
	}
	// A denied workspace opens no attachment either.
	t.Setenv("WS_MCP_DENY_TENANTS", testWorkspace)
	if cfg, err := Load(); err != nil || cfg.MCP.MediaAllowed(workspace) {
		t.Fatalf("a denied workspace opens attachments: %v", err)
	}
	// Media rides on content: content off, or the connector off, turns it
	// off whatever its own switch says.
	off := cfg.MCP
	off.ContentEnabled = false
	if off.MediaAllowed(workspace) {
		t.Fatal("media allowed with content off")
	}
	off = cfg.MCP
	off.Enabled = false
	if off.MediaAllowed(workspace) {
		t.Fatal("media allowed with the connector off")
	}
	// No kind off is the default.
	t.Setenv("WS_MCP_DENY_TENANTS", "")
	t.Setenv("WS_MCP_MEDIA_OFF_KINDS", "")
	if cfg, err = Load(); err != nil || len(cfg.MCP.MediaOffKinds) != 0 || strings.Contains(cfg.MCP.String(), "media_off") {
		t.Fatalf("no kinds off: %v %v %q", err, cfg.MCP.MediaOffKinds, cfg.MCP.String())
	}
}

func TestMCPMediaInvalid(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"a retired list":       {"WS_MCP_MEDIA_TENANTS": testWorkspace},
		"unknown kind":         {"WS_MCP_MEDIA_OFF_KINDS": "pdf,slides"},
		"every kind as *":      {"WS_MCP_MEDIA_OFF_KINDS": "*"},
		"switch not a boolean": {"WS_MCP_MEDIA_ENABLED": "maybe"},
	} {
		t.Run(name, func(t *testing.T) {
			mediaEnv(t)
			t.Setenv("WS_MCP_MEDIA_ENABLED", "true")
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted %v", env)
			}
		})
	}
	// Content off is the kill switch, and flipping it must not need the
	// media block tidied first: its kinds are not inspected then.
	mediaEnv(t)
	t.Setenv("WS_MCP_CONTENT_ENABLED", "false")
	t.Setenv("WS_MCP_MEDIA_ENABLED", "true")
	t.Setenv("WS_MCP_MEDIA_TENANTS", testWorkspace)
	t.Setenv("WS_MCP_MEDIA_OFF_KINDS", "slides")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("with content off the media block was inspected: %v", err)
	}
	if cfg.MCP.MediaAllowed(uuid.MustParse(testWorkspace)) {
		t.Fatal("media allowed with content off")
	}
}

// Sending is off unless switched on, nothing of it is inspected while it is
// off, and the startup line says so with the limits in force.
func TestMCPSendOffByDefault(t *testing.T) {
	mediaEnv(t)
	for k, v := range map[string]string{
		"WS_MCP_SEND_TENANTS": "not even a uuid", "WS_MCP_SEND_SELF_ENABLED": "true", "WS_MCP_SEND_DIRECT_ENABLED": "true",
		"WS_MCP_SEND_DRAFTS_PER_HOUR": "31", "WS_MCP_SEND_MIN_INTERVAL": "1s", "WS_MCP_SEND_TENANT_PER_DAY": "0",
	} {
		t.Setenv(k, v)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("an unused send block was inspected: %v", err)
	}
	workspace := uuid.MustParse(testWorkspace)
	if cfg.MCP.SendEnabled || cfg.MCP.SendAllowed(workspace) || cfg.MCP.SendSelfAllowed(workspace) || cfg.MCP.SendDirectAllowed(workspace) {
		t.Fatal("sending allowed with the switch off")
	}
	if !cfg.MCP.ContentAllowed(workspace) {
		t.Fatal("the send switch turned content off")
	}
	// The limits that did not parse are the defaults, the image's own.
	if cfg.MCP.SendLimits != (MCPSendLimits{DraftsPerHour: 30, DraftsPending: 20, PerDay: 20, PerChatPerDay: 5, MinInterval: 30 * time.Second, TenantPerDay: 100}) {
		t.Fatalf("limits = %+v", cfg.MCP.SendLimits)
	}
	want := " send=off send_self=on send_direct=on" +
		" send_limits=drafts_per_hour:30,drafts_pending:20,per_day:20,per_chat_per_day:5,min_interval:30s,tenant_per_day:100"
	if !strings.Contains(cfg.MCP.String(), want+" ai=") {
		t.Fatalf("String = %q", cfg.MCP.String())
	}
}

// sendEnv is mediaEnv with sending on.
func sendEnv(t *testing.T) {
	t.Helper()
	mediaEnv(t)
	t.Setenv("WS_MCP_SEND_ENABLED", "true")
}

func TestMCPSendLoads(t *testing.T) {
	sendEnv(t)
	for k, v := range map[string]string{
		"WS_MCP_SEND_DRAFTS_PER_HOUR": "10", "WS_MCP_SEND_DRAFTS_PENDING": " 5 ", "WS_MCP_SEND_PER_DAY": "1",
		"WS_MCP_SEND_PER_CHAT_PER_DAY": "2", "WS_MCP_SEND_MIN_INTERVAL": "5m", "WS_MCP_SEND_TENANT_PER_DAY": "1000",
	} {
		t.Setenv(k, v)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	workspace := uuid.MustParse(testWorkspace)
	if !cfg.MCP.SendEnabled || !cfg.MCP.SendAllowed(workspace) || cfg.MCP.SendAllowed(uuid.New()) {
		t.Fatal("SendAllowed does not follow content")
	}
	// The own-chat switch is off unless set; direct send is never on yet.
	if cfg.MCP.SendSelfAllowed(workspace) || cfg.MCP.SendDirectAllowed(workspace) {
		t.Fatal("own chat or direct send allowed without their switches")
	}
	if cfg.MCP.SendLimits != (MCPSendLimits{DraftsPerHour: 10, DraftsPending: 5, PerDay: 1, PerChatPerDay: 2, MinInterval: 5 * time.Minute, TenantPerDay: 1000}) {
		t.Fatalf("limits = %+v", cfg.MCP.SendLimits)
	}
	if !strings.Contains(cfg.MCP.String(), " send=on send_self=off send_direct=off send_limits=drafts_per_hour:10,drafts_pending:5,per_day:1,per_chat_per_day:2,min_interval:5m0s,tenant_per_day:1000") {
		t.Fatalf("String = %q", cfg.MCP.String())
	}
	t.Setenv("WS_MCP_SEND_SELF_ENABLED", "true")
	if cfg, err = Load(); err != nil || !cfg.MCP.SendSelfAllowed(workspace) || cfg.MCP.SendSelfAllowed(uuid.New()) {
		t.Fatalf("own chat: %v", err)
	}
	// A denied workspace neither reads nor sends.
	t.Setenv("WS_MCP_DENY_TENANTS", testWorkspace)
	if cfg, err := Load(); err != nil || cfg.MCP.SendAllowed(workspace) || cfg.MCP.SendSelfAllowed(workspace) {
		t.Fatalf("a denied workspace sends: %v", err)
	}
	// Sending rides on content and on the connector.
	off := cfg.MCP
	off.ContentEnabled = false
	if off.SendAllowed(workspace) || off.SendSelfAllowed(workspace) {
		t.Fatal("sending allowed with content off")
	}
	off = cfg.MCP
	off.Enabled = false
	if off.SendAllowed(workspace) {
		t.Fatal("sending allowed with the connector off")
	}
	// Direct send follows its switch where a configuration has it at all.
	off = cfg.MCP
	off.SendDirectEnabled = true
	if !off.SendDirectAllowed(workspace) || off.SendDirectAllowed(uuid.New()) {
		t.Fatal("SendDirectAllowed does not follow content")
	}
}

func TestMCPSendInvalid(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"a retired list":           {"WS_MCP_SEND_TENANTS": testWorkspace},
		"content off":              {"WS_MCP_CONTENT_ENABLED": "false"},
		"direct before S3":         {"WS_MCP_SEND_DIRECT_ENABLED": "true"},
		"switch not a boolean":     {"WS_MCP_SEND_ENABLED": "maybe"},
		"self not a boolean":       {"WS_MCP_SEND_SELF_ENABLED": "sometimes"},
		"drafts per hour over":     {"WS_MCP_SEND_DRAFTS_PER_HOUR": "31"},
		"drafts per hour zero":     {"WS_MCP_SEND_DRAFTS_PER_HOUR": "0"},
		"drafts pending over":      {"WS_MCP_SEND_DRAFTS_PENDING": "21"},
		"per day over":             {"WS_MCP_SEND_PER_DAY": "21"},
		"per day not a number":     {"WS_MCP_SEND_PER_DAY": "twenty"},
		"per chat over":            {"WS_MCP_SEND_PER_CHAT_PER_DAY": "6"},
		"interval under the image": {"WS_MCP_SEND_MIN_INTERVAL": "29s"},
		"interval over an hour":    {"WS_MCP_SEND_MIN_INTERVAL": "61m"},
		"interval not a duration":  {"WS_MCP_SEND_MIN_INTERVAL": "30"},
		"tenant per day over":      {"WS_MCP_SEND_TENANT_PER_DAY": "1001"},
		"tenant per day negative":  {"WS_MCP_SEND_TENANT_PER_DAY": "-1"},
		"drafts per hour fraction": {"WS_MCP_SEND_DRAFTS_PER_HOUR": "2.5"},
	} {
		t.Run(name, func(t *testing.T) {
			sendEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted %v", env)
			}
		})
	}
	// The error names the variable, so the operator knows which to fix.
	sendEnv(t)
	t.Setenv("WS_MCP_SEND_PER_DAY", "50")
	if err := mustFail(t); !strings.Contains(err.Error(), "WS_MCP_SEND_PER_DAY") {
		t.Fatalf("error = %v", err)
	}
	// Sending off is the kill switch, and flipping it must not need the rest
	// of the block tidied first; a disabled connector looks at none of it.
	sendEnv(t)
	t.Setenv("WS_MCP_SEND_ENABLED", "false")
	t.Setenv("WS_MCP_SEND_TENANTS", testWorkspace)
	t.Setenv("WS_MCP_SEND_DIRECT_ENABLED", "true")
	t.Setenv("WS_MCP_SEND_PER_DAY", "500")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("with sending off the send block was inspected: %v", err)
	}
	if cfg.MCP.SendAllowed(uuid.MustParse(testWorkspace)) {
		t.Fatal("sending allowed with the switch off")
	}
	t.Setenv("WS_MCP_ENABLED", "false")
	t.Setenv("WS_MCP_SEND_ENABLED", "true")
	t.Setenv("WS_MCP_CONTENT_ENABLED", "false")
	if _, err := Load(); err != nil {
		t.Fatalf("a disabled connector's send switch was inspected: %v", err)
	}
}

// The content switch, the workspaces' default and the deny list are
// documented where an operator looks: the readers' configuration section of
// docs/mcp.md and .env.example, each with its rule. So are the attachments'
// and sending's, and the retired lists are named in the section, with what
// replaced them, for whoever still has them in an environment.
func TestContentVariablesDocumented(t *testing.T) {
	section, env := readersDocs(t)
	for _, name := range []string{"WS_MCP_CONTENT_ENABLED", "WS_MCP_WORKSPACE_DEFAULT", "WS_MCP_DENY_TENANTS", "WS_MCP_MEDIA_ENABLED", "WS_MCP_MEDIA_OFF_KINDS",
		"WS_MCP_SEND_ENABLED", "WS_MCP_SEND_SELF_ENABLED", "WS_MCP_SEND_DIRECT_ENABLED",
		"WS_MCP_SEND_DRAFTS_PER_HOUR", "WS_MCP_SEND_DRAFTS_PENDING", "WS_MCP_SEND_PER_DAY", "WS_MCP_SEND_PER_CHAT_PER_DAY",
		"WS_MCP_SEND_MIN_INTERVAL", "WS_MCP_SEND_TENANT_PER_DAY"} {
		if !strings.Contains(section, "| `"+name+"` |") {
			t.Errorf("docs/mcp.md's readers' configuration does not list %s", name)
		}
	}
	// .env.example is the operator's to edit (docs/mcp-enclave.md §19.30
	// lists what it should show now); the switches it has always shown stay.
	for _, name := range []string{"WS_MCP_CONTENT_ENABLED", "WS_MCP_MEDIA_ENABLED", "WS_MCP_MEDIA_OFF_KINDS",
		"WS_MCP_SEND_ENABLED", "WS_MCP_SEND_SELF_ENABLED", "WS_MCP_SEND_DIRECT_ENABLED"} {
		if !strings.Contains(env, "\n# "+name+"=") {
			t.Errorf(".env.example does not show %s", name)
		}
	}
	for _, name := range retiredLists {
		if !strings.Contains(section, "`"+name+"`") {
			t.Errorf("docs/mcp.md's readers' configuration does not say %s is retired", name)
		}
	}
	if !strings.Contains(env, "# WS_MCP_CONTENT_ENABLED=false\n") {
		t.Error(".env.example does not show the content switch's default")
	}
	if !strings.Contains(env, "# WS_MCP_MEDIA_ENABLED=false\n") {
		t.Error(".env.example does not show the media switch's default")
	}
	for _, off := range []string{"# WS_MCP_SEND_ENABLED=false\n", "# WS_MCP_SEND_SELF_ENABLED=false\n", "# WS_MCP_SEND_DIRECT_ENABLED=false\n"} {
		if !strings.Contains(env, off) {
			t.Errorf(".env.example does not show %q", strings.TrimSpace(off))
		}
	}
}

// readersDocs returns the readers' configuration section of docs/mcp.md and
// the whole of .env.example.
func readersDocs(t *testing.T) (section, env string) {
	t.Helper()
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	doc := read("../../docs/mcp.md")
	start := strings.Index(doc, "### Server configuration for the readers")
	end := strings.Index(doc, "## Configuration and identity")
	if start < 0 || end < start {
		t.Fatal("docs/mcp.md has no readers' configuration section")
	}
	return doc[start:end], read("../../.env.example")
}
