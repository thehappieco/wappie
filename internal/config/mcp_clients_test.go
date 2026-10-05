package config

import (
	"strings"
	"testing"
)

// The any-client block (docs/mcp-enclave.md §19.21): allowlist mode, no
// blocked client, the hosts of the pinned DCR redirects (Claude's two, not
// ChatGPT's since §19.34) and no notice origin by default, each printed on
// the startup line.
func TestMCPClientsDefaults(t *testing.T) {
	mcpEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := cfg.MCP
	if m.CIMDMode != CIMDModeAllowlist || m.UnknownAllowed() || len(m.BlockedClients) != 0 || m.NoticeOrigin != "" || m.NoticeLinkOrigin(true) != "" {
		t.Fatalf("defaults = %q %v %v %q", m.CIMDMode, m.UnknownAllowed(), m.BlockedClients, m.NoticeOrigin)
	}
	if got := strings.Join(m.DCRHosts, ","); got != "claude.ai,claude.com" {
		t.Fatalf("dcr hosts = %q", got)
	}
	if !strings.Contains(m.String(), " cimd_mode=allowlist blocked_clients=none dcr_hosts=claude.ai,claude.com notice_origin=unset") {
		t.Fatalf("String = %q", m.String())
	}
}

func TestMCPClientsLoad(t *testing.T) {
	mcpEnv(t)
	t.Setenv("WS_MCP_CIMD_MODE", " Any ")
	t.Setenv("WS_MCP_BLOCKED_CLIENTS", " claude_dcr,claude_code,, claude_dcr")
	t.Setenv("WS_MCP_DCR_HOSTS", " Claude.AI ,claude.ai")
	t.Setenv("WS_MCP_NOTICE_ORIGIN", "https://api.example.com")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := cfg.MCP
	if !m.UnknownAllowed() || strings.Join(m.BlockedClients, ",") != "claude_code,claude_dcr" || strings.Join(m.DCRHosts, ",") != "claude.ai" {
		t.Fatalf("loaded = %q %v %v", m.CIMDMode, m.BlockedClients, m.DCRHosts)
	}
	if got := m.NoticeLinkOrigin(true); got != "https://api.example.com" {
		t.Fatalf("notice origin = %q", got)
	}
	if !strings.Contains(m.String(), " cimd_mode=any blocked_clients=claude_code,claude_dcr dcr_hosts=claude.ai notice_origin=https://api.example.com") {
		t.Fatalf("String = %q", m.String())
	}
}

func TestMCPClientsRefused(t *testing.T) {
	for name, env := range map[string][2]string{
		"a mode that is not one":      {"WS_MCP_CIMD_MODE", "open"},
		"a blocked id of upper case":  {"WS_MCP_BLOCKED_CLIENTS", "Claude"},
		"a blocked id too long":       {"WS_MCP_BLOCKED_CLIENTS", "a" + strings.Repeat("b", 32)},
		"a DCR host that is a suffix": {"WS_MCP_DCR_HOSTS", "github.io"},
		"a DCR host of Wappie's":      {"WS_MCP_DCR_HOSTS", "api.wappie.thehappie.co"},
		"a DCR address":               {"WS_MCP_DCR_HOSTS", "127.0.0.1"},
		"no DCR host":                 {"WS_MCP_DCR_HOSTS", " , "},
		"a notice origin over http":   {"WS_MCP_NOTICE_ORIGIN", "http://api.example.com"},
		"a notice origin with a path": {"WS_MCP_NOTICE_ORIGIN", "https://api.example.com/v1"},
	} {
		t.Run(name, func(t *testing.T) {
			mcpEnv(t)
			t.Setenv(env[0], env[1])
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), env[0]) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// A disabled connector inspects none of it.
	minimalEnv(t)
	t.Setenv("WS_MCP_CIMD_MODE", "open")
	t.Setenv("WS_MCP_DCR_HOSTS", "github.io")
	if _, err := Load(); err != nil {
		t.Fatalf("a disabled connector's block was inspected: %v", err)
	}
}
