package config

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// aiMediaEnv is mediaEnv with attachments on, which is what AI rides on.
func aiMediaEnv(t *testing.T) {
	t.Helper()
	mediaEnv(t)
	t.Setenv("WS_MCP_MEDIA_ENABLED", "true")
}

// aiEnv is aiMediaEnv with AI on.
func aiEnv(t *testing.T) {
	t.Helper()
	aiMediaEnv(t)
	t.Setenv("WS_AI_ENABLED", "true")
}

// AI is off unless switched on, nothing of its block is inspected while it
// is off, and the startup line says so.
func TestAIOffByDefault(t *testing.T) {
	aiMediaEnv(t)
	t.Setenv("WS_AI_TENANTS", "not even a uuid")
	t.Setenv("WS_AI_OFF_PROVIDERS", "mistral")
	t.Setenv("WS_AI_OFF_FEATURES", "slides")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("an unused AI block was inspected: %v", err)
	}
	workspace := uuid.MustParse(testWorkspace)
	if cfg.MCP.AIEnabled || cfg.MCP.AIAllowed(workspace) {
		t.Fatal("AI allowed with the switch off")
	}
	if !cfg.MCP.MediaAllowed(workspace) {
		t.Fatal("the AI switch turned attachments off")
	}
	if !strings.HasSuffix(cfg.MCP.String(), " ai=off") {
		t.Fatalf("String = %q", cfg.MCP.String())
	}
	t.Setenv("WS_MCP_ENABLED", "false")
	if cfg, err := Load(); err != nil || cfg.MCP.AIEnabled || strings.Contains(cfg.MCP.String(), "ai=") {
		t.Fatalf("a disabled connector = %v %q", err, cfg.MCP.String())
	}
}

func TestAILoads(t *testing.T) {
	aiEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	workspace := uuid.MustParse(testWorkspace)
	if !cfg.MCP.AIEnabled || !cfg.MCP.AIAllowed(workspace) || cfg.MCP.AIAllowed(uuid.New()) {
		t.Fatal("AIAllowed does not follow attachments")
	}
	if len(cfg.MCP.AIOffProviders) != 0 || len(cfg.MCP.AIOffFeatures) != 0 || !strings.HasSuffix(cfg.MCP.String(), " ai=on") {
		t.Fatalf("nothing off = %v %v %q", cfg.MCP.AIOffProviders, cfg.MCP.AIOffFeatures, cfg.MCP.String())
	}
	// The off lists: any case and order, kept lower-cased, once each, sorted.
	t.Setenv("WS_AI_OFF_PROVIDERS", " OpenAI ,anthropic,,openai")
	t.Setenv("WS_AI_OFF_FEATURES", "Video, audio ,VIDEO")
	if cfg, err = Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := strings.Join(cfg.MCP.AIOffProviders, ","); got != "anthropic,openai" {
		t.Fatalf("off providers = %q", got)
	}
	if got := strings.Join(cfg.MCP.AIOffFeatures, ","); got != "audio,video" {
		t.Fatalf("off features = %q", got)
	}
	if !strings.HasSuffix(cfg.MCP.String(), " ai=on ai_off_providers=anthropic,openai ai_off_features=audio,video") {
		t.Fatalf("String = %q", cfg.MCP.String())
	}
	// One list alone still prints both.
	t.Setenv("WS_AI_OFF_PROVIDERS", "")
	if cfg, err = Load(); err != nil || !strings.HasSuffix(cfg.MCP.String(), " ai_off_providers= ai_off_features=audio,video") {
		t.Fatalf("String = %v %q", err, cfg.MCP.String())
	}
	// AI rides on attachments, content, the deny list and the connector: any
	// of them off turns it off whatever its own switch says.
	for name, mutate := range map[string]func(*MCP){
		"media off":     func(m *MCP) { m.MediaEnabled = false },
		"content off":   func(m *MCP) { m.ContentEnabled = false },
		"connector off": func(m *MCP) { m.Enabled = false },
		"switch off":    func(m *MCP) { m.AIEnabled = false },
		"denied":        func(m *MCP) { m.DenyTenants = []uuid.UUID{workspace} },
	} {
		off := cfg.MCP
		mutate(&off)
		if off.AIAllowed(workspace) {
			t.Fatalf("%s: AI allowed", name)
		}
	}
}

func TestAIInvalid(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"a retired list":       {"WS_AI_TENANTS": testWorkspace},
		"media off":            {"WS_MCP_MEDIA_ENABLED": "false"},
		"unknown provider":     {"WS_AI_OFF_PROVIDERS": "openai,mistral"},
		"every provider as *":  {"WS_AI_OFF_PROVIDERS": "*"},
		"unknown function":     {"WS_AI_OFF_FEATURES": "audio,transcripts"},
		"a kind, not a func":   {"WS_AI_OFF_FEATURES": "pdf"},
		"switch not a boolean": {"WS_AI_ENABLED": "maybe"},
	} {
		t.Run(name, func(t *testing.T) {
			aiEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted %v", env)
			}
		})
	}
	// The error names the variable, so the operator knows which to fix.
	aiEnv(t)
	t.Setenv("WS_AI_OFF_FEATURES", "subtitles")
	if err := mustFail(t); !strings.Contains(err.Error(), "WS_AI_OFF_FEATURES") || !strings.Contains(err.Error(), "subtitles") {
		t.Fatalf("error = %v", err)
	}
	aiEnv(t)
	t.Setenv("WS_MCP_MEDIA_ENABLED", "false")
	if err := mustFail(t); !strings.Contains(err.Error(), "WS_AI_ENABLED needs WS_MCP_MEDIA_ENABLED") {
		t.Fatalf("error = %v", err)
	}
	// AI off is the kill switch, and flipping it must not need the rest of
	// the block tidied first.
	aiEnv(t)
	t.Setenv("WS_AI_ENABLED", "false")
	t.Setenv("WS_AI_TENANTS", "*")
	t.Setenv("WS_AI_OFF_PROVIDERS", "mistral")
	if cfg, err := Load(); err != nil || cfg.MCP.AIAllowed(uuid.MustParse(testWorkspace)) {
		t.Fatalf("with AI off its block was inspected: %v", err)
	}
	// Nothing is inspected while content is off: content off in a hurry
	// needs neither the media nor the AI block tidied.
	aiEnv(t)
	t.Setenv("WS_MCP_CONTENT_ENABLED", "false")
	t.Setenv("WS_MCP_MEDIA_ENABLED", "false")
	t.Setenv("WS_AI_TENANTS", "acme")
	t.Setenv("WS_AI_OFF_FEATURES", "slides")
	if cfg, err := Load(); err != nil || cfg.MCP.AIAllowed(uuid.MustParse(testWorkspace)) {
		t.Fatalf("with content off the AI block was inspected: %v", err)
	}
	// A disabled connector looks at none of it.
	aiEnv(t)
	t.Setenv("WS_MCP_ENABLED", "false")
	t.Setenv("WS_MCP_MEDIA_ENABLED", "false")
	t.Setenv("WS_AI_TENANTS", "*")
	if _, err := Load(); err != nil {
		t.Fatalf("a disabled connector's AI switch was inspected: %v", err)
	}
}

// The AI variables are documented where an operator looks, like the others.
func TestAIVariablesDocumented(t *testing.T) {
	section, env := readersDocs(t)
	for _, name := range []string{"WS_AI_ENABLED", "WS_AI_OFF_PROVIDERS", "WS_AI_OFF_FEATURES"} {
		if !strings.Contains(section, "| `"+name+"` |") {
			t.Errorf("docs/mcp.md's readers' configuration does not list %s", name)
		}
		if !strings.Contains(env, "\n# "+name+"=") {
			t.Errorf(".env.example does not show %s", name)
		}
	}
	if !strings.Contains(env, "# WS_AI_ENABLED=false\n") {
		t.Error(".env.example does not show the AI switch's default")
	}
}
