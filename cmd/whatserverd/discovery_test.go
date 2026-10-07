package main

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"

	"whatserver2/internal/authapi"
)

func TestDiscoveryDescribesProtocolWithoutWorkspaceData(t *testing.T) {
	w := httptest.NewRecorder()
	discovery(w, httptest.NewRequest("GET", "/v1/discovery", nil))
	var doc struct {
		Product      string            `json:"product"`
		Version      int               `json:"api_version"`
		Endpoints    map[string]string `json:"endpoints"`
		Capabilities []string          `json:"capabilities"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Product != "wappie" || doc.Version != 1 || doc.Endpoints["websocket"] != "/v1/ws" {
		t.Fatalf("incompatible discovery: %s", w.Body.String())
	}
	if !slices.Contains(doc.Capabilities, "archive.rest.v1") || doc.Endpoints["archive_rest"] != "/v1" || doc.Endpoints["openapi"] != "/v1/openapi.json" {
		t.Fatalf("REST discovery missing: %s", w.Body.String())
	}
	if !slices.Contains(doc.Capabilities, "apikeys.device-scope.v1") {
		t.Fatal("clients cannot distinguish atomic device-scoped issuance from legacy servers that ignore device_ids")
	}
}

func TestDiscoveryAdvertisesContactPagesAndDeviceScans(t *testing.T) {
	w := httptest.NewRecorder()
	discovery(w, httptest.NewRequest("GET", "/v1/discovery", nil))
	var doc struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []string{"archive.contacts.v1", "archive.scan.v1"} {
		if !slices.Contains(doc.Capabilities, capability) {
			t.Fatalf("missing capability %s", capability)
		}
	}
}

// The hosted connector is advertised exactly when it is mounted: a console
// offering a remote connection against a server that cannot record one
// would fail at the consent, which is the wrong moment.
func TestDiscoveryAdvertisesRemoteMCP(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		server := ""
		if enabled {
			server = "https://api.example.test/mcp"
		}
		w := httptest.NewRecorder()
		discoveryFor(mcpEndpoints{Server: server})(w, httptest.NewRequest("GET", "/v1/discovery", nil))
		var doc struct {
			Capabilities []string          `json:"capabilities"`
			Endpoints    map[string]string `json:"endpoints"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		_, hasEndpoint := doc.Endpoints["mcp"]
		if slices.Contains(doc.Capabilities, "mcp.remote.v1") != enabled || hasEndpoint != enabled {
			t.Fatalf("enabled=%v: %s", enabled, w.Body.String())
		}
		if enabled && doc.Endpoints["mcp"] != "/v1/mcp" {
			t.Fatalf("mcp endpoint = %q", doc.Endpoints["mcp"])
		}
		// The console cannot derive the connector's address from its own
		// origin, so the server names it.
		if got, has := doc.Endpoints["mcp_server"]; has != enabled || (enabled && got != "https://api.example.test/mcp") {
			t.Fatalf("enabled=%v: mcp_server = %q", enabled, got)
		}
		// Everything a client relied on before is still there.
		if !slices.Contains(doc.Capabilities, "archive.rest.v1") || doc.Endpoints["websocket"] != "/v1/ws" {
			t.Fatalf("enabled=%v lost an existing capability: %s", enabled, w.Body.String())
		}
	}
}

// The enclave reader is advertised beside the hosted one, under its own name,
// and only when it is configured: the console picks the address to hand an
// assistant, and an attested address must never appear by accident.
func TestDiscoveryAdvertisesAttestedMCP(t *testing.T) {
	for name, tc := range map[string]struct {
		endpoints         mcpEndpoints
		server, attested  string
		hasServer, hasAtt bool
	}{
		"both":          {mcpEndpoints{Server: "https://api.example.test/mcp", Attested: "https://mcp.example.test/mcp"}, "https://api.example.test/mcp", "https://mcp.example.test/mcp", true, true},
		"enclave alone": {mcpEndpoints{Attested: "https://mcp.example.test/mcp"}, "", "https://mcp.example.test/mcp", false, true},
		"hosted alone":  {mcpEndpoints{Server: "https://api.example.test/mcp"}, "https://api.example.test/mcp", "", true, false},
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			discoveryFor(tc.endpoints)(w, httptest.NewRequest("GET", "/v1/discovery", nil))
			var doc struct {
				Capabilities []string          `json:"capabilities"`
				Endpoints    map[string]string `json:"endpoints"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(doc.Capabilities, "mcp.remote.v1") || doc.Endpoints["mcp"] != "/v1/mcp" {
				t.Fatalf("the consent API is not advertised: %s", w.Body.String())
			}
			if got, has := doc.Endpoints["mcp_server"]; has != tc.hasServer || got != tc.server {
				t.Fatalf("mcp_server = %q %v", got, has)
			}
			if got, has := doc.Endpoints["mcp_server_attested"]; has != tc.hasAtt || got != tc.attested {
				t.Fatalf("mcp_server_attested = %q %v", got, has)
			}
		})
	}
}

// Content is advertised only with the enclave configured and the switch on;
// which workspaces may use it is asked per workspace.
func TestDiscoveryAdvertisesContent(t *testing.T) {
	for _, tc := range []struct {
		endpoints mcpEndpoints
		want      bool
	}{
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Content: true}, true},
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp"}, false},
		{mcpEndpoints{Server: "https://api.example.test/mcp", Content: true}, false},
	} {
		w := httptest.NewRecorder()
		discoveryFor(tc.endpoints)(w, httptest.NewRequest("GET", "/v1/discovery", nil))
		var doc struct {
			Capabilities []string `json:"capabilities"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(doc.Capabilities, "mcp.remote.content.v1") != tc.want {
			t.Fatalf("%+v: %s", tc.endpoints, w.Body.String())
		}
	}
}

// Attachments are advertised only where content is, and with their own
// switch on; which workspaces may use them is asked per workspace.
func TestDiscoveryAdvertisesMedia(t *testing.T) {
	for _, tc := range []struct {
		endpoints mcpEndpoints
		want      bool
	}{
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Content: true, Media: true}, true},
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Content: true}, false},
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Media: true}, false},
		{mcpEndpoints{Server: "https://api.example.test/mcp", Content: true, Media: true}, false},
	} {
		w := httptest.NewRecorder()
		discoveryFor(tc.endpoints)(w, httptest.NewRequest("GET", "/v1/discovery", nil))
		var doc struct {
			Capabilities []string `json:"capabilities"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(doc.Capabilities, "mcp.remote.media.v1") != tc.want {
			t.Fatalf("%+v: %s", tc.endpoints, w.Body.String())
		}
	}
}

// Sending is advertised only where content is, and with its own switch on;
// which workspaces may send is asked per workspace.
func TestDiscoveryAdvertisesSend(t *testing.T) {
	for _, tc := range []struct {
		endpoints mcpEndpoints
		want      bool
	}{
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Content: true, Send: true}, true},
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Content: true, Media: true}, false},
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Send: true}, false},
		{mcpEndpoints{Server: "https://api.example.test/mcp", Content: true, Send: true}, false},
	} {
		w := httptest.NewRecorder()
		discoveryFor(tc.endpoints)(w, httptest.NewRequest("GET", "/v1/discovery", nil))
		var doc struct {
			Capabilities []string `json:"capabilities"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(doc.Capabilities, "mcp.remote.send.v1") != tc.want {
			t.Fatalf("%+v: %s", tc.endpoints, w.Body.String())
		}
	}
}

// AI integrations are advertised exactly where content is, with the AI
// switch on; which workspaces may is asked per workspace (GET
// /v1/mcp/content's ai).
func TestDiscoveryAdvertisesAI(t *testing.T) {
	for _, tc := range []struct {
		endpoints mcpEndpoints
		want      bool
	}{
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Content: true, Media: true, AI: true}, true},
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Content: true, AI: true}, true},
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", Content: true, Media: true}, false},
		{mcpEndpoints{Attested: "https://mcp.example.test/mcp", AI: true}, false},
		{mcpEndpoints{Server: "https://api.example.test/mcp", Content: true, AI: true}, false},
	} {
		w := httptest.NewRecorder()
		discoveryFor(tc.endpoints)(w, httptest.NewRequest("GET", "/v1/discovery", nil))
		var doc struct {
			Capabilities []string `json:"capabilities"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(doc.Capabilities, "mcp.remote.ai.v1") != tc.want {
			t.Fatalf("%+v: %s", tc.endpoints, w.Body.String())
		}
	}
}

// Sign-in through the identity provider is advertised exactly when it is
// configured, with what the console needs to begin one; password sign-in
// stops being advertised only once WS_LOCAL_LOGIN is off.
func TestDiscoveryAdvertisesPlatformLogin(t *testing.T) {
	type doc struct {
		Capabilities  []string                   `json:"capabilities"`
		PlatformLogin *authapi.PlatformDiscovery `json:"platform_login"`
	}
	read := func(t *testing.T, p *authapi.PlatformDiscovery) doc {
		t.Helper()
		w := httptest.NewRecorder()
		discoveryWith(mcpEndpoints{}, p)(w, httptest.NewRequest("GET", "/.well-known/wappie", nil))
		var d doc
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	off := read(t, nil)
	if off.PlatformLogin != nil || slices.Contains(off.Capabilities, "auth.platform.v1") || slices.Contains(off.Capabilities, "auth.platform.stepup.v1") ||
		!slices.Contains(off.Capabilities, "auth.password") {
		t.Fatalf("unconfigured: %+v", off)
	}
	for _, local := range []string{"on", "link_only", "off"} {
		d := read(t, &authapi.PlatformDiscovery{Issuer: "https://id.thehappie.co", ClientID: "wappie-app", Product: "wappie", LocalLogin: local})
		if d.PlatformLogin == nil || d.PlatformLogin.Issuer != "https://id.thehappie.co" || d.PlatformLogin.ClientID != "wappie-app" ||
			d.PlatformLogin.Product != "wappie" || d.PlatformLogin.LocalLogin != local || !slices.Contains(d.Capabilities, "auth.platform.v1") {
			t.Fatalf("%s: %+v", local, d)
		}
		// The step-up at the provider comes with the sign-in through it.
		if !slices.Contains(d.Capabilities, "auth.platform.stepup.v1") {
			t.Fatalf("%s: no step-up at the provider: %v", local, d.Capabilities)
		}
		if slices.Contains(d.Capabilities, "auth.password") != (local != "off") {
			t.Fatalf("%s: auth.password %v", local, d.Capabilities)
		}
	}
}
