package main

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"
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
