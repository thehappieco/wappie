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
		w := httptest.NewRecorder()
		discoveryFor(enabled)(w, httptest.NewRequest("GET", "/v1/discovery", nil))
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
		// Everything a client relied on before is still there.
		if !slices.Contains(doc.Capabilities, "archive.rest.v1") || doc.Endpoints["websocket"] != "/v1/ws" {
			t.Fatalf("enabled=%v lost an existing capability: %s", enabled, w.Body.String())
		}
	}
}
