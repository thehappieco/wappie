package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryDescribesProtocolWithoutWorkspaceData(t *testing.T) {
	w := httptest.NewRecorder()
	discovery(w, httptest.NewRequest("GET", "/v1/discovery", nil))
	var doc struct {
		Product   string            `json:"product"`
		Version   int               `json:"api_version"`
		Endpoints map[string]string `json:"endpoints"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Product != "wappie" || doc.Version != 1 || doc.Endpoints["websocket"] != "/v1/ws" {
		t.Fatalf("incompatible discovery: %s", w.Body.String())
	}
}
