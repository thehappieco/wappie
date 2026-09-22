package main

import (
	"encoding/json"
	"net/http"
)

// BuildVersion may be supplied with -ldflags; protocol compatibility is stable
// independently of a source checkout's release label.
var BuildVersion = "development"

// discovery describes the protocol with nothing about the hosted connector.
// What the process actually mounts is decided by configuration, and routes
// use discoveryFor with it; this form serves the tests and any caller that
// has no configuration in hand.
func discovery(w http.ResponseWriter, r *http.Request) {
	discoveryFor(false)(w, r)
}

// discoveryFor describes the protocol. The hosted assistant connector is
// advertised only when it is mounted, so a console never offers a remote
// connection this installation cannot record.
func discoveryFor(remoteMCP bool) http.HandlerFunc {
	capabilities := []string{"archive.sealed.v1", "archive.rest.v1", "archive.contacts.v1", "archive.scan.v1", "apikeys.device-scope.v1", "workspaces.v1", "auth.password", "external-client.v1"}
	endpoints := map[string]string{"websocket": "/v1/ws", "archive_rest": "/v1", "openapi": "/v1/openapi.json", "auth": "/v1/auth", "media": "/v1/media", "upload": "/v1/upload", "calls_media": "/v1/calls/media"}
	if remoteMCP {
		capabilities = append(capabilities, "mcp.remote.v1")
		endpoints["mcp"] = "/v1/mcp"
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(struct {
			Product      string            `json:"product"`
			Version      string            `json:"version"`
			APIVersion   int               `json:"api_version"`
			Capabilities []string          `json:"capabilities"`
			Endpoints    map[string]string `json:"endpoints"`
		}{"wappie", BuildVersion, 1, capabilities, endpoints}); err != nil {
			// A failed response write means the requester disconnected.
			return
		}
	}
}
