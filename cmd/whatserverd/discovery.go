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
	discoveryFor(mcpEndpoints{})(w, r)
}

// mcpEndpoints are the absolute addresses of the connector's readers that an
// assistant may be given, "" for a reader that is not configured.
type mcpEndpoints struct {
	// Server is the hosted reader, <public origin>/mcp.
	Server string
	// Attested is the reader in the Nitro Enclave, <its public origin>/mcp.
	Attested string
}

// discoveryFor describes the protocol. The hosted assistant connector is
// advertised only when it is mounted, so a console never offers a remote
// connection this installation cannot record.
//
// Each reader's address is advertised because the console runs on another
// origin than the connector (app. against api. or mcp.) and cannot work out
// the address an assistant must be given: endpoints.mcp_server for the hosted
// reader, endpoints.mcp_server_attested for the enclave. "mcp" stays the path
// of the consent API on this server.
func discoveryFor(mcp mcpEndpoints) http.HandlerFunc {
	remoteMCP := mcp.Server != "" || mcp.Attested != ""
	capabilities := []string{"archive.sealed.v1", "archive.rest.v1", "archive.contacts.v1", "archive.scan.v1", "apikeys.device-scope.v1", "workspaces.v1", "auth.password", "external-client.v1"}
	endpoints := map[string]string{"websocket": "/v1/ws", "archive_rest": "/v1", "openapi": "/v1/openapi.json", "auth": "/v1/auth", "media": "/v1/media", "upload": "/v1/upload", "calls_media": "/v1/calls/media"}
	if remoteMCP {
		capabilities = append(capabilities, "mcp.remote.v1")
		endpoints["mcp"] = "/v1/mcp"
	}
	if mcp.Server != "" {
		endpoints["mcp_server"] = mcp.Server
	}
	if mcp.Attested != "" {
		endpoints["mcp_server_attested"] = mcp.Attested
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
