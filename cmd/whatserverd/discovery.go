package main

import (
	"encoding/json"
	"net/http"
)

// BuildVersion may be supplied with -ldflags; protocol compatibility is stable
// independently of a source checkout's release label.
var BuildVersion = "development"

func discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(struct {
		Product      string            `json:"product"`
		Version      string            `json:"version"`
		APIVersion   int               `json:"api_version"`
		Capabilities []string          `json:"capabilities"`
		Endpoints    map[string]string `json:"endpoints"`
	}{"wappie", BuildVersion, 1, []string{"archive.sealed.v1", "workspaces.v1", "auth.password", "external-client.v1"}, map[string]string{"websocket": "/v1/ws", "auth": "/v1/auth", "media": "/v1/media", "upload": "/v1/upload", "calls_media": "/v1/calls/media"}}); err != nil {
		// A failed response write means the requester disconnected.
		return
	}
}
