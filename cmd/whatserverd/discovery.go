package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"whatserver2/internal/authapi"
	"whatserver2/internal/config"
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
	// Content is set when the enclave may open message text: the switch is
	// on. Which workspaces may is asked per workspace (GET /v1/mcp/content).
	Content bool
	// Media is set when it may also open attachments: both switches are on.
	// Which workspaces may is asked the same way.
	Media bool
	// Send is set when its connections may also draft and send: content and
	// sending are on. Which workspaces may is asked the same way.
	Send bool
	// AI is set when AI integrations are on beside content: the AI switch
	// is on. Which workspaces may is asked the same way (GET
	// /v1/mcp/content's ai).
	AI bool
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
func discoveryFor(mcp mcpEndpoints) http.HandlerFunc { return discoveryWith(mcp, nil, nil) }

// platformTokensFor is how long discovery trusts what it read of the
// narrowing: contract.md's mode cache, 5 seconds (the plan's 7.4). A
// failed read is trusted as long: the last answer stands until then.
const platformTokensFor = 5 * time.Second

// platformTokensRead bounds one read of the narrowing. Discovery answers
// without signing in, so a slow database must not hold its requests.
const platformTokensRead = time.Second

// platformTokens is whether this installation takes The Happie Co's API
// tokens in place of its own keys (store.APIKeys.KeysNarrowed: the token
// mode on, or the keys retired), for discovery's tokens.platform.v1. A
// console then sends its people to the platform's API keys page; an
// installation that never says so keeps its own keys and TokenPanel.
//
// One request at a time reads it, at most once per platformTokensFor, for
// at most platformTokensRead, with no lock held over the read. The others
// answer the last read's answer at once. Only before the first read has
// ended do they wait for it, within their own context. A failed read keeps
// the last answer for platformTokensFor. A nil one is never on.
type platformTokens struct {
	read func(context.Context) (bool, error)
	log  *slog.Logger
	// now is the clock; nil is time.Now.
	now func() time.Time
	// readFor bounds a read; zero is platformTokensRead.
	readFor time.Duration

	mu sync.Mutex
	at time.Time
	on bool
	// reading is closed when the read in flight ends; nil for none.
	reading chan struct{}
}

// On reports the narrowing as read within platformTokensFor.
func (p *platformTokens) On(ctx context.Context) bool {
	if p == nil {
		return false
	}
	now := time.Now()
	if p.now != nil {
		now = p.now()
	}
	p.mu.Lock()
	if !p.at.IsZero() && now.Sub(p.at) < platformTokensFor {
		on := p.on
		p.mu.Unlock()
		return on
	}
	if wait := p.reading; wait != nil {
		on, first := p.on, p.at.IsZero()
		p.mu.Unlock()
		if !first {
			return on
		}
		select {
		case <-wait:
		case <-ctx.Done():
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.on
	}
	done := make(chan struct{})
	p.reading = done
	p.mu.Unlock()

	limit := p.readFor
	if limit <= 0 {
		limit = platformTokensRead
	}
	// Not the request's context: a client that leaves must not cut the
	// read the others wait on.
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), limit)
	on, err := p.read(readCtx)
	cancel()
	if err != nil && p.log != nil {
		p.log.Warn("discovery could not read whether the platform's tokens are on", "error", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		p.on = on
	}
	p.at, p.reading = now, nil
	close(done)
	return p.on
}

// discoveryWith is discoveryFor and, when sign-in through an identity
// provider is configured, platform_login: the issuer, the client and what
// remains of password sign-in, so the console begins a sign-in without
// hard-coding any of it. auth.password is advertised while password sign-in
// is open at all, and auth.platform.v1 while the provider is, with
// auth.platform.stepup.v1: the step-up at the provider
// (/v1/auth/platform/step-up/start and /finish). tokens.platform.v1 is
// computed per request (tokens): while it is advertised, the general
// credential here is the platform's token, and apikeys.create issues only
// an MCP setup's key.
func discoveryWith(mcp mcpEndpoints, platform *authapi.PlatformDiscovery, tokens *platformTokens) http.HandlerFunc {
	remoteMCP := mcp.Server != "" || mcp.Attested != ""
	capabilities := []string{"archive.sealed.v1", "archive.rest.v1", "archive.contacts.v1", "archive.scan.v1", "apikeys.device-scope.v1", "workspaces.v1"}
	if platform == nil || platform.LocalLogin != string(config.LocalLoginOff) {
		capabilities = append(capabilities, "auth.password")
	}
	if platform != nil {
		capabilities = append(capabilities, "auth.platform.v1", "auth.platform.stepup.v1")
	}
	capabilities = append(capabilities, "external-client.v1")
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
		if mcp.Content {
			capabilities = append(capabilities, "mcp.remote.content.v1")
			if mcp.Media {
				capabilities = append(capabilities, "mcp.remote.media.v1")
			}
			if mcp.Send {
				capabilities = append(capabilities, "mcp.remote.send.v1")
			}
			if mcp.AI {
				capabilities = append(capabilities, "mcp.remote.ai.v1")
			}
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		capabilities := capabilities
		if tokens.On(r.Context()) {
			capabilities = append(capabilities[:len(capabilities):len(capabilities)], "tokens.platform.v1")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(struct {
			Product       string                     `json:"product"`
			Version       string                     `json:"version"`
			APIVersion    int                        `json:"api_version"`
			Capabilities  []string                   `json:"capabilities"`
			Endpoints     map[string]string          `json:"endpoints"`
			PlatformLogin *authapi.PlatformDiscovery `json:"platform_login,omitempty"`
		}{"wappie", BuildVersion, 1, capabilities, endpoints, platform}); err != nil {
			// A failed response write means the requester disconnected.
			return
		}
	}
}
