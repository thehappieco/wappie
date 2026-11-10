package main

import (
	"context"
	"path/filepath"
	"testing"

	"whatserver2/internal/authapi"
	"whatserver2/internal/migrate"
	"whatserver2/internal/numberacts"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/wsapi"
)

// serve's readers for a permission change's ended connections (DS47, and
// a lone grant.revoke's, DS48): the screen's routes, the contract's acts
// and the socket server all take the one adapter, built before the MCP
// routes, which tells nobody until routes gives it their handler, and
// then tells through it.
func TestServeWiresReaders(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	commandEnv(t, pool, filepath.Join(t.TempDir(), "deletions.ledger"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, closeAll, err := setup(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	if h := a.authHandler(); h.Readers != authapi.Readers(&a.readers) {
		t.Fatalf("the screen's routes tell %v", h.Readers)
	}
	if acts := a.settingsConfig().Acts; acts == nil || acts.Readers != numberacts.Readers(&a.readers) {
		t.Fatalf("the acts tell %+v", acts)
	}
	// The socket's grant.revoke (DS48).
	if r := a.ws.MCPReaders(); r != wsapi.MCPReaders(&a.readers) {
		t.Fatalf("the socket's grant.revoke tells %v", r)
	}
	// Before the routes, and in a process without MCP: nobody to tell.
	a.readers.TellRevoked(ctx, "enclave", "01a1c320-eb07-7f54-be23-fb8834f7a92f")
	if a.readers.h.Load() != nil {
		t.Fatal("a handler before the routes")
	}
	a.cfg.MCP = enclaveConfig()
	a.routes()
	if a.mcp == nil || a.readers.h.Load() != a.mcp {
		t.Fatal("the readers do not reach the MCP routes' handler")
	}
}
