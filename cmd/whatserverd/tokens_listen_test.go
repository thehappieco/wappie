package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/access"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/tokentest"
)

// TestTheTokenListenerWakesTheTokensWatch: the serving process's listener
// hands a token's notice to its watch, which wakes that token's sockets and
// streams. (The database is shared with other packages' tests, whose
// notices of every token may come too, so no other watch is asserted
// quiet here: access's own test pins that.)
func TestTheTokenListenerWakesTheTokensWatch(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	w := tokentest.New(t, pool, uuid.Nil)
	device := w.Number("Vendas")
	revoked := w.Token(tokentest.Read(device))
	a := &app{log: slog.New(slog.DiscardHandler), pools: &pg.Pools{API: pool}, checker: &access.Checker{Watch: access.NewTokenWatch()}}
	woken, cancelWoken := a.checker.Watch.Register(revoked.ID)
	defer cancelWoken()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.listenTokens(ctx)
	// The listener wakes every registration once it listens.
	select {
	case <-woken:
	case <-time.After(10 * time.Second):
		t.Fatal("the listener never listened")
	}
	w.Revoke(revoked)
	select {
	case <-woken:
	case <-time.After(10 * time.Second):
		t.Fatal("the revocation's notice never came")
	}
}
