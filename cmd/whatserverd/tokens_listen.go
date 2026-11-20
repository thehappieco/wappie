package main

import (
	"context"
	"time"

	"whatserver2/internal/access"
)

// A platform token's narrowing notifies every process at its commit
// (0053's triggers on store.ContractTokensChannel). On the notice, each
// process checks its token sockets and media streams of that token, or of
// every token, at once (access.TokenWatch); persons' and keys' sockets are
// not woken. The one-second checks stay the bound while the listening
// connection is down, and for what sends no notice: a workspace closed or
// suspended, a rotation, a membership.

// listenTokens reconnects and listens until ctx ends, with listenExcluded's
// backoff: doubling from a second while connecting keeps failing, up to a
// minute, and back to a second once a listen was established.
func (a *app) listenTokens(ctx context.Context) {
	if a.checker == nil || a.checker.Watch == nil {
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		err := access.ListenTokens(ctx, a.pools.API, a.checker.Watch, func() { backoff = time.Second })
		if ctx.Err() != nil {
			return
		}
		a.log.Warn("listening for token changes failed; token sockets and streams still check each second", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// checkerUse is the token usage counter, nil (which counts nothing) without
// a checker.
func (a *app) checkerUse() *access.TokenUse {
	if a.checker == nil {
		return nil
	}
	return a.checker.Use
}
