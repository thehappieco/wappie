package access

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/store"
)

// TokenWatch wakes a token's open sockets and media streams when something
// token auth reads changes (the plan's 4.6): 0053's triggers NOTIFY
// store.ContractTokensChannel with a token's id, or "all", and ListenTokens
// hands each notice to Notify. Only token sockets and streams register, so
// a notice wakes no person's or key's. The wake is an early check only: the
// one-second checks stay the bound, for what sends no notice. A nil
// *TokenWatch wakes nothing.
type TokenWatch struct {
	mu   sync.Mutex
	subs map[uuid.UUID]map[chan struct{}]struct{}
}

// NewTokenWatch returns an empty watch.
func NewTokenWatch() *TokenWatch {
	return &TokenWatch{subs: map[uuid.UUID]map[chan struct{}]struct{}{}}
}

// Register wakes the returned channel on every notice of token or of all,
// until cancel. A wake that finds the channel full is the one it holds.
func (w *TokenWatch) Register(token uuid.UUID) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	if w == nil {
		return ch, func() {}
	}
	w.mu.Lock()
	if w.subs == nil {
		w.subs = map[uuid.UUID]map[chan struct{}]struct{}{}
	}
	if w.subs[token] == nil {
		w.subs[token] = map[chan struct{}]struct{}{}
	}
	w.subs[token][ch] = struct{}{}
	w.mu.Unlock()
	return ch, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.subs[token], ch)
		if len(w.subs[token]) == 0 {
			delete(w.subs, token)
		}
	}
}

// Notify wakes the registrations of a notice's payload: a token's id, or
// every token's for "all" or anything that is not an id.
func (w *TokenWatch) Notify(payload string) {
	if w == nil {
		return
	}
	id, err := uuid.Parse(payload)
	w.mu.Lock()
	defer w.mu.Unlock()
	wake := func(chans map[chan struct{}]struct{}) {
		for ch := range chans {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
	if err != nil {
		for _, chans := range w.subs {
			wake(chans)
		}
		return
	}
	wake(w.subs[id])
}

// ListenTokens holds one connection of its own, opened with pool's
// configuration but outside it, so a LISTEN never takes a request's slot,
// and hands every notice of store.ContractTokensChannel to watch until ctx
// ends or the connection fails. Each ready runs once it listens. Every
// registration is woken once it listens, for what changed while it did
// not.
func ListenTokens(ctx context.Context, pool *pgxpool.Pool, watch *TokenWatch, ready ...func()) error {
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		//nolint:errcheck // closing a listener that is going away anyway
		_ = conn.Close(closeCtx)
	}()
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{store.ContractTokensChannel}.Sanitize()); err != nil {
		return err
	}
	watch.Notify("all")
	for _, f := range ready {
		f()
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		watch.Notify(n.Payload)
	}
}
