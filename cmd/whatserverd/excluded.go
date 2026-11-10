package main

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/store"
)

// A deletion notifies every process at its commit (store.Quarantine sends
// store.DeviceExcludedChannel). Rows can no longer be written for the number
// anywhere (WS002), and every request checks access again, but presence and
// typing are published with no database write: a process that holds the
// number would go on relaying them to its own subscribers until its
// supervisor's next tick. On the notice, each process drops the number from
// its subscriptions at once, and stops and forgets it if it holds it, unless
// a deletion is logging it out here. The tick stays the backstop while the
// listening connection is down.

// listenExcluded listens for deletions until ctx ends (keepListening).
func (a *app) listenExcluded(ctx context.Context) {
	a.keepListening(ctx, "listening for deleted numbers failed; the supervisor's tick still releases them",
		func(ready func()) error {
			return listenDeviceExcluded(ctx, a.pools.API, func(tenant, device uuid.UUID) {
				a.onDeviceExcluded(ctx, tenant, device)
			}, ready)
		})
}

// keepListening runs listen until ctx ends, again after each failure,
// logging failed at Warn. The wait between attempts doubles while
// connecting keeps failing, up to a minute, and starts again at a second
// once a listen was established (listen calls ready then), so failures
// days apart never leave a whole minute of notices unheard.
func (a *app) keepListening(ctx context.Context, failed string, listen func(ready func()) error) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := listen(func() { backoff = time.Second })
		if ctx.Err() != nil {
			return
		}
		a.log.Warn(failed, "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// onDeviceExcluded lets go of a deleted number in this process.
func (a *app) onDeviceExcluded(ctx context.Context, tenant, device uuid.UUID) {
	if a.bus != nil {
		a.bus.DropDevice(tenant, device)
	}
	a.release(ctx, device.String(), "deleted")
}

// listenDeviceExcluded calls notice for each deletion until ctx ends or
// the connection fails (listenNotices).
func listenDeviceExcluded(ctx context.Context, pool *pgxpool.Pool, notice func(tenant, device uuid.UUID), ready ...func()) error {
	return listenNotices(ctx, pool, store.DeviceExcludedChannel, func(payload string) {
		tenant, device, err := store.ParseDeviceExcluded(payload)
		if err != nil {
			return
		}
		notice(tenant, device)
	}, ready...)
}

// listenNotices holds one connection of its own, opened with pool's
// configuration but outside it, so a LISTEN never takes a request's slot,
// and calls notice with each payload sent on channel until ctx ends or
// the connection fails. It returns once it is listening only through
// ready.
func listenNotices(ctx context.Context, pool *pgxpool.Pool, channel string, notice func(payload string), ready ...func()) error {
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
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return err
	}
	for _, f := range ready {
		f()
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		notice(n.Payload)
	}
}
