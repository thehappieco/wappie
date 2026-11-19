package main

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/store"
)

// A reset (store.ResetArchive) and a new archive key
// (store.CreateArchiveKey) notify every process at their commit
// (store.ArchiveKeyChannel). Ingest builds each number's pipeline once,
// with the number's archive key, and keeps it. Without the notice a
// running server kept sealing to the old key after reset-archive
// -keep-devices and device-key, which gives the number a new key at epoch
// 1, until it restarted. On the notice, each process drops the pipeline of
// that number, or of every number of the workspace, and the next message
// builds it again from the key as it is now. Each new content key is also
// checked against the number's key (ingest.PinnedKeys), which catches a
// pipeline a notice missed (DS49).

// listenArchiveKeys listens for archive key changes until ctx ends
// (keepListening).
func (a *app) listenArchiveKeys(ctx context.Context) {
	a.keepListening(ctx, "listening for archive key changes failed; each new content key is still checked against the number's key",
		func(ready func()) error {
			return listenArchiveKeyChanged(ctx, a.pools.API, a.onArchiveKey, ready)
		})
}

// onArchiveKey drops what ingest built from an archive key that changed:
// one number's pipeline, every pipeline of a workspace (device nil, a
// reset), or every pipeline (tenant nil too, when listening starts).
func (a *app) onArchiveKey(tenant, device uuid.UUID) {
	switch {
	case tenant == uuid.Nil:
		a.router.ForgetAll()
	case device == uuid.Nil:
		a.log.Info("a workspace's archive was reset; ingest seals to its new keys from the next message", "tenant", tenant)
		a.router.ForgetWorkspace(tenant)
	default:
		a.log.Info("a number has a new archive key; ingest seals to it from the next message", "tenant", tenant, "device", device)
		a.router.Forget(device)
	}
}

// listenArchiveKeyChanged calls notice for each archive key change until
// ctx ends or the connection fails (listenNotices). Once it is listening,
// and before ready, it calls notice(uuid.Nil, uuid.Nil): a notice sent
// while this process was not listening is lost, so every pipeline goes.
func listenArchiveKeyChanged(ctx context.Context, pool *pgxpool.Pool, notice func(tenant, device uuid.UUID), ready ...func()) error {
	return listenNotices(ctx, pool, store.ArchiveKeyChannel, func(payload string) {
		tenant, device, err := store.ParseArchiveKeyNotice(payload)
		if err != nil {
			return
		}
		notice(tenant, device)
	}, append([]func(){func() { notice(uuid.Nil, uuid.Nil) }}, ready...)...)
}
