package main

import (
	"context"
	"time"

	"whatserver2/internal/store"
)

// maintain applies retention windows and forgets dead sessions, once an hour.
//
// Nothing in it runs for a tenant that has not set a window, and the
// housekeeping only touches rows that have been dead for a month: the point
// is to stop holding what has no further use, not to be tidy.
func (a *app) maintain(ctx context.Context) {
	const every = time.Hour
	const grace = 30 * 24 * time.Hour

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		a.maintainOnce(ctx, grace)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *app) maintainOnce(ctx context.Context, grace time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	if sessions, invites, err := store.Housekeeping(ctx, a.pools.API, grace); err != nil {
		a.log.Warn("housekeeping failed", "error", err)
	} else if sessions+invites > 0 {
		a.log.Info("housekeeping", "sessions", sessions, "invites", invites)
	}

	tenants, err := store.TenantsWithRetention(ctx, a.pools.API)
	if err != nil {
		a.log.Warn("could not list retention windows", "error", err)
		return
	}
	for _, t := range tenants {
		before := time.Now().Add(-time.Duration(t.Days) * 24 * time.Hour)
		counts, err := store.Purge(ctx, a.pools.History, t.ID, before)
		if err != nil {
			a.log.Warn("retention purge failed", "tenant", t.ID, "error", err)
			continue
		}
		removed, failed := 0, 0
		if a.blob.Configured() {
			for _, key := range counts.ObjectKeys {
				if err := a.blob.Delete(ctx, key); err != nil {
					failed++
					continue
				}
				removed++
			}
		}
		if counts.Messages+counts.Receipts+counts.Changes > 0 || removed+failed > 0 {
			a.log.Info("retention applied", "tenant", t.ID, "days", t.Days,
				"messages", counts.Messages, "receipts", counts.Receipts,
				"group_events", counts.Changes, "objects_removed", removed, "objects_failed", failed)
		}
	}
}
