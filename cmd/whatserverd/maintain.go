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

// mcpPendingTTL is how long a consented connection may wait for the reader to
// finish the handshake. It matches the reader's own pending-request lifetime:
// past it the request is gone and the consent can only be given again.
const mcpPendingTTL = 20 * time.Minute

func (a *app) maintainOnce(ctx context.Context, grace time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	if sessions, invites, err := store.Housekeeping(ctx, a.pools.API, grace); err != nil {
		a.log.Warn("housekeeping failed", "error", err)
	} else if sessions+invites > 0 {
		a.log.Info("housekeeping", "sessions", sessions, "invites", invites)
	}

	// Keys issued with a deadline stop working the moment it passes; this
	// records the fact so the key list agrees. A hosted assistant connection
	// whose handshake never finished is revoked with its key once the reader
	// has forgotten the request — where a reader runs; elsewhere the table
	// stays empty and is left alone.
	if keys, err := store.ExpireAPIKeys(ctx, a.pools.API); err != nil {
		a.log.Warn("api key expiry failed", "error", err)
	} else if keys > 0 {
		a.log.Info("api keys expired", "keys", keys)
	}
	if a.cfg.MCP.Enabled {
		if connections, err := store.ExpireMCPConnections(ctx, a.pools.API, mcpPendingTTL); err != nil {
			a.log.Warn("mcp connection expiry failed", "error", err)
		} else if connections > 0 {
			a.log.Info("mcp connections settled", "connections", connections)
		}
	}

	// Retry confirmed orphan objects even when no new retention purge occurs.
	// Failed physical deletes retain their storage charge and remain retryable.
	if a.storage != nil && a.blob.Configured() {
		ids, err := a.listTenantIDs(ctx)
		if err != nil {
			a.log.Warn("could not list storage cleanup workspaces", "error", err)
		}
		for _, id := range ids {
			keys, err := a.storage.UnreferencedObjects(ctx, id, 1000)
			if err != nil {
				a.log.Warn("could not list orphan objects", "tenant", id, "error", err)
				continue
			}
			for _, key := range keys {
				if err := a.storage.DeleteObject(ctx, id, key, a.blob.Delete); err != nil {
					a.log.Warn("orphan object cleanup failed", "tenant", id, "error", err)
				}
			}
		}
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
				if err := a.storage.DeleteObject(ctx, t.ID, key, a.blob.Delete); err != nil {
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
