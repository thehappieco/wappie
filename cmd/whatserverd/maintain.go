package main

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
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
		a.maintainOnce(ctx, grace, a.blob)
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

// objectStore is what the janitor needs of the bucket, so a test can pass a
// fake: core's CI runs Postgres only. *blob.Store is one, nil included.
type objectStore interface {
	Configured() bool
	Delete(ctx context.Context, key string) error
}

func (a *app) maintainOnce(ctx context.Context, grace time.Duration, objects objectStore) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	// A deletion whose WhatsApp logout was not confirmed is tried again,
	// by the session's fingerprint.
	a.retryLeftoverSessions(ctx)

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
		// A connection unused past its tier's idle time is dead to its
		// assistant, whose refresh token died in the reader: it ends, so the
		// console's list and the workspace's cap stop counting it. The
		// readers are told by the revocation watch (docs/mcp-enclave.md
		// §19.35).
		if idle, err := store.RevokeIdleMCPConnections(ctx, a.pools.API); err != nil {
			a.log.Warn("idle mcp connections were not all revoked", "error", err, "revoked", len(idle))
		} else if len(idle) > 0 {
			a.log.Info("idle mcp connections revoked", "connections", len(idle))
		}
		// A content consent abandoned after its service account registered
		// leaves an account with a thirty-minute deadline and no connection.
		if services, err := store.ExpireServiceAccounts(ctx, a.pools.API); err != nil {
			a.log.Warn("mcp service account expiry failed", "error", err)
		} else if services > 0 {
			a.log.Info("mcp service accounts removed", "accounts", services)
		}
		// Drafts nobody decided expire with their text, a send whose
		// request died is uncertain, and the ledger forgets after a year.
		settled, err := store.SettleMCPOutbound(ctx, a.pools.API)
		if err != nil {
			a.log.Warn("mcp ledger settling failed", "error", err)
		}
		for _, row := range settled.Expired {
			a.log.Info("mcp_draft_expired", "connection", row[0], "draft", row[1])
		}
		for _, row := range settled.Uncertain {
			a.log.Warn("mcp_send_uncertain", "connection", row[0], "send", row[1], "reason", "no outcome recorded")
		}
		if settled.Deleted > 0 {
			a.log.Info("mcp ledger rows past retention removed", "rows", settled.Deleted)
		}
		// AI usage counters go 400 days after their day, and deleted
		// keychain items 30 days after their deletion. The results go with
		// their messages.
		if ai, err := store.SettleAI(ctx, a.pools.API); err != nil {
			a.log.Warn("ai retention failed", "error", err)
		} else if ai.UsageRows+ai.KeychainRows > 0 {
			a.log.Info("ai rows past retention removed", "usage", ai.UsageRows, "keychain", ai.KeychainRows)
		}
	}

	// Retry confirmed orphan objects even when no new retention purge occurs.
	// Failed physical deletes retain their storage charge and remain retryable.
	if a.storage != nil && objects.Configured() {
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
				if err := a.storage.DeleteObject(ctx, id, key, objects.Delete); err != nil {
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
		if objects.Configured() {
			for _, key := range counts.ObjectKeys {
				if err := a.storage.DeleteObject(ctx, t.ID, key, objects.Delete); err != nil {
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

// sessionUnlinker is what the janitor needs of the registry to log out a
// deleted number's leftover session.
type sessionUnlinker interface {
	Unlink(ctx context.Context, tenantID, deviceID string, jid types.JID, recheck func(context.Context) error) error
}

// errSessionChanged aborts a retry whose number was recovered, deleted again,
// or whose session is no longer the fingerprinted one.
var errSessionChanged = errors.New("the deleted number or its session changed since it was listed")

// retryLeftoverSessions retries, once per pass, the logouts that deletions
// could not confirm (decision 0038's plan, 4.5), in every workspace whatever
// its status: a session WhatsApp still lists is the phone's concern either
// way. A fingerprinted session that is gone was logged out and only its
// record was lost, which is recorded without asking WhatsApp. A number held
// elsewhere, or by a recovery, waits for the next pass and costs no attempt.
// After the last attempt the purge removes the session by its fingerprint.
func (a *app) retryLeftoverSessions(ctx context.Context) {
	if a.devices == nil || a.unlinker == nil {
		return
	}
	tenants, err := a.listAllTenantIDs(ctx)
	if err != nil {
		a.log.Warn("could not list workspaces for leftover sessions", "error", err)
		return
	}
	for _, tenant := range tenants {
		leftovers, err := a.devices.LeftoverSessions(ctx, tenant)
		if err != nil {
			a.log.Warn("could not list leftover sessions", "tenant", tenant, "error", err)
			continue
		}
		for _, l := range leftovers {
			a.retryLeftoverSession(ctx, tenant, l)
		}
	}
}

func (a *app) retryLeftoverSession(ctx context.Context, tenant uuid.UUID, l store.Leftover) {
	err := wa.ErrNoSession
	if l.Present {
		jid, parseErr := types.ParseJID(l.JID)
		if parseErr != nil {
			a.log.Warn("a leftover session has no usable JID", "device", l.DeviceID, "error", parseErr)
			return
		}
		reg := l.RegistrationID
		unlinkCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		err = a.unlinker.Unlink(unlinkCtx, tenant.String(), l.DeviceID.String(), jid, func(ctx context.Context) error {
			still, err := a.devices.StillExcluded(ctx, tenant, l.DeviceID, l.DeletedAt, &reg)
			if err == nil && !still {
				err = errSessionChanged
			}
			return err
		})
		cancel()
	}
	if errors.Is(err, wa.ErrAlreadyRunning) || errors.Is(err, errSessionChanged) {
		return
	}
	confirmed := err == nil || errors.Is(err, wa.ErrNoSession)
	record, recordErr := a.devices.RecordUnlink(ctx, tenant, l.DeviceID, l.DeletedAt, confirmed)
	switch {
	case recordErr != nil && !errors.Is(recordErr, store.ErrNotFound):
		a.log.Warn("could not record a leftover session's logout", "device", l.DeviceID, "error", recordErr)
	case recordErr == nil && record.Unlinked:
		a.log.Info("a deleted number's leftover session was logged out", "device", l.DeviceID)
	case recordErr == nil && l.Attempts+1 >= store.MaxUnlinkAttempts:
		a.log.Warn("a deleted number's WhatsApp session could not be logged out; its purge removes it",
			"device", l.DeviceID, "attempts", l.Attempts+1, "error", err)
	}
}

// listAllTenantIDs is every workspace, whatever its status: the deletions'
// leftovers are retried, and purged, in suspended ones too.
func (a *app) listAllTenantIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := a.pools.API.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}
