package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// The janitor's bounds (decision 0038's plan, section 7). The purge and the
// orphan pass each spend a budget of their own inside the pass's 30
// minutes, so neither can leave retention with an expired context; every
// object delete has its own bound, well below the API pool's 30 s statement
// timeout, since it holds the workspace's row across the bucket call.
const (
	purgeBudget   = 15 * time.Minute
	orphanBudget  = 5 * time.Minute
	objectTimeout = 10 * time.Second
	// purgePerPass is how many numbers of one workspace a pass purges.
	purgePerPass = 5
	// overdueAfter is how long past its date a number may wait before
	// every pass warns about it.
	overdueAfter = 2 * time.Hour
	// ledgerKeep is how long the ledger keeps a number after its newest
	// line, so every snapshot that can still be restored finds the lines
	// written after it. Backups live under 90 days (decision 0027): the
	// daily prune deletes a snapshot at 89 days less an hour, so the next
	// run, at most a day and half an hour later, is still inside its 90
	// days (commercial deploy/prune-backups.sh, wappie-prune-backups.timer),
	// and an off-host copy must expire as early. A host that was down
	// catches up only at its next start, and a copy's expiry can run late
	// the same way: 90 days and three of slack.
	// TestLedgerOutlivesTheBackups holds the bound.
	ledgerKeep = 93 * 24 * time.Hour
	// compactEvery is how often a process compacts the ledger.
	compactEvery = 24 * time.Hour
)

// janitorLimits are the janitor's bounds; a zero value is the default.
type janitorLimits struct {
	purge, orphans, object time.Duration
}

func (l janitorLimits) withDefaults() janitorLimits {
	if l.purge <= 0 {
		l.purge = purgeBudget
	}
	if l.orphans <= 0 {
		l.orphans = orphanBudget
	}
	if l.object <= 0 {
		l.object = objectTimeout
	}
	return l
}

func (a *app) maintainOnce(ctx context.Context, grace time.Duration, objects objectStore) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	limits := a.janitor.withDefaults()
	// One per pass: after three object deletes in a row run out of their
	// bound, the rest of the pass skips them, and the objects stay for the
	// next orphan pass.
	deletes := a.objectDeletes(objects, limits.object)

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
		a.maintainMCP(ctx)
	}

	// Every workspace, whatever its status: a closed team's and a suspended
	// one's deleted numbers are purged on their date too (the owner's
	// decisions of 2026-10-13).
	tenants, err := a.listAllTenantIDs(ctx)
	if err != nil {
		a.log.Warn("could not list the workspaces for the janitor", "error", err)
	}
	// The purge and retention release objects first; the orphan pass
	// after them retries, in the same pass, whatever they failed to delete.
	a.purgeDeletedNumbers(ctx, tenants, deletes, limits.purge)
	a.deletionHousekeeping(ctx, tenants)
	a.compactLedger(time.Now())
	a.applyRetention(ctx, deletes)
	a.deleteOrphans(ctx, tenants, deletes, limits.orphans)
}

// maintainMCP is the assistant connector's share of the pass.
func (a *app) maintainMCP(ctx context.Context) {
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

// objectDeletes is the pass's object deleter, or nil when there is no
// bucket to delete from: the objects then stay, charged, for a pass that
// has one.
func (a *app) objectDeletes(objects objectStore, timeout time.Duration) *store.ObjectDeletes {
	if a.storage == nil || objects == nil || !objects.Configured() {
		return nil
	}
	return &store.ObjectDeletes{Storage: a.storage, Remove: objects.Delete, Timeout: timeout,
		OnTrip: func() {
			a.log.Warn("object deletes keep failing; the rest of this pass leaves them for the next orphan pass", "timeout", timeout)
		}}
}

// deleteObject is one bounded object delete, or none without a bucket.
func deleteObject(ctx context.Context, deletes *store.ObjectDeletes, tenant uuid.UUID, key string) error {
	if deletes == nil {
		return store.ErrObjectsSkipped
	}
	return deletes.Delete(ctx, tenant, key)
}

// applyRetention applies each workspace's retention window.
func (a *app) applyRetention(ctx context.Context, deletes *store.ObjectDeletes) {
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
		// Each delete is cut off from ctx, so the pass's own end is
		// checked here: what is left stays for the next orphan pass.
		removed, failed, left := 0, 0, 0
		if deletes != nil {
			for i, key := range counts.ObjectKeys {
				if ctx.Err() != nil {
					left = len(counts.ObjectKeys) - i
					break
				}
				if err := deleteObject(ctx, deletes, t.ID, key); err != nil {
					failed++
					continue
				}
				removed++
			}
		}
		if counts.Messages+counts.Receipts+counts.Changes > 0 || removed+failed+left > 0 {
			a.log.Info("retention applied", "tenant", t.ID, "days", t.Days,
				"messages", counts.Messages, "receipts", counts.Receipts,
				"group_events", counts.Changes, "objects_removed", removed, "objects_failed", failed, "objects_left", left)
		}
	}
}

// deleteOrphans retries confirmed orphan objects, in every workspace, even
// when no new purge occurred: it is the only retry of a failed physical
// delete, which keeps its storage charge until it succeeds.
func (a *app) deleteOrphans(ctx context.Context, tenants []uuid.UUID, deletes *store.ObjectDeletes, budget time.Duration) {
	if deletes == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for _, id := range tenants {
		if ctx.Err() != nil {
			a.log.Warn("the orphan pass ran out of its budget; the rest waits for the next pass", "budget", budget)
			return
		}
		keys, err := a.storage.UnreferencedObjects(ctx, id, 1000)
		if err != nil {
			a.log.Warn("could not list orphan objects", "tenant", id, "error", err)
			continue
		}
		for _, key := range keys {
			if ctx.Err() != nil {
				break
			}
			if err := deleteObject(ctx, deletes, id, key); err != nil && !errors.Is(err, store.ErrObjectsSkipped) {
				a.log.Warn("orphan object cleanup failed", "tenant", id, "error", err)
			}
		}
	}
}

// purgeDeletedNumbers purges the deleted numbers whose 30 days are over,
// at most purgePerPass per workspace, within budget. Each pass starts at
// the next workspace, so a large or failing number early in the list
// cannot use up every pass; a number not finished goes on at the next.
// WS_DELETED_NUMBER_PURGE=hold, an operator's valve for an incident, purges
// nothing and says how many are due.
func (a *app) purgeDeletedNumbers(ctx context.Context, tenants []uuid.UUID, deletes *store.ObjectDeletes, budget time.Duration) {
	if len(tenants) == 0 {
		return
	}
	devices := store.NewDevices(a.pools.API)
	turn := a.purgeTurn.Add(1) - 1
	if a.cfg.Deletion.PurgeHold {
		due := 0
		for _, tenant := range tenants {
			if _, n, err := devices.DueDeletions(ctx, tenant, 1); err == nil {
				due += n
			}
		}
		a.log.Warn("deleted-number purges are held (WS_DELETED_NUMBER_PURGE=hold)", "due", due)
		return
	}
	purgeCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	start := purgeStart(tenants, turn)
	var unreached []uuid.UUID
	for i := range tenants {
		tenant := tenants[(start+i)%len(tenants)]
		if purgeCtx.Err() != nil {
			unreached = append(unreached, tenant)
			continue
		}
		due, _, err := devices.DueDeletions(purgeCtx, tenant, purgePerPass)
		if err != nil {
			if purgeCtx.Err() != nil {
				unreached = append(unreached, tenant)
			} else {
				a.log.Warn("could not list the deleted numbers due for their purge", "tenant", tenant, "error", err)
			}
			continue
		}
		for _, d := range due {
			if d.DueFor > overdueAfter {
				a.log.Warn("a deleted number is overdue for its purge", "tenant", tenant, "device", d.DeviceID,
					"due_for", d.DueFor.Round(time.Minute).String())
			}
			if purgeCtx.Err() != nil {
				continue
			}
			res, err := store.PurgeDevice(purgeCtx, a.pools.History, tenant, d.DeviceID, deletes, store.PurgeOptions{})
			switch {
			case errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrNotDue):
				// Purged by another process, or recovered, meanwhile.
			case err != nil && purgeCtx.Err() != nil:
				a.log.Info("a purge goes on at the next pass", "tenant", tenant, "device", d.DeviceID, "batches", res.Batches)
			case err != nil:
				a.log.Warn("a deleted number's purge failed; the next pass goes on with it", "tenant", tenant, "device", d.DeviceID, "error", err)
			case res.Busy:
				a.log.Info("a deleted number is still held by a client or a logout; its purge waits for the next pass",
					"tenant", tenant, "device", d.DeviceID)
			case res.Final:
				a.purged(ctx, tenant, d.DeviceID, res)
			}
		}
	}
	if purgeCtx.Err() == nil {
		return
	}
	var left []string
	for _, tenant := range unreached {
		_, n, err := devices.DueDeletions(ctx, tenant, 1)
		switch {
		case err != nil:
			left = append(left, tenant.String()+":unknown")
		case n > 0:
			left = append(left, fmt.Sprintf("%s:%d", tenant, n))
		}
	}
	a.log.Warn("the deleted-number purge ran out of its budget; the next pass starts at another workspace",
		"budget", budget, "not_reached", strings.Join(left, ","))
}

// purgeStart is where the turn-th pass starts among tenants: one workspace
// later each pass.
func purgeStart(tenants []uuid.UUID, turn uint64) int {
	if len(tenants) == 0 {
		return 0
	}
	return int(turn % uint64(len(tenants))) //nolint:gosec // G115: below len(tenants), an int
}

// purged records a purge that finished: the ledger, then the line the
// deploy's smoke test reads.
func (a *app) purged(ctx context.Context, tenant, device uuid.UUID, res store.PurgeResult) {
	a.exportLedger(ctx, tenant)
	var rows int64
	for _, n := range res.Rows {
		rows += n
	}
	a.log.Info("number purged", "tenant", tenant, "device", device, "deleted_at", res.DeletedAt, "purge_after", res.PurgeAfter,
		"batches", res.Batches, "rows", rows, "session_removed", res.SessionRemoved, "objects_removed", res.ObjectsRemoved,
		"objects_failed", res.ObjectsFailed, "objects_left", res.ObjectsSkipped)
}

// deletionHousekeeping exports each workspace's new events to the ledger,
// then forgets the event rows and notices whose time is over.
func (a *app) deletionHousekeeping(ctx context.Context, tenants []uuid.UUID) {
	for _, tenant := range tenants {
		a.exportLedger(ctx, tenant)
		counts, err := store.DeletionHousekeeping(ctx, a.pools.API, tenant)
		if err != nil {
			a.log.Warn("deleted-number housekeeping failed", "tenant", tenant, "error", err)
			continue
		}
		if counts.Events+counts.Notices > 0 {
			a.log.Info("deleted-number housekeeping", "tenant", tenant, "events", counts.Events, "notices", counts.Notices)
		}
		if counts.Unledgered > 0 {
			a.log.Error("event rows 30 days old are still not in the deletion ledger; they stay until it takes them",
				"tenant", tenant, "rows", counts.Unledgered, "oldest", counts.Oldest)
		}
	}
}

// compactLedger drops, once a day, the ledger lines no restorable backup
// can need.
func (a *app) compactLedger(now time.Time) {
	if a.ledger == nil || (!a.compacted.IsZero() && now.Sub(a.compacted) < compactEvery) {
		return
	}
	res, err := a.ledger.Compact(now, ledgerKeep)
	if err != nil {
		a.log.Error("deletion ledger compaction failed", "path", a.ledger.Path, "error", err)
		return
	}
	a.compacted = now
	if res.Rewritten {
		a.log.Info("deletion ledger compacted", "path", a.ledger.Path, "kept", res.Kept, "dropped", res.Dropped)
	}
}

// sessionUnlinker is what the janitor needs of the registry to log out a
// deleted number's leftover session: a logout that never touches a number
// this process holds or a deletion is logging out here, and the device lock
// for a record with no logout.
type sessionUnlinker interface {
	UnlinkLeftover(ctx context.Context, tenantID, deviceID string, jid types.JID,
		recheck func(context.Context) error, record func(context.Context, error)) error
	LockIdle(ctx context.Context, deviceID string, f func(context.Context) error) error
}

// errSessionChanged aborts a retry whose number was recovered, deleted again,
// or whose session is no longer the fingerprinted one.
var errSessionChanged = errors.New("the deleted number or its session changed since it was listed")

// retryLeftoverSessions retries, once per pass, the logouts that deletions
// could not confirm (decision 0038's plan, 4.5), in every workspace whatever
// its status: a session WhatsApp still lists is the phone's concern either
// way. A fingerprinted session that is gone was logged out and only its
// record was lost, which is recorded without asking WhatsApp. A number held
// here or elsewhere, by a deletion or by a recovery, waits for the next pass
// and costs no attempt. After the last attempt the purge removes the session
// by its fingerprint.
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
	var record store.UnlinkRecord
	var recordErr error
	recorded := false
	// Every record that follows a logout, or that confirms one, runs under
	// the device lock, so a recovery cannot land between them.
	write := func(ctx context.Context, logoutErr error) {
		confirmed := logoutErr == nil || errors.Is(logoutErr, wa.ErrNoSession)
		record, recordErr = a.devices.RecordUnlink(context.WithoutCancel(ctx), tenant, l.DeviceID, l.DeletedAt, confirmed)
		recorded = true
	}
	var err error
	if l.Present {
		jid, parseErr := types.ParseJID(l.JID)
		if parseErr != nil {
			a.log.Warn("a leftover session has no usable JID", "device", l.DeviceID)
			return
		}
		reg := l.RegistrationID
		unlinkCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		err = a.unlinker.UnlinkLeftover(unlinkCtx, tenant.String(), l.DeviceID.String(), jid, func(ctx context.Context) error {
			still, err := a.devices.StillExcluded(ctx, tenant, l.DeviceID, l.DeletedAt, &reg)
			if err == nil && !still {
				err = errSessionChanged
			}
			return err
		}, write)
		cancel()
	} else {
		err = a.unlinker.LockIdle(ctx, l.DeviceID.String(), func(ctx context.Context) error {
			write(ctx, wa.ErrNoSession)
			return nil
		})
	}
	if errors.Is(err, wa.ErrAlreadyRunning) || errors.Is(err, errSessionChanged) {
		return
	}
	if !recorded {
		// The logout never reached WhatsApp: one more attempt.
		write(ctx, err)
	}
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
