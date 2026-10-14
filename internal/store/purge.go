package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// The purge (decision 0038's plan, section 7): 30 days after its deletion an
// excluded number is deleted for good, in short transactions, each taking
// the workspace's row before the number's (the order of every writer, so a
// recovery waits for a batch instead of deadlocking with it). The rows, the
// keys, the grants and the WhatsApp session go on schedule; an object whose
// delete fails stays in storage_objects, unreferenced and still charged, for
// the orphan pass to retry, as retention's do. Nothing ever moves a
// purge_after later, and nothing logs a session out: one left by a logout
// WhatsApp never confirmed is removed by its exact fingerprint.

var (
	// ErrNotDue is an excluded number whose purge_after has not come.
	ErrNotDue = errors.New("store: this number's purge is not due")
	// ErrObjectsSkipped is an object delete the breaker skipped: the object
	// stays for the next orphan pass.
	ErrObjectsSkipped = errors.New("store: object deletes are skipped for the rest of this pass")
)

// DueDeletion is an excluded number whose purge is due.
type DueDeletion struct {
	DeviceID uuid.UUID
	// DueFor is how long past its purge_after it is, on the database's
	// clock.
	DueFor time.Duration
}

// DueDeletions is up to limit of the workspace's excluded numbers whose
// purge_after has passed on the database's clock, the longest due first,
// and how many are due in all.
func (d *Devices) DueDeletions(ctx context.Context, tenant uuid.UUID, limit int) ([]DueDeletion, int, error) {
	var out []DueDeletion
	total := 0
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		return withQuarantine(ctx, tx, func() error {
			rows, err := tx.Query(ctx, `SELECT id, extract(epoch FROM clock_timestamp() - purge_after)::float8, count(*) OVER ()
				FROM devices WHERE deleted_at IS NOT NULL AND purge_after <= clock_timestamp()
				ORDER BY purge_after, id LIMIT $1`, limit)
			if err != nil {
				return err
			}
			out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (DueDeletion, error) {
				var due DueDeletion
				var seconds float64
				err := row.Scan(&due.DeviceID, &seconds, &total)
				due.DueFor = time.Duration(seconds * float64(time.Second))
				return due, err
			})
			return err
		})
	})
	return out, total, err
}

// ObjectDeletes deletes the objects the janitor released, each through
// Storage.DeleteObject with Remove as the bucket's delete, under its own
// bound and cut off from the caller's cancellation: DeleteObject holds the
// workspace's row across the bucket call, and every archive write of the
// workspace waits on that row. After Trip consecutive deletes failed in one
// pass, whether they ran out of their bound or the bucket refused them at
// once, every later one is skipped, and the objects stay for the next
// orphan pass: a bucket that is down costs a pass three deletes, not one
// workspace-row hold per object. One ObjectDeletes is one pass.
type ObjectDeletes struct {
	Storage *Storage
	Remove  func(context.Context, string) error
	// Timeout bounds each delete; zero is 10 seconds.
	Timeout time.Duration
	// Trip is how many failures in a row stop the deletes; zero is 3.
	Trip int
	// OnTrip runs once, when the deletes stop.
	OnTrip func()

	mu       sync.Mutex
	failures int
	tripped  bool
	skipped  int
}

// Delete deletes one object of tenant, or skips it once the deletes stopped.
func (o *ObjectDeletes) Delete(ctx context.Context, tenant uuid.UUID, key string) error {
	o.mu.Lock()
	if o.tripped {
		o.skipped++
		o.mu.Unlock()
		return ErrObjectsSkipped
	}
	o.mu.Unlock()
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	err := o.Storage.DeleteObject(bounded, tenant, key, o.Remove)
	trip := o.Trip
	if trip <= 0 {
		trip = 3
	}
	o.mu.Lock()
	var tripped bool
	if err != nil {
		o.failures++
		if o.failures >= trip && !o.tripped {
			o.tripped, tripped = true, true
		}
	} else {
		o.failures = 0
	}
	o.mu.Unlock()
	if tripped && o.OnTrip != nil {
		o.OnTrip()
	}
	return err
}

// Skipped is how many deletes were skipped since the deletes stopped.
func (o *ObjectDeletes) Skipped() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.skipped
}

// PurgeOptions changes how PurgeDevice runs.
type PurgeOptions struct {
	// Now purges an excluded number whatever its date: an operator's
	// --now. Its purge_after becomes the purge's start, so its record
	// says it was purged early.
	Now bool
	// Batch is the most rows one batch deletes from one table; zero is 2000.
	Batch int
	// AfterBatch, for tests, runs after each batch's commit with the table
	// and the rows it deleted.
	AfterBatch func(table string, rows int64)
	// BeforeEnd, for tests, runs once the batches are done, before the
	// final transaction begins.
	BeforeEnd func()
}

// PurgeResult is what a PurgeDevice call did.
type PurgeResult struct {
	// Busy is a number a client or a logout still holds: skipped, for a
	// later pass.
	Busy bool
	// Done is a number that is gone: this call deleted its row (Final), or
	// another purger did.
	Done, Final bool
	Batches     int
	Rows        map[string]int64
	// SessionRemoved is the leftover WhatsApp session the start removed.
	SessionRemoved bool
	// Objects released by the batches: deleted, failed (left in
	// storage_objects for the orphan pass), and skipped by the breaker or
	// the budget.
	ObjectsRemoved, ObjectsFailed, ObjectsSkipped int
	DeletedAt, PurgeAfter                         time.Time
}

// purgeTables are the archive tables a purge empties, in its order, each
// with the statement that deletes one batch of the number's rows from it.
// An attachment and its AI results go with their message; the AI results
// go first, on their own, so no batch cascades to more than one row per
// message.
var purgeTables = []struct{ name, sql string }{
	{"ai_derived", `DELETE FROM ai_derived WHERE ctid = ANY(ARRAY(SELECT ctid FROM ai_derived WHERE device_id = $1 LIMIT $2))`},
	{"messages", ``},
	{"receipts", `DELETE FROM receipts WHERE ctid = ANY(ARRAY(SELECT ctid FROM receipts WHERE device_id = $1 LIMIT $2))`},
	{"group_changes", `DELETE FROM group_changes WHERE ctid = ANY(ARRAY(SELECT ctid FROM group_changes WHERE device_id = $1 LIMIT $2))`},
	{"group_participants", `DELETE FROM group_participants WHERE ctid = ANY(ARRAY(SELECT ctid FROM group_participants WHERE device_id = $1 LIMIT $2))`},
	{"contacts", `DELETE FROM contacts WHERE ctid = ANY(ARRAY(SELECT ctid FROM contacts WHERE device_id = $1 LIMIT $2))`},
	{"chats", `DELETE FROM chats WHERE ctid = ANY(ARRAY(SELECT ctid FROM chats WHERE device_id = $1 LIMIT $2))`},
	{"events", `DELETE FROM events WHERE ctid = ANY(ARRAY(SELECT ctid FROM events WHERE device_id = $1 LIMIT $2))`},
}

// PurgeDevice purges one excluded number whose purge is due, on pool (the
// History pool: its statements may take minutes). ctx is its budget,
// checked between batches and between objects; a purge it cuts short goes
// on at the next pass, since the start is kept. objects deletes what each
// batch released; nil leaves it all to the orphan pass.
//
//   - The start: the number's device lock, held by a running client or a
//     logout (Busy then: never delete a session under a live client); the
//     start time, after which no recovery is possible; and the leftover
//     WhatsApp session, removed by its exact fingerprint (jid and
//     registration id) with its privacy tokens, and never logged out.
//   - The batches: up to Batch rows of one table each, in purgeTables'
//     order, then the objects that batch released.
//   - The end: the row, whose cascade takes its keys, grants, permissions
//     and the rest; its readers' deletion notices kept with no label or
//     hint, its other notices deleted; the label and hint nulled in every
//     event row of the number, in this workspace and in any team it moved
//     out of; and the purged event.
//
// Another purger of the same number (the janitor runs in every process)
// waits on the workspace's row at each step, so the two serialize batch by
// batch, and the event's dedupe key gives one purged row.
func PurgeDevice(ctx context.Context, pool *pgxpool.Pool, tenant, device uuid.UUID, objects *ObjectDeletes, opts PurgeOptions) (PurgeResult, error) {
	out := PurgeResult{Rows: map[string]int64{}}
	batch := opts.Batch
	if batch <= 0 {
		batch = 2000
	}
	// Each transaction runs to its end once begun: the budget is checked
	// between them, and the pool's statement timeout bounds each one.
	txCtx := context.WithoutCancel(ctx)
	lockTenant := func(tx pgx.Tx) error {
		_, err := tx.Exec(txCtx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, tenant)
		return err
	}

	// The start.
	err := pg.InTenantTx(txCtx, pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockTenant(tx); err != nil {
			return err
		}
		return withQuarantine(txCtx, tx, func() error {
			var due, started bool
			var jid *string
			var reg *int64
			err := tx.QueryRow(txCtx, `SELECT purge_after <= clock_timestamp(), purge_started_at IS NOT NULL,
				wa_leftover->>'jid', (wa_leftover->>'registration_id')::bigint
				FROM devices WHERE id = $1 AND deleted_at IS NOT NULL FOR UPDATE`, device).Scan(&due, &started, &jid, &reg)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			if !due && !started && !opts.Now {
				return ErrNotDue
			}
			acquired, err := pg.TryLockTx(txCtx, tx, "device:"+device.String())
			if err != nil {
				return err
			}
			if !acquired {
				out.Busy = true
				return nil
			}
			if err := tx.QueryRow(txCtx, `UPDATE devices SET purge_started_at = coalesce(purge_started_at, clock_timestamp()),
				purge_after = CASE WHEN $2 THEN least(purge_after, clock_timestamp()) ELSE purge_after END
				WHERE id = $1 RETURNING deleted_at, purge_after`, device, opts.Now).Scan(&out.DeletedAt, &out.PurgeAfter); err != nil {
				return err
			}
			if jid == nil || reg == nil {
				return nil
			}
			present, err := sessionTableTx(txCtx, tx)
			if err != nil || !present {
				return err
			}
			// whatsmeow's own foreign keys take the session's other tables.
			// A phone linked again under the same JID has another
			// registration id and is never touched.
			tag, err := tx.Exec(txCtx, `DELETE FROM whatsmeow_device WHERE jid = $1 AND registration_id = $2`, *jid, *reg)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return nil
			}
			out.SessionRemoved = true
			return deletePrivacyTokensTx(txCtx, tx, *jid)
		})
	})
	if err != nil || out.Busy {
		return out, err
	}

	// The batches.
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		var table string
		var rows int64
		var keys []string
		gone := false
		err := pg.InTenantTx(txCtx, pool, tenant.String(), func(tx pgx.Tx) error {
			if err := lockTenant(tx); err != nil {
				return err
			}
			return withQuarantine(txCtx, tx, func() error {
				var held int
				err := tx.QueryRow(txCtx, `SELECT 1 FROM devices WHERE id = $1 AND purge_started_at IS NOT NULL FOR UPDATE`, device).Scan(&held)
				if errors.Is(err, pgx.ErrNoRows) {
					// Another purger finished it.
					gone = true
					return nil
				}
				if err != nil {
					return err
				}
				for _, t := range purgeTables {
					var err error
					if t.name == "messages" {
						rows, keys, err = purgeMessagesTx(txCtx, tx, device, batch)
					} else {
						var tag pgconn.CommandTag
						tag, err = tx.Exec(txCtx, t.sql, device, batch)
						rows = tag.RowsAffected()
					}
					if err != nil {
						return fmt.Errorf("store: purge %s: %w", t.name, err)
					}
					if rows > 0 {
						table = t.name
						return nil
					}
				}
				return nil
			})
		})
		if err != nil {
			return out, err
		}
		if gone {
			out.Done = true
			return out, nil
		}
		if rows == 0 {
			break
		}
		out.Batches++
		out.Rows[table] += rows
		if opts.AfterBatch != nil {
			opts.AfterBatch(table, rows)
		}
		if err := deleteReleased(ctx, pool, tenant, keys, objects, &out); err != nil {
			return out, err
		}
	}

	// The end.
	if opts.BeforeEnd != nil {
		opts.BeforeEnd()
	}
	err = pg.InTenantTx(txCtx, pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockTenant(tx); err != nil {
			return err
		}
		return withQuarantine(txCtx, tx, func() error {
			err := tx.QueryRow(txCtx, `SELECT deleted_at, purge_after FROM devices WHERE id = $1 AND purge_started_at IS NOT NULL FOR UPDATE`,
				device).Scan(&out.DeletedAt, &out.PurgeAfter)
			if errors.Is(err, pgx.ErrNoRows) {
				out.Done = true
				return nil
			}
			if err != nil {
				return err
			}
			// A reader whose next visit comes after the purge is still
			// told; the notice keeps no name of the number.
			if _, err := tx.Exec(txCtx, `UPDATE device_notices SET label = NULL, hint = NULL, purged_at = clock_timestamp()
				WHERE device_id = $1 AND kind = 'number_deleted'`, device); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `DELETE FROM device_notices WHERE device_id = $1 AND kind <> 'number_deleted'`, device); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `UPDATE item_events SET label = NULL, hint = NULL WHERE item_id = $1`, device); err != nil {
				return err
			}
			if err := scrubFormerWorkspacesTx(txCtx, tx, tenant, device); err != nil {
				return err
			}
			var at time.Time
			if err := tx.QueryRow(txCtx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
				return err
			}
			deletedAt, purgeAfter := out.DeletedAt, out.PurgeAfter
			if err := recordEvent(txCtx, tx, tenant, itemEvent{
				Type: eventPurged, ItemID: device, DedupeKey: dedupeKey(eventPurged, device, deletedAt), OccurredAt: at,
				ActorKind: actorApp, DeletedAt: &deletedAt, PurgeAfter: &purgeAfter,
			}); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `DELETE FROM devices WHERE id = $1`, device); err != nil {
				return fmt.Errorf("store: purge the number's row: %w", err)
			}
			out.Done, out.Final = true, true
			return nil
		})
	})
	return out, err
}

// scrubFormerWorkspacesTx nulls the label and hint of the number's event
// rows in each team it moved out of, its moved_out among them. They were
// written before the move, and usually go 30 days after it, before any
// purge; but an operator's early purge, or an export that has not taken
// them yet, finds them still there. It runs before the row's delete, whose
// cascade takes device_transfers, and leaves tx in tenant.
func scrubFormerWorkspacesTx(ctx context.Context, tx pgx.Tx, tenant, device uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT source_workspace_id FROM device_transfers WHERE device_id = $1 AND source_workspace_id <> $2`,
		device, tenant)
	if err != nil {
		return err
	}
	sources, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(sources) == 0 {
		return err
	}
	for _, source := range sources {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, source.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE item_events SET label = NULL, hint = NULL WHERE item_id = $1`, device); err != nil {
			return fmt.Errorf("store: purge the number's rows in workspace %s: %w", source, err)
		}
	}
	_, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String())
	return err
}

// purgeMessagesTx deletes up to batch of the number's messages, their
// attachments and AI results with them, and returns the object keys those
// attachments named.
func purgeMessagesTx(ctx context.Context, tx pgx.Tx, device uuid.UUID, batch int) (int64, []string, error) {
	rows, err := tx.Query(ctx, `SELECT uid FROM messages WHERE device_id = $1 LIMIT $2`, device, batch)
	if err != nil {
		return 0, nil, err
	}
	uids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(uids) == 0 {
		return 0, nil, err
	}
	keys, err := objectKeysWhere(ctx, tx, `SELECT object_key FROM media WHERE message_uid = ANY($1) AND object_key IS NOT NULL`, uids)
	if err != nil {
		return 0, nil, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM messages WHERE uid = ANY($1)`, uids)
	if err != nil {
		return 0, nil, err
	}
	return tag.RowsAffected(), keys, nil
}

// deleteReleased deletes the objects a committed batch released that
// nothing references any more. A failure is counted and left: the object's
// storage_objects row stays, unreferenced, and the orphan pass retries it,
// which is also why a crash before this loses nothing.
func deleteReleased(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID, keys []string, objects *ObjectDeletes, out *PurgeResult) error {
	if len(keys) == 0 {
		return nil
	}
	if objects == nil {
		out.ObjectsSkipped += len(keys)
		return nil
	}
	free, err := Unreferenced(context.WithoutCancel(ctx), pool, tenant, keys)
	if err != nil {
		// The objects stay for the orphan pass; the rows go on schedule.
		free = nil
		out.ObjectsFailed += len(keys)
	}
	for i, key := range free {
		if ctx.Err() != nil {
			out.ObjectsSkipped += len(free) - i
			return ctx.Err()
		}
		switch err := objects.Delete(ctx, tenant, key); {
		case err == nil:
			out.ObjectsRemoved++
		case errors.Is(err, ErrObjectsSkipped):
			out.ObjectsSkipped++
		default:
			out.ObjectsFailed++
		}
	}
	return nil
}

// OperatorDeleted is an excluded number as an operator lists it: its id,
// dates and state, never its name or its phone number.
type OperatorDeleted struct {
	DeviceID              uuid.UUID
	DeletedAt, PurgeAfter time.Time
	PurgeStarted          bool
	// Due is past its purge_after on the database's clock, by DueFor.
	Due    bool
	DueFor time.Duration
	Status string
	// Leftover is a WhatsApp session a logout did not confirm.
	Leftover bool
}

// ListAllDeleted is every excluded number of a workspace, for the operator's
// command: no owner, no names.
func (d *Devices) ListAllDeleted(ctx context.Context, tenant uuid.UUID) ([]OperatorDeleted, error) {
	var out []OperatorDeleted
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		return withQuarantine(ctx, tx, func() error {
			rows, err := tx.Query(ctx, `SELECT id, deleted_at, purge_after, purge_started_at IS NOT NULL,
				purge_after <= clock_timestamp(), greatest(extract(epoch FROM clock_timestamp() - purge_after), 0)::float8,
				status, wa_leftover IS NOT NULL
				FROM devices WHERE deleted_at IS NOT NULL ORDER BY purge_after, id`)
			if err != nil {
				return err
			}
			out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (OperatorDeleted, error) {
				var n OperatorDeleted
				var seconds float64
				err := row.Scan(&n.DeviceID, &n.DeletedAt, &n.PurgeAfter, &n.PurgeStarted, &n.Due, &seconds, &n.Status, &n.Leftover)
				n.DueFor = time.Duration(seconds * float64(time.Second))
				return n, err
			})
			return err
		})
	})
	return out, err
}
