package store

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/label"
	"whatserver2/internal/obs"
)

// item_events (0050) is the local log of what happened to a number: one
// plain row per event, in the transaction that made the change. Nothing
// reads the rows yet but the ledger export and housekeeping; a later release
// renders the platform contract's events from them. Every row goes in
// through recordEvent, and every writer holds the workspace's row lock until
// its commit, so seq order within a workspace is commit order.

// Event types recorded in this release; purged comes with the purge.
const (
	eventDeleted    = "deleted"
	eventRecovered  = "recovered"
	eventSyncPaused = "sync_paused"
	eventMovedOut   = "moved_out"
)

// Actor kinds of an event row.
const (
	actorPerson = "person"
	actorKey    = "key"
)

// itemEvent is one row of item_events. Times come from the database's clock.
type itemEvent struct {
	Type   string
	ItemID uuid.UUID
	// DedupeKey makes a retried write a no-op: type, item and the instant
	// that identifies the event, in microseconds.
	DedupeKey  string
	OccurredAt time.Time
	// ActorKind is person, key or app. ActorSub is the platform sub of the
	// person (or of a key's creator); ActorUserID is local and never sent.
	ActorKind   string
	ActorSub    *uuid.UUID
	ActorUserID *uuid.UUID
	ReaderSubs  []uuid.UUID
	Label, Hint *string
	DeletedAt   *time.Time
	PurgeAfter  *time.Time
	// ToTenantID is the workspace a moved_out number went to.
	ToTenantID *uuid.UUID
}

// recordEvent writes ev in the workspace of tx, the one INSERT into
// item_events. A row with the same dedupe key is already the event, and
// nothing is written again. A sync_paused row is never ledgered, so it is
// written as if it were: the ledger keeps what a restore must replay.
func recordEvent(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, ev itemEvent) error {
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("store: event id: %w", err)
	}
	subs := ev.ReaderSubs
	if subs == nil {
		subs = []uuid.UUID{}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at,
		actor_kind, actor_sub, actor_user_id, reader_subs, label, hint, deleted_at, purge_after, to_tenant_id, ledgered_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, CASE WHEN $3 = 'sync_paused' THEN clock_timestamp() END)
		ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
		id, tenant, ev.Type, ev.ItemID, ev.DedupeKey, ev.OccurredAt, ev.ActorKind, ev.ActorSub, ev.ActorUserID,
		subs, ev.Label, ev.Hint, ev.DeletedAt, ev.PurgeAfter, ev.ToTenantID); err != nil {
		return fmt.Errorf("store: record %s: %w", ev.Type, err)
	}
	return nil
}

// dedupeKey is type:item:instant, the instant in microseconds, as the
// database stores it.
func dedupeKey(kind string, item uuid.UUID, at time.Time) string {
	return kind + ":" + item.String() + ":" + strconv.FormatInt(at.UnixMicro(), 10)
}

// itemLabel is what a notice and an event row keep of a number's name: the
// contract's label (decision 0038's plan, 4.11: its label, else its push
// name, with phone numbers masked and addresses dropped), and "…" with the
// last four digits of its phone number. Never the number, never its LID.
func itemLabel(device uuid.UUID, name, pushName, pn string) (lbl, hint *string) {
	return label.Contract(name, pushName, pn, device.String()), label.HintFromPN(pn)
}

// actorSubTx is an actor's platform sub (a person, or a key's creator), or
// nil for someone the platform does not know. Where people sign in through
// the platform, every person who can act has one, so an actor without one
// is a fault: it is logged at ERROR and the row keeps actor_kind with no
// sub, never the app's (the plan's section 8, "Actors"). A self-hosted
// installation links nobody, and says nothing.
func actorSubTx(ctx context.Context, tx pgx.Tx, user uuid.UUID) (*uuid.UUID, error) {
	var sub *uuid.UUID
	var platform bool
	err := tx.QueryRow(ctx, `SELECT (SELECT sub FROM platform_identities WHERE user_id=$1),
		EXISTS(SELECT 1 FROM platform_identities)`, user).Scan(&sub, &platform)
	if err != nil {
		return nil, err
	}
	if sub == nil && platform {
		obs.LoggerFrom(ctx).Error("an event's actor has no platform sub", "user", user)
	}
	return sub, nil
}
