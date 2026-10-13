package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/label"
)

// item_events (0050) is the local log of what happened to a number: one
// plain row per event, in the transaction that made the change. Nothing
// reads the rows yet but the ledger export and housekeeping; a later release
// renders the platform contract's events from them. Every row goes in
// through recordEvent, and every writer holds the workspace's row lock until
// its commit, so seq order within a workspace is commit order.

// Event types recorded in this release.
const (
	eventDeleted   = "deleted"
	eventRecovered = "recovered"
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
}

// recordEvent writes ev in the workspace of tx. A row with the same dedupe
// key is already the event, and nothing is written again.
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
		actor_kind, actor_sub, actor_user_id, reader_subs, label, hint, deleted_at, purge_after)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
		id, tenant, ev.Type, ev.ItemID, ev.DedupeKey, ev.OccurredAt, ev.ActorKind, ev.ActorSub, ev.ActorUserID,
		subs, ev.Label, ev.Hint, ev.DeletedAt, ev.PurgeAfter); err != nil {
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
// contract's label (decision 0038's plan, 4.11), and "…" with the last four
// digits of its phone number. The label rule, which masks phone numbers and
// addresses, comes with the notices' own release step; until then no label
// is kept at all, which is the one answer that cannot leak a digit.
func itemLabel(_, _, pn string) (lbl, hint *string) {
	return nil, label.HintFromPN(pn)
}

// actorSubTx is a person's platform sub, or nil for someone the platform
// does not know (a local account, or a self-hosted installation).
func actorSubTx(ctx context.Context, tx pgx.Tx, user uuid.UUID) (*uuid.UUID, error) {
	var sub uuid.UUID
	err := tx.QueryRow(ctx, `SELECT sub FROM platform_identities WHERE user_id=$1`, user).Scan(&sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sub, nil
}
