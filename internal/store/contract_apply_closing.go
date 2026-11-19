package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A closed account at enforce (DS54; E1c). The account's part of a closed
// document (whose workspaces is []): the person is suspended and leaves
// every team at once (but a team whose number they are the last key holder
// of, which waits for the confirmation), the personal workspace is left as
// it is, and the closing is recorded (contract_closings.seen_at) and held
// (closing_unconfirmed). A document that says anything else again drops a
// record not confirmed yet. Only a fresh signed GET of the confirmed
// generation that still answers closed confirms it (ConfirmClosing): each
// number of the personal workspace is then deleted by the app (logged out,
// purged within 30 days of the closing seen), a registration that never
// linked is deleted at once, and the next pass applies the team losses
// held. Once every personal number is purged, the account is forgotten
// (ForgetClosed), while its document still says closed: its users row
// goes, and with it its personal workspace, platform identity, wraps,
// sessions and passkeys by their foreign keys. The caller then sends the platform's unsubscribe
// (ClosingUnsubscribed). The record of the closing (sub and times) stays 13
// months (RetainClosings). An active fresh answer deletes nothing
// (ErrClosingContradicted, logged at ERROR as closing_contradicted).

// ErrClosingContradicted is a fresh answer that says the closed account is
// active: nothing is deleted.
var ErrClosingContradicted = errors.New("store: a fresh answer says the closed account is active")

// ErrClosingUnconfirmed is a fresh answer that does not confirm the
// closing (not closed, another sub, or not of the confirmed generation):
// nothing is deleted.
var ErrClosingUnconfirmed = errors.New("store: the answer does not confirm the closing")

// ContractErrorClosingContradicted is contract_state.error_class for a
// closing a fresh answer contradicted.
const ContractErrorClosingContradicted = "closing_contradicted"

// ClosingResult is what a closing's confirmation or forgetting did.
type ClosingResult struct {
	Sub       uuid.UUID
	Workspace uuid.UUID
	// Already: the closing was confirmed (or forgotten) before.
	Already bool
	// Quarantined counts the personal numbers deleted (excluded, purged
	// later); Deleted the registrations that never linked, deleted now.
	Quarantined, Deleted int
	PurgeDueAt           *time.Time
	// Sessions are the deleted numbers' WhatsApp sessions to log out,
	// which the janitor logs out when nobody else does.
	Sessions []WASession
}

// closing records a closed account's closing, and holds it until a fresh
// answer confirms it. A record not confirmed yet takes the account's
// current local account and personal workspace and keeps when it was seen;
// one of another local account, or forgotten, is a closing of its own and
// starts again (a forgotten sub can come back through a new link). The
// caller holds the account's row.
func (r *applyRun) closing(ctx context.Context) error {
	var personal *uuid.UUID
	if r.personal != uuid.Nil {
		personal = &r.personal
	}
	var user *uuid.UUID
	var confirmed, forgotten *time.Time
	err := r.tx.QueryRow(ctx, `SELECT user_id, confirmed_at, forgotten_at FROM contract_closings WHERE sub = $1`, r.sub).
		Scan(&user, &confirmed, &forgotten)
	seen := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return err
	}
	if seen && (forgotten != nil || user == nil || *user != r.user) {
		seen, confirmed = false, nil
		if r.st.apply {
			if _, err := r.tx.Exec(ctx, `DELETE FROM contract_closings WHERE sub = $1`, r.sub); err != nil {
				return err
			}
		}
	}
	if r.st.apply {
		switch {
		case !seen:
			_, err = r.tx.Exec(ctx, `INSERT INTO contract_closings (sub, user_id, personal_workspace) VALUES ($1, $2, $3)`,
				r.sub, r.user, personal)
		case confirmed == nil:
			_, err = r.tx.Exec(ctx, `UPDATE contract_closings SET user_id = $2, personal_workspace = $3 WHERE sub = $1`,
				r.sub, r.user, personal)
		}
		if err != nil {
			return err
		}
	}
	if !seen {
		r.out.add(ApplyAction{Kind: ApplyClosingSeen, User: r.user, Workspace: r.personal})
	}
	if confirmed == nil {
		r.hold(HeldClosingUnconfirmed, r.personal)
	}
	return nil
}

// ConfirmClosing confirms sub's closing with fresh, the document a signed
// GET answered just now (membership.Members' confirmClosing), in one
// transaction at enforce: contract_state FOR SHARE, the account's row, the
// closing's, the personal workspace's row. fresh must be closed, of sub,
// of the stored generation, which must be confirmed; an active one is
// ErrClosingContradicted, anything else ErrClosingUnconfirmed, and nothing
// is written. Each live number of the personal workspace is deleted by the
// app (quarantineTx), with its purge no later than 30 days after the
// closing was seen; a registration that never linked is deleted now. It
// records confirmed_at and purge_due_at, the last purge's date.
func (c *Contract) ConfirmClosing(ctx context.Context, sub uuid.UUID, fresh ContractDoc) (ClosingResult, error) {
	return c.confirmClosing(ctx, sub, fresh, true)
}

func (c *Contract) confirmClosing(ctx context.Context, sub uuid.UUID, fresh ContractDoc, gate bool) (ClosingResult, error) {
	var out ClosingResult
	err := c.applyTx(ctx, gate, func(tx pgx.Tx, st applyState) error {
		out = ClosingResult{Sub: sub}
		switch {
		case fresh.Sub != sub:
			return ErrClosingUnconfirmed
		case fresh.Status == "active":
			return ErrClosingContradicted
		case fresh.Status != "closed" || st.generation == nil || !st.confirmed || fresh.Generation != *st.generation:
			return ErrClosingUnconfirmed
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_accounts WHERE sub = $1 FOR UPDATE`, sub); err != nil {
			return err
		}
		var personal *uuid.UUID
		var seenAt time.Time
		var confirmedAt *time.Time
		err := tx.QueryRow(ctx, `SELECT personal_workspace, seen_at, confirmed_at FROM contract_closings WHERE sub = $1 FOR UPDATE`, sub).
			Scan(&personal, &seenAt, &confirmedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if confirmedAt != nil {
			out.Already = true
			return nil
		}
		var due time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&due); err != nil {
			return err
		}
		if personal != nil {
			out.Workspace = *personal
			last, err := quarantinePersonalTx(ctx, tx, *personal, seenAt.Add(30*24*time.Hour), &out)
			if err != nil {
				return err
			}
			if last.After(due) {
				due = last
			}
		}
		out.PurgeDueAt = &due
		if _, err := tx.Exec(ctx, `UPDATE contract_closings SET confirmed_at = clock_timestamp(), purge_due_at = $2 WHERE sub = $1`,
			sub, due); err != nil {
			return err
		}
		// The hold stays for the next pass, first in line: it applies
		// the team losses the closing held (those that strand a number)
		// and clears it.
		_, err = tx.Exec(ctx, `UPDATE contract_accounts SET apply_last_at = NULL WHERE sub = $1 AND apply_held IS NOT NULL`, sub)
		return err
	})
	return out, err
}

// quarantinePersonalTx deletes every number of a closed account's personal
// workspace as the app, under the workspace's row: a registration that
// never linked now, a live number by quarantineTx with its purge no later
// than purgeBy, a number deleted already as it is. It returns the latest
// purge date.
func quarantinePersonalTx(ctx context.Context, tx pgx.Tx, personal uuid.UUID, purgeBy time.Time, out *ClosingResult) (time.Time, error) {
	var last time.Time
	if err := scope(ctx, tx, personal, uuid.Nil); err != nil {
		return last, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)`, personal).Scan(&exists); err != nil || !exists {
		return last, err
	}
	if err := lockWorkspaceAccess(ctx, tx, personal); err != nil {
		return last, err
	}
	type number struct {
		id               uuid.UUID
		deleted, pending bool
		purgeAfter       *time.Time
	}
	var numbers []number
	err := withQuarantine(ctx, tx, func() error {
		rows, err := tx.Query(ctx, `SELECT id, deleted_at IS NOT NULL, lid IS NULL AND pn IS NULL AND last_connected_at IS NULL, purge_after
			FROM devices WHERE tenant_id = $1 ORDER BY id`, personal)
		if err != nil {
			return err
		}
		numbers, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (number, error) {
			var n number
			err := row.Scan(&n.id, &n.deleted, &n.pending, &n.purgeAfter)
			return n, err
		})
		return err
	})
	if err != nil {
		return last, err
	}
	for _, n := range numbers {
		switch {
		case n.deleted:
			if n.purgeAfter != nil && n.purgeAfter.After(last) {
				last = *n.purgeAfter
			}
			continue
		case n.pending:
			tag, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1 AND lid IS NULL AND pn IS NULL AND last_connected_at IS NULL`, n.id)
			if err != nil {
				return last, err
			}
			if tag.RowsAffected() == 1 {
				out.Deleted++
				continue
			}
			// It linked since the read (a code scanned before the
			// suspension): deleted below like any live number, under
			// its row.
		}
		q := Quarantined{DeviceID: n.id}
		err := quarantineTx(ctx, tx, personal, n.id, quarantineBy{purgeBy: &purgeBy}, &q)
		if errors.Is(err, ErrNotFound) {
			// Gone since the read.
			continue
		}
		if err != nil {
			return last, err
		}
		if !q.Already {
			out.Quarantined++
			if q.Session != nil {
				out.Sessions = append(out.Sessions, *q.Session)
			}
		}
		if q.PurgeAfter.After(last) {
			last = q.PurgeAfter
		}
	}
	return last, nil
}

// ForgetClosed forgets a closed account once its closing is confirmed and
// every number of its personal workspace is purged, in one transaction at
// enforce: its users row is deleted, and its personal workspace, platform
// identity, wraps, sessions and passkeys go by their foreign keys (a
// transfer it made keeps its record with no actor, an outbound message it
// decided keeps its with no decider: 0055). It records forgotten_at, and
// drops the record's local account and personal workspace: it keeps the
// sub and the times only. false, writing nothing, while a personal number
// or a team membership remains (a loss held for a strand), or once the
// stored document of the stored generation no longer says closed or the
// account is no longer disabled here.
func (c *Contract) ForgetClosed(ctx context.Context, sub uuid.UUID) (ClosingResult, bool, error) {
	return c.forgetClosed(ctx, sub, true)
}

func (c *Contract) forgetClosed(ctx context.Context, sub uuid.UUID, gate bool) (ClosingResult, bool, error) {
	var out ClosingResult
	forgotten := false
	err := c.applyTx(ctx, gate, func(tx pgx.Tx, _ applyState) error {
		out, forgotten = ClosingResult{Sub: sub}, false
		if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_accounts WHERE sub = $1 FOR UPDATE`, sub); err != nil {
			return err
		}
		var user, personal *uuid.UUID
		var confirmedAt, forgottenAt *time.Time
		err := tx.QueryRow(ctx, `SELECT user_id, personal_workspace, confirmed_at, forgotten_at FROM contract_closings WHERE sub = $1 FOR UPDATE`,
			sub).Scan(&user, &personal, &confirmedAt, &forgottenAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if forgottenAt != nil {
			out.Already, forgotten = true, true
			return nil
		}
		if confirmedAt == nil || user == nil {
			return nil
		}
		// Only while the stored document of the stored generation still
		// says closed and the account is still disabled here: anything
		// else forgets nothing.
		var still bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM contract_accounts a JOIN contract_state s ON s.generation = a.generation
				WHERE a.sub = $1 AND a.doc IS NOT NULL AND a.doc->>'status' = 'closed')`, sub).Scan(&still); err != nil || !still {
			return err
		}
		var home uuid.UUID
		err = tx.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, *user).Scan(&home)
		if errors.Is(err, pgx.ErrNoRows) {
			// Forgotten already, by another hand: only the record is left.
			_, err = tx.Exec(ctx, forgetClosingSQL, sub)
			forgotten = err == nil
			return err
		}
		if err != nil {
			return err
		}
		if personal != nil {
			out.Workspace = *personal
			if err := scope(ctx, tx, *personal, uuid.Nil); err != nil {
				return err
			}
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)`, *personal).Scan(&exists); err != nil {
				return err
			}
			if exists {
				if err := lockWorkspaceAccess(ctx, tx, *personal); err != nil {
					return err
				}
				var left int
				if err := withQuarantine(ctx, tx, func() error {
					return tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id = $1`, *personal).Scan(&left)
				}); err != nil {
					return err
				}
				if left > 0 {
					return nil
				}
			}
		}
		if err := scope(ctx, tx, uuid.Nil, *user); err != nil {
			return err
		}
		var teams int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM workspace_memberships WHERE user_id = $1 AND tenant_id IS DISTINCT FROM $2`,
			*user, personal).Scan(&teams); err != nil {
			return err
		}
		if teams > 0 {
			return nil
		}
		if err := scope(ctx, tx, home, uuid.Nil); err != nil {
			return err
		}
		// The person's row last, after the workspace's (DB23's order).
		var disabled bool
		if err := tx.QueryRow(ctx, `SELECT status = 'disabled' FROM users WHERE id = $1 FOR UPDATE`, *user).Scan(&disabled); err != nil || !disabled {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, *user); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, forgetClosingSQL, sub); err != nil {
			return err
		}
		forgotten = true
		return nil
	})
	return out, forgotten, err
}

// forgetClosingSQL marks a closing ($1) forgotten: the record keeps the
// sub and the times only, for its 13 months.
const forgetClosingSQL = `UPDATE contract_closings SET forgotten_at = clock_timestamp(), user_id = NULL, personal_workspace = NULL
	WHERE sub = $1`

// ClosingUnsubscribed records that the platform's unsubscribe of a
// forgotten account was sent and answered.
func (c *Contract) ClosingUnsubscribed(ctx context.Context, sub uuid.UUID) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_closings SET unsubscribed_at = clock_timestamp()
		WHERE sub = $1 AND forgotten_at IS NOT NULL AND unsubscribed_at IS NULL`, sub)
	return err
}

// PendingClosings lists, at most limit of each, the closings to confirm,
// those confirmed and not forgotten yet (ForgetClosed decides whether their
// purge is done), and those forgotten whose unsubscribe is not sent.
func (c *Contract) PendingClosings(ctx context.Context, limit int) (confirm, forget, unsubscribe []uuid.UUID, err error) {
	for _, q := range []struct {
		where string
		into  *[]uuid.UUID
	}{
		{`confirmed_at IS NULL`, &confirm},
		{`confirmed_at IS NOT NULL AND forgotten_at IS NULL AND purge_due_at <= clock_timestamp()`, &forget},
		{`forgotten_at IS NOT NULL AND unsubscribed_at IS NULL`, &unsubscribe},
	} {
		rows, err := c.pool.Query(ctx, `SELECT sub FROM contract_closings WHERE `+q.where+` ORDER BY seen_at, sub LIMIT $1`, limit)
		if err != nil {
			return nil, nil, nil, err
		}
		if *q.into, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
			return nil, nil, nil, err
		}
	}
	return confirm, forget, unsubscribe, nil
}

// RetainClosings deletes the records of closings forgotten over 13 months
// ago: the sub and the times are all they keep.
func (c *Contract) RetainClosings(ctx context.Context) (int64, error) {
	tag, err := c.pool.Exec(ctx, `DELETE FROM contract_closings
		WHERE forgotten_at IS NOT NULL AND forgotten_at < clock_timestamp() - interval '13 months'`)
	return tag.RowsAffected(), err
}
