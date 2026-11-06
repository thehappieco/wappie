package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/pg"
	"whatserver2/internal/wa"
)

// A relink links a logged-out number again, into the same row (decision
// 0057): its id, key, epoch, grants, readers and receipt mode stay. The
// pairing lives in memory (internal/wa); the row changes only in
// AttachRelink, once WhatsApp confirmed the link of the number's own
// account.

var (
	// ErrRelinkStateChanged is a number that is no longer one to link
	// again: deleted, moved, paused since, no longer logged out, or its
	// workspace no longer active.
	ErrRelinkStateChanged = errors.New("store: the number changed during the relink")
	// ErrRelinkNumberHeld is an account another live number of the
	// workspace holds.
	ErrRelinkNumberHeld = errors.New("store: this WhatsApp account is linked here as another number")
	// ErrRelinkNoSession is a new link whose session is not stored.
	ErrRelinkNoSession = errors.New("store: the new link's session is not stored")
)

// RelinkRow is what a relink judges a number on.
type RelinkRow struct {
	ID, TenantID uuid.UUID
	// Identity is as stored: device JIDs, either half maybe empty.
	Identity     wa.Identity
	Status       wa.Status
	StatusReason string
	Paused       bool
	PauseCause   string
	PauseSeq     int64
	Epoch        int
	ReceiptMode  wa.ReceiptMode
}

// RelinkSeen is what the relink saw at its start, which the attach must
// find again.
type RelinkSeen struct{ PauseSeq int64 }

// Attached reports what the attach did besides naming the new link.
type Attached struct {
	// ResumedPause is a pause the attach lifted, with its open sync_paused
	// notices marked resumed.
	ResumedPause bool
	// OldSessionRemoved is a dead session row of the old link it deleted.
	OldSessionRemoved bool
}

// RelinkRow reads a live number. A deleted one, or one of another
// workspace, is ErrNotFound.
func (d *Devices) RelinkRow(ctx context.Context, tenant, device uuid.UUID) (RelinkRow, error) {
	var row RelinkRow
	var lid, pn string
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, tenant_id, coalesce(lid, ''), coalesce(pn, ''), status, status_reason,
			paused, coalesce(pause_cause, ''), pause_seq, current_epoch, receipt_mode
			FROM devices WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`, device, tenant).Scan(
			&row.ID, &row.TenantID, &lid, &pn, &row.Status, &row.StatusReason,
			&row.Paused, &row.PauseCause, &row.PauseSeq, &row.Epoch, &row.ReceiptMode)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelinkRow{}, fmt.Errorf("%w: %s", ErrNotFound, device)
	}
	if err != nil {
		return RelinkRow{}, fmt.Errorf("store: read a number to link again: %w", err)
	}
	row.Identity = wa.Identity{LID: parseJID(lid), PN: parseJID(pn)}
	return row, nil
}

// KeyHeld reports whether a person holds the number's key at its current
// epoch: the key-holder side of sole_key_holders (0051). A suspended person
// whose membership stands still holds it; a service account, a connection's
// service account and an expiring membership do not.
func (d *Devices) KeyHeld(ctx context.Context, tenant, device uuid.UUID) (bool, error) {
	var held bool
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM devices dv
			  JOIN device_archive_keys k ON k.device_id = dv.id AND k.epoch = dv.current_epoch AND k.retired_at IS NULL
			  JOIN device_key_grants g ON g.device_id = dv.id AND g.epoch = dv.current_epoch
			  JOIN workspace_memberships m ON m.tenant_id = dv.tenant_id AND m.user_id = g.user_id
			       AND m.status = 'active' AND m.expires_at IS NULL AND m.role <> 'service'
			  JOIN users u ON u.id = m.user_id AND u.status IN ('active', 'disabled') AND u.role <> 'service'
			 WHERE dv.id = $1 AND dv.tenant_id = $2 AND dv.current_epoch >= 1
			   AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = g.user_id))`,
			device, tenant).Scan(&held)
	})
	if err != nil {
		return false, fmt.Errorf("store: who holds a number's key: %w", err)
	}
	return held, nil
}

// HeldElsewhere reports whether another live number of the workspace, not
// logged out and not banned, holds the account: the user part of its phone
// number or of its LID, whatever the device numbers. A paused number
// counts. Only this workspace is asked (spec 14.9, number_held).
func (d *Devices) HeldElsewhere(ctx context.Context, tenant, device uuid.UUID, account wa.Identity) (bool, error) {
	var held bool
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		held, err = heldElsewhereTx(ctx, tx, tenant, device, account)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("store: is the account linked as another number: %w", err)
	}
	return held, nil
}

func heldElsewhereTx(ctx context.Context, tx pgx.Tx, tenant, device uuid.UUID, account wa.Identity) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT coalesce(pn, ''), coalesce(lid, '') FROM devices
		WHERE tenant_id = $1 AND id <> $2 AND deleted_at IS NULL AND status NOT IN ('logged_out', 'banned')
		  AND (pn IS NOT NULL OR lid IS NOT NULL)`, tenant, device)
	if err != nil {
		return false, err
	}
	pairs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[struct{ PN, LID string }])
	if err != nil {
		return false, err
	}
	for _, p := range pairs {
		if sameAccountUser(parseJID(p.PN), account.PN) || sameAccountUser(parseJID(p.LID), account.LID) {
			return true, nil
		}
	}
	return false, nil
}

// sameAccountUser compares two JIDs by user and server, never by device.
func sameAccountUser(a, b types.JID) bool {
	return a.User != "" && a.User == b.User && a.Server == b.Server
}

// RelinkState is the relink's read of the number and its workspace, with no
// lock: ErrRelinkStateChanged unless the workspace is active and the number
// is live, logged out, paused no more since the start (pause_seq) and not
// held by a move; ErrStoragePaused when the workspace's storage is paused.
func (d *Devices) RelinkState(ctx context.Context, tenant, device uuid.UUID, seen RelinkSeen) error {
	return pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		return relinkStateTx(ctx, tx, tenant, device, seen, false)
	})
}

// RelinkRecheck is RelinkState, then ErrRelinkNumberHeld when another live
// number of the workspace holds the account. The check in the session
// store's first write of a new link runs it.
func (d *Devices) RelinkRecheck(ctx context.Context, tenant, device uuid.UUID, seen RelinkSeen, account wa.Identity) error {
	return pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := relinkStateTx(ctx, tx, tenant, device, seen, false); err != nil {
			return err
		}
		held, err := heldElsewhereTx(ctx, tx, tenant, device, account)
		if err != nil {
			return err
		}
		if held {
			return ErrRelinkNumberHeld
		}
		return nil
	})
}

// relinkStateTx reads the workspace, then the number, locking both when
// lock is set (tenants, then the device: the order Pause, MarkResumed, a
// deletion and a move take).
func relinkStateTx(ctx context.Context, tx pgx.Tx, tenant, device uuid.UUID, seen RelinkSeen, lock bool) error {
	forUpdate := ""
	if lock {
		forUpdate = " FOR UPDATE"
	}
	var status string
	var storagePaused bool
	err := tx.QueryRow(ctx, `SELECT status, storage_paused_at IS NOT NULL FROM tenants WHERE id = $1`+forUpdate, tenant).
		Scan(&status, &storagePaused)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRelinkStateChanged
	}
	if err != nil {
		return err
	}
	if status != "active" {
		return ErrRelinkStateChanged
	}
	if storagePaused {
		return ErrStoragePaused
	}
	var devStatus, cause string
	var pauseSeq int64
	err = tx.QueryRow(ctx, `SELECT status, pause_seq, coalesce(pause_cause, '') FROM devices
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`+forUpdate, device, tenant).Scan(&devStatus, &pauseSeq, &cause)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRelinkStateChanged
	}
	if err != nil {
		return err
	}
	if devStatus != string(wa.StatusLoggedOut) || pauseSeq != seen.PauseSeq || cause == PauseForMove {
		return ErrRelinkStateChanged
	}
	return nil
}

// AttachRelink writes a new link into the number, in one transaction that
// is a compare-and-set on what the relink saw at its start: the workspace
// active with its storage running, the number live, still logged out, not
// paused again since (pause_seq) and not held by a move, and the account
// held by no other live number of the workspace. It then names the new
// link (pn, lid, push name), marks the number offline until its client
// connects, lifts its pause with its open sync_paused notices marked
// resumed, and deletes what is left of the old link's session. Every other
// column, the key, the grants and the archive stay. It writes no
// item_events row: a relink is not a new link.
func (d *Devices) AttachRelink(ctx context.Context, tenant, device uuid.UUID, seen RelinkSeen, linked wa.Identity) (Attached, error) {
	var out Attached
	if linked.PN.IsEmpty() || linked.LID.IsEmpty() {
		return out, errors.New("store: a relink attaches both halves of the new link")
	}
	newPN, newLID := linked.PN.String(), linked.LID.String()
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := relinkStateTx(ctx, tx, tenant, device, seen, true); err != nil {
			return err
		}
		var oldPN, oldLID string
		var paused bool
		if err := tx.QueryRow(ctx, `SELECT coalesce(pn, ''), coalesce(lid, ''), paused FROM devices WHERE id = $1`,
			device).Scan(&oldPN, &oldLID, &paused); err != nil {
			return err
		}
		held, err := heldElsewhereTx(ctx, tx, tenant, device, linked)
		if err != nil {
			return err
		}
		if held {
			return ErrRelinkNumberHeld
		}
		stored, err := sessionStoredTx(ctx, tx, newPN)
		if err != nil {
			return err
		}
		if !stored {
			return ErrRelinkNoSession
		}
		// The devices_pause_cause trigger clears pause_cause with paused.
		_, err = tx.Exec(ctx, `UPDATE devices SET pn = $2, lid = $3,
			push_name = CASE WHEN $4 <> '' THEN $4 ELSE push_name END,
			status = 'offline', status_reason = 'linked again', paused = false
			WHERE id = $1`, device, newPN, newLID, linked.PushName)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrRelinkNumberHeld
		}
		if err != nil {
			return err
		}
		if paused {
			// MarkResumed's statement, in the attach: the notice and the
			// resume commit together.
			if _, err := tx.Exec(ctx, `UPDATE device_notices SET resumed_at = clock_timestamp()
				WHERE tenant_id = $1 AND device_id = $2 AND kind = 'sync_paused' AND resumed_at IS NULL AND seen_at IS NULL`,
				tenant, device); err != nil {
				return err
			}
			out.ResumedPause = true
		}
		for _, old := range []string{oldPN, oldLID} {
			if old == "" || old == newPN {
				continue
			}
			removed, err := deleteSessionTx(ctx, tx, old)
			if err != nil {
				return err
			}
			out.OldSessionRemoved = out.OldSessionRemoved || removed
		}
		if oldPN != "" && oldPN != newPN {
			return deletePrivacyTokensTx(ctx, tx, oldPN)
		}
		return nil
	})
	if err != nil {
		return Attached{}, err
	}
	return out, nil
}

// sessionStoredTx reports whether whatsmeow's session store holds a session
// under jid. No session table means none.
func sessionStoredTx(ctx context.Context, tx pgx.Tx, jid string) (bool, error) {
	var table bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('whatsmeow_device') IS NOT NULL`).Scan(&table); err != nil || !table {
		return false, err
	}
	var stored bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM whatsmeow_device WHERE jid = $1)`, jid).Scan(&stored)
	return stored, err
}

// deleteSessionTx deletes a dead session row of an old link, with
// whatsmeow's cascades. Normally there is none: the phone's logout made
// whatsmeow delete it, unless that delete failed.
func deleteSessionTx(ctx context.Context, tx pgx.Tx, jid string) (bool, error) {
	var table bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('whatsmeow_device') IS NOT NULL`).Scan(&table); err != nil || !table {
		return false, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid = $1`, jid)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ForgetDiscardedSession deletes the privacy tokens of a new link a refused
// attach logged out, which whatsmeow keeps with no foreign key, unless a
// session under that JID exists again.
func (d *Devices) ForgetDiscardedSession(ctx context.Context, tenant uuid.UUID, jid string) error {
	return pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		return deletePrivacyTokensTx(ctx, tx, jid)
	})
}

// MarkPausedOffline is a stop's display status: offline, "paused by
// request", unless the number is logged out or banned, which a pause keeps.
// It returns the status the number has after it, with its reason.
func (d *Devices) MarkPausedOffline(ctx context.Context, tenantID, deviceID string) (wa.Status, string, error) {
	var status, reason string
	err := pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE devices SET status = 'offline', status_reason = 'paused by request'
			WHERE id = $1 AND status NOT IN ('logged_out', 'banned') RETURNING status, status_reason`, deviceID).
			Scan(&status, &reason)
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(ctx, `SELECT status, status_reason FROM devices WHERE id = $1`, deviceID).Scan(&status, &reason)
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", fmt.Errorf("%w: %s", ErrNotFound, deviceID)
	}
	if err != nil {
		return "", "", fmt.Errorf("store: mark a paused number offline: %w", err)
	}
	return wa.Status(status), reason, nil
}
