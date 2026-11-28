package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
	"whatserver2/internal/wa"
)

// Trial codes, item.linked, item.identity_updated and placed_at on Wappie's
// side (migration 0054; the platform's spec, sections 15.5, 15.10 to
// 15.12; E0 slice 19). The rows are written whatever the entitlements mode
// says, in the transaction of the act that makes them; no code is ever
// stored: internal/membership makes each at send time from the number's
// phone number and LID, and a row whose number makes none, or that goes
// while K_app is not usable, settles not_sent (EventsNotSent).
//
// Every writer of these rows holds its workspace's row (tenants, FOR
// UPDATE) before it writes, as every other writer of item_events does, so
// seq order within a workspace is commit order.

// The classes of slice 19's ERRORs, kept by RecordError.
const (
	// ContractErrorTrialKey: K_app does not open (a class only), or its
	// envelope is on the retired list.
	ContractErrorTrialKey = "trial_key"
	// ContractErrorEventRecord: an item.linked or item.identity_updated
	// could not be written; the daily catch-up covers the number.
	ContractErrorEventRecord = "event_record"
)

// The codes switch (contract_trial_key_state.codes).
const (
	TrialCodesOn        = "on"
	TrialCodesSuspended = "suspended"
)

// The acts a link check is made for (contract_link_checks.act).
const (
	LinkActLink = "link"
	LinkActMove = "move"
)

// LinkCheckFor is how long contract_link_checks keeps a check, and the
// window contract status counts.
const LinkCheckFor = 24 * time.Hour

// ErrTrialKeyExists is init's refusal: a key is installed already, and it
// is never rotated (spec 15.10).
var ErrTrialKeyExists = errors.New("store: a trial key is installed already")

// lockWorkspaceTx takes the workspace's row FOR UPDATE, as every writer of
// item_events does before it writes; false when Wappie has no such
// workspace.
func lockWorkspaceTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) (bool, error) {
	tag, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, tenant)
	return tag.RowsAffected() == 1, err
}

// inWorkspaceTx runs fn with tx's row-level security on tenant, and puts
// back the workspace tx had: a document's apply runs outside any.
func inWorkspaceTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, fn func() error) error {
	var was string
	if err := tx.QueryRow(ctx, `SELECT coalesce(current_setting($1, true), '')`, pg.TenantGUC).Scan(&was); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, tenant.String()); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, was)
	return err
}

// identityArgs are the two halves of id as devices stores them, nil for a
// half not known.
func identityArgs(id wa.Identity) (pn, lid *string) {
	if !id.PN.IsEmpty() {
		s := id.PN.String()
		pn = &s
	}
	if !id.LID.IsEmpty() {
		s := id.LID.String()
		lid = &s
	}
	return pn, lid
}

// RecordLinked records a new link of device in tenant (spec 15.12, the
// table's first row): in one transaction, under the workspace's row, the
// number's identity from the paired session (COALESCE, as SetIdentity: the
// QR channel's success may come before PairSuccess persists it, so the
// event's render never waits on that write), placed_at the commit's time,
// and item.linked. actor is the person who linked it, or nil for a full
// key's pairing (actor null). It returns placed_at. A pairing never fails
// for it: the caller retries and the daily catch-up covers the number; a
// retry of a link already recorded (its commit's answer lost) writes
// nothing and returns the recorded placed_at.
func (c *Contract) RecordLinked(ctx context.Context, tenant, device uuid.UUID, actor *uuid.UUID, id wa.Identity) (time.Time, error) {
	var placed time.Time
	pn, lid := identityArgs(id)
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		if ok, err := lockWorkspaceTx(ctx, tx, tenant); err != nil || !ok {
			if err == nil {
				err = ErrNotFound
			}
			return err
		}
		// A retry after a commit whose answer was lost finds its own row:
		// the number's placed_at is that item.linked's, and nothing is
		// written twice.
		err := tx.QueryRow(ctx, `SELECT d.placed_at FROM devices d WHERE d.id = $2 AND d.placed_at IS NOT NULL
			AND EXISTS (SELECT 1 FROM item_events e WHERE e.tenant_id = $1 AND e.item_id = d.id AND e.type = 'linked'
			            AND e.occurred_at = d.placed_at)`, tenant, device).Scan(&placed)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var name, phone string
		err = tx.QueryRow(ctx, `UPDATE devices SET pn = coalesce(pn, $2), lid = coalesce(lid, $3), placed_at = clock_timestamp()
			WHERE id = $1 RETURNING placed_at, label, coalesce(pn, '')`, device, pn, lid).Scan(&placed, &name, &phone)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrNotFound, device)
		}
		if err != nil {
			return err
		}
		var sub *uuid.UUID
		if actor != nil {
			if sub, err = actorSubTx(ctx, tx, *actor); err != nil {
				return err
			}
		}
		itemName, hint := itemLabel(device, name, phone)
		return recordEvent(ctx, tx, tenant, itemEvent{
			Type: eventLinked, ItemID: device, DedupeKey: dedupeKey(eventLinked, device, placed), OccurredAt: placed,
			ActorKind: actorPerson, ActorSub: sub, ActorUserID: actor, Label: itemName, Hint: hint,
		})
	})
	return placed, err
}

// identityUpdatedTx records item.identity_updated at at for each of
// devices, in the workspace of tx (its row locked by the caller), with the
// actor given (app, or a person with their sub). A device gone since is
// skipped. It returns how many it recorded.
func identityUpdatedTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, devices []uuid.UUID, at time.Time,
	kind string, actor *uuid.UUID) (int, error) {
	if len(devices) == 0 {
		return 0, nil
	}
	var sub *uuid.UUID
	if actor != nil {
		var err error
		if sub, err = actorSubTx(ctx, tx, *actor); err != nil {
			return 0, err
		}
	}
	rows, err := tx.Query(ctx, `SELECT id, label, coalesce(pn, '') FROM devices WHERE id = ANY ($1) ORDER BY id`, devices)
	if err != nil {
		return 0, err
	}
	type number struct {
		id       uuid.UUID
		name, pn string
	}
	found, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (number, error) {
		var n number
		return n, row.Scan(&n.id, &n.name, &n.pn)
	})
	if err != nil {
		return 0, err
	}
	for _, n := range found {
		itemName, hint := itemLabel(n.id, n.name, n.pn)
		if err := recordEvent(ctx, tx, tenant, itemEvent{
			Type: eventIdentityUpdated, ItemID: n.id, DedupeKey: dedupeKey(eventIdentityUpdated, n.id, at), OccurredAt: at,
			ActorKind: kind, ActorSub: sub, ActorUserID: actor, Label: itemName, Hint: hint,
		}); err != nil {
			return 0, err
		}
	}
	return len(found), nil
}

// unlistedNumbersTx are the workspace of tx's linked, hosted, not deleted
// numbers with an identity (a phone number or a LID) that listed does not
// name, in id order: the numbers a document's or a recovery's
// item.identity_updated goes for (spec 15.12). Wappie hosts every number
// it holds; a deleted one is left out explicitly, since a recovery reads
// with deleted numbers visible.
func unlistedNumbersTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, listed []string) ([]uuid.UUID, error) {
	if listed == nil {
		listed = []string{}
	}
	rows, err := tx.Query(ctx, `SELECT id FROM devices WHERE tenant_id = $1 AND deleted_at IS NULL
		AND (pn IS NOT NULL OR lid IS NOT NULL) AND NOT (id::text = ANY ($2)) ORDER BY id`, tenant, listed)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// itemIDs are the ids a document's items list.
func itemIDs(items []kc.ItemTrial) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.ID)
	}
	return out
}

// CodesAfterDue reports whether a document's requests.codes_after asks for
// codes: set, and later than the last one answered for the workspace (nil:
// none answered, or a reset forgot it). wire-entitlements.json's
// codes_after.
func CodesAfterDue(lastAnswered, codesAfter *time.Time) bool {
	return codesAfter != nil && (lastAnswered == nil || codesAfter.After(*lastAnswered))
}

// entCodesPrev is what a document row held before an apply, for the
// triggers of item.identity_updated.
type entCodesPrev struct {
	// Applied: a document was applied for the workspace before (applied_at
	// set); Trial: that document's trial_ends_at.
	Applied         bool
	Trial           *time.Time
	Answered        *time.Time
	FirstAfterReset bool
}

// TrialDocumentDue reports whether applying a document whose trial_ends_at
// is trial asks for item.identity_updated by its trial (spec 15.12): set,
// when the last document applied had none, none was applied, or it is the
// first applied after a reset.
func trialDocumentDue(prev entCodesPrev, trial *time.Time) bool {
	return trial != nil && (!prev.Applied || prev.Trial == nil || prev.FirstAfterReset)
}

// entCodesTx is the document triggers of item.identity_updated, in an
// apply's transaction (CommitEntPage, EntGotDoc, the late apply of a
// naming), so the obligation survives a crash: when doc, just applied for
// ws, asks for codes by its trial or its codes_after, one
// item.identity_updated, at the apply's time, for each linked hosted
// number of ws its items do not list. codes_after_answered is then set and
// first_after_reset cleared. It returns how many it recorded.
func entCodesTx(ctx context.Context, tx pgx.Tx, ws uuid.UUID, doc kc.EntitlementsDoc, prev entCodesPrev) (int, error) {
	var trial, after *time.Time
	if doc.State.TrialEndsAt != nil {
		trial = &doc.State.TrialEndsAt.Time
	}
	if doc.Requests.CodesAfter != nil {
		after = &doc.Requests.CodesAfter.Time
	}
	byTrial, byCodes := trialDocumentDue(prev, trial), CodesAfterDue(prev.Answered, after)
	n := 0
	if byTrial || byCodes {
		err := inWorkspaceTx(ctx, tx, ws, func() error {
			ok, err := lockWorkspaceTx(ctx, tx, ws)
			if err != nil || !ok {
				return err
			}
			numbers, err := unlistedNumbersTx(ctx, tx, ws, itemIDs(doc.Items))
			if err != nil {
				return err
			}
			var at time.Time
			if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
				return err
			}
			n, err = identityUpdatedTx(ctx, tx, ws, numbers, at, actorApp, nil)
			return err
		})
		if err != nil {
			return 0, fmt.Errorf("store: a document's item.identity_updated: %w", err)
		}
	}
	_, err := tx.Exec(ctx, `UPDATE contract_ent_docs SET first_after_reset = false,
		codes_after_answered = CASE WHEN $2 THEN $3 ELSE codes_after_answered END WHERE workspace_id = $1`, ws, byCodes, after)
	return n, err
}

// SetIdentity's event: identityLearnedTx records item.identity_updated for
// device when the update just learned a half of its identity (a LID, or a
// phone number, seen after pairing: spec 15.12) and the number was linked
// (placed_at, or an item.linked row). It runs inside a savepoint: a failed
// insert is rolled back to it, logged at ERROR with ids only and recorded,
// and the identity's write still commits; the daily catch-up then covers
// the number.
func identityLearnedTx(ctx context.Context, tx pgx.Tx, tenant, device uuid.UUID, placed bool, onFail func()) error {
	if !placed {
		var linked bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM item_events WHERE tenant_id = $1 AND item_id = $2 AND type = 'linked')`,
			tenant, device).Scan(&linked); err != nil {
			return err
		}
		if !linked {
			return nil
		}
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	err = func() error {
		var at time.Time
		if err := sp.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
			return err
		}
		_, err := identityUpdatedTx(ctx, sp, tenant, []uuid.UUID{device}, at, actorApp, nil)
		return err
	}()
	if err != nil {
		if rerr := sp.Rollback(ctx); rerr != nil {
			return rerr
		}
		obs.LoggerFrom(ctx).Error("contract: an item.identity_updated could not be written; the catch-up covers the number",
			"workspace", tenant, "device", device)
		if onFail != nil {
			onFail()
		}
		return nil
	}
	return sp.Commit(ctx)
}

// recoveryCodesTx is a recovery's trigger (spec 15.12, P1's literal
// reading): in the recovery's transaction, when the workspace's applied
// document has state.trial_ends_at, one item.identity_updated at the
// recovery's time for each linked hosted number of the workspace the
// document's items do not list, the recovered one included, the recoverer
// its actor.
func recoveryCodesTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, at time.Time, actor uuid.UUID) error {
	var raw []byte
	var trial *time.Time
	err := tx.QueryRow(ctx, `SELECT doc, trial_ends_at FROM contract_ent_docs WHERE workspace_id = $1 AND applied_at IS NOT NULL`,
		tenant).Scan(&raw, &trial)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && trial == nil) {
		return nil
	}
	if err != nil {
		return err
	}
	var doc kc.EntitlementsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("store: the applied document of a recovery's workspace: %w", err)
	}
	numbers, err := unlistedNumbersTx(ctx, tx, tenant, itemIDs(doc.Items))
	if err != nil {
		return err
	}
	_, err = identityUpdatedTx(ctx, tx, tenant, numbers, at, actorPerson, &actor)
	return err
}

// codesCatchUpSQL is the catch-up's predicate for a number d of workspace
// $1 (spec 15.12 "An item with no code"; P2): live, with an identity, in a
// workspace whose events go now (a row written now is owed: events
// observed, not paused, the workspace named), and either no row of the two
// types, or its newest row went with no codes: settled not_sent, delivered
// before the key now in use was made ($2, against settled_at: codes are
// made at send time, so a row delivered under the new key carried its
// codes), never owed (written in an off period, before the first observe
// or before the workspace's naming: it is never sent), or parked expired
// (or parked not_found past its 29 days). A number whose newest row is
// still owed, or parked not_found and still released by a release, is left
// to that row; one parked for any other refusal is left alone (a new row
// would be refused alike, each day).
var codesCatchUpSQL = `d.tenant_id = $1 AND d.deleted_at IS NULL AND (d.pn IS NOT NULL OR d.lid IS NOT NULL)
	AND EXISTS (SELECT 1 FROM contract_state s JOIN contract_workspaces w ON w.workspace_id = $1
	             WHERE s.events_from IS NOT NULL AND s.events_paused_at IS NULL
	               AND clock_timestamp() >= greatest(s.events_from, w.named_at))
	AND coalesce((SELECT CASE
	                  WHEN e.settled_at IS NOT NULL
	                    THEN e.outcome = 'not_sent' OR (e.outcome IN ('accepted', 'duplicate') AND e.settled_at < $2)
	                  WHEN e.parked_at IS NOT NULL
	                    THEN e.reject_code IN ('` + EventParkedExpired + `', '` + EventParkedNotFound + `') AND NOT (` + releasableEventSQL + `)
	                  ELSE NOT (` + owedEventSQL + `) END
	                FROM ` + owedFromSQL + `
	               WHERE e.tenant_id = $1 AND e.item_id = d.id AND e.type IN ('linked', 'identity_updated')
	               ORDER BY e.seq DESC LIMIT 1), true)`

// CodesCatchUpItem is a number the catch-up owes an item.identity_updated:
// its workspace, and the identity its codes are made from (never logged).
type CodesCatchUpItem struct {
	Workspace, Device uuid.UUID
	PN, LID           string
}

// CodesCatchUp lists, in one read-only snapshot, the numbers of every named
// workspace Wappie holds that the catch-up owes an item.identity_updated
// under the key made at keyMade, in workspace and id order.
func (c *Contract) CodesCatchUp(ctx context.Context, keyMade time.Time) ([]CodesCatchUpItem, error) {
	var out []CodesCatchUpItem
	err := pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		out = nil
		rows, err := tx.Query(ctx, `SELECT w.workspace_id FROM contract_workspaces w JOIN tenants t ON t.id = w.workspace_id
			ORDER BY w.workspace_id`)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, ws := range ids {
			if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, ws.String()); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT d.id, coalesce(d.pn, ''), coalesce(d.lid, '') FROM devices d
				WHERE `+codesCatchUpSQL+` ORDER BY d.id`, ws, keyMade)
			if err != nil {
				return err
			}
			items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (CodesCatchUpItem, error) {
				it := CodesCatchUpItem{Workspace: ws}
				return it, row.Scan(&it.Device, &it.PN, &it.LID)
			})
			if err != nil {
				return err
			}
			out = append(out, items...)
		}
		return nil
	})
	return out, err
}

// RecordCatchUp records the catch-up's item.identity_updated of device in
// ws, now, the app its actor, in its own transaction under the workspace's
// row, after checking again that it is still owed under the key made at
// keyMade; false when it is not (a row came meanwhile, the number went).
func (c *Contract) RecordCatchUp(ctx context.Context, ws, device uuid.UUID, keyMade time.Time) (bool, error) {
	recorded := false
	err := pg.InTenantTx(ctx, c.pool, ws.String(), func(tx pgx.Tx) error {
		recorded = false
		if ok, err := lockWorkspaceTx(ctx, tx, ws); err != nil || !ok {
			return err
		}
		var owed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices d WHERE d.id = $3 AND `+codesCatchUpSQL+`)`,
			ws, keyMade, device).Scan(&owed); err != nil || !owed {
			return err
		}
		var at time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
			return err
		}
		n, err := identityUpdatedTx(ctx, tx, ws, []uuid.UUID{device}, at, actorApp, nil)
		recorded = n == 1
		return err
	})
	return recorded, err
}

// EventsNotSent settles, in the workspace's queue, the item.linked and
// item.identity_updated rows named that go with no code (no usable K_app,
// codes suspended, or a number whose identity makes none, or is gone):
// not_sent, nothing sent (spec 15.12 "An item with no code"). It returns
// how many it settled.
func (c *Contract) EventsNotSent(ctx context.Context, workspace uuid.UUID, ids []uuid.UUID) (int, error) {
	n := 0
	err := retryDeadlock(ctx, func() error {
		n = 0
		return pg.InTenantTx(ctx, c.pool, workspace.String(), func(tx pgx.Tx) error {
			if _, ok, err := lockQueueTx(ctx, tx, workspace); err != nil || !ok {
				return err
			}
			tag, err := tx.Exec(ctx, `WITH x AS (SELECT seq FROM item_events WHERE tenant_id = $1 AND event_id = ANY ($2)
					AND type IN ('linked', 'identity_updated') AND settled_at IS NULL AND parked_at IS NULL ORDER BY seq FOR UPDATE)
				UPDATE item_events e SET settled_at = clock_timestamp(), outcome = 'not_sent' FROM x
				WHERE e.tenant_id = $1 AND e.seq = x.seq`, workspace, ids)
			n = int(tag.RowsAffected())
			return err
		})
	})
	return n, err
}

// eventIdentitiesTx gives each item.linked and item.identity_updated of
// events its number's phone number and LID, read with deleted numbers
// visible: its codes are made from them at send time. A purged number has
// none, and its row settles not_sent.
func eventIdentitiesTx(ctx context.Context, tx pgx.Tx, events []ContractEvent) error {
	var ids []uuid.UUID
	for _, e := range events {
		if e.Type == eventLinked || e.Type == eventIdentityUpdated {
			ids = append(ids, e.ItemID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return withQuarantine(ctx, tx, func() error {
		rows, err := tx.Query(ctx, `SELECT id, coalesce(pn, ''), coalesce(lid, '') FROM devices WHERE id = ANY ($1)`, ids)
		if err != nil {
			return err
		}
		type identity struct{ pn, lid string }
		found := map[uuid.UUID]identity{}
		err = forEachRow(rows, func(row pgx.Rows) error {
			var id uuid.UUID
			var i identity
			if err := row.Scan(&id, &i.pn, &i.lid); err != nil {
				return err
			}
			found[id] = i
			return nil
		})
		if err != nil {
			return err
		}
		for i := range events {
			if e := &events[i]; e.Type == eventLinked || e.Type == eventIdentityUpdated {
				e.PN, e.LID = found[e.ItemID].pn, found[e.ItemID].lid
			}
		}
		return nil
	})
}

// IsCodeEvent reports whether an item_events type carries trial codes:
// item.linked and item.identity_updated.
func IsCodeEvent(kind string) bool { return kind == eventLinked || kind == eventIdentityUpdated }

// TrialKeyState is contract_trial_key_state's one row, with whether a key
// is installed and its envelope's sha256 and creation time: what contract
// status shows of the key, read without opening it.
type TrialKeyState struct {
	Codes   string
	CodesAt time.Time
	// OpenedAt and EnvelopeSHA256 are wappie-api's last open; OpenError
	// and OpenErrorAt its last failure's class.
	OpenedAt       *time.Time
	EnvelopeSHA256 []byte
	OpenError      string
	OpenErrorAt    *time.Time
	// Installed: contract_trial_key holds a row; StoredSHA256 is its
	// envelope's, and KeyMade its creation.
	Installed    bool
	StoredSHA256 []byte
	KeyMade      *time.Time
}

// TrialKeyState reads the codes switch, the last open and the key's row.
func (c *Contract) TrialKeyState(ctx context.Context) (TrialKeyState, error) {
	var s TrialKeyState
	err := c.pool.QueryRow(ctx, `SELECT st.codes, st.codes_at, st.opened_at, st.envelope_sha256, coalesce(st.open_error, ''), st.open_error_at,
			k.id IS NOT NULL, sha256(k.envelope), k.created_at
		FROM contract_trial_key_state st LEFT JOIN contract_trial_key k ON true`).
		Scan(&s.Codes, &s.CodesAt, &s.OpenedAt, &s.EnvelopeSHA256, &s.OpenError, &s.OpenErrorAt, &s.Installed, &s.StoredSHA256, &s.KeyMade)
	return s, err
}

// TrialKeyEnvelope reads K_app's envelope and when it was made; false when
// none is installed.
func (c *Contract) TrialKeyEnvelope(ctx context.Context) ([]byte, time.Time, bool, error) {
	var envelope []byte
	var made time.Time
	err := c.pool.QueryRow(ctx, `SELECT envelope, created_at FROM contract_trial_key`).Scan(&envelope, &made)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, time.Time{}, false, nil
	}
	return envelope, made, err == nil, err
}

// InitTrialKey installs K_app's envelope, once: ErrTrialKeyExists when a
// key is installed already (spec 15.10: never rotated).
func (c *Contract) InitTrialKey(ctx context.Context, envelope []byte) error {
	tag, err := c.pool.Exec(ctx, `INSERT INTO contract_trial_key (envelope) VALUES ($1) ON CONFLICT (id) DO NOTHING`, envelope)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTrialKeyExists
	}
	return nil
}

// SetTrialCodes switches codes on or suspended, and reports whether it
// changed; a switch notifies wappie-api (0054's contract_trial_key_mark).
func (c *Contract) SetTrialCodes(ctx context.Context, codes string) (bool, error) {
	if codes != TrialCodesOn && codes != TrialCodesSuspended {
		return false, fmt.Errorf("store: trial codes %q is not a switch", codes)
	}
	tag, err := c.pool.Exec(ctx, `UPDATE contract_trial_key_state SET codes = $1, codes_at = clock_timestamp() WHERE codes <> $1`, codes)
	return tag.RowsAffected() == 1, err
}

// TrialKeyOpened records wappie-api's open of the envelope whose sha256 is
// sum.
func (c *Contract) TrialKeyOpened(ctx context.Context, envelope []byte) error {
	sum := sha256.Sum256(envelope)
	_, err := c.pool.Exec(ctx, `UPDATE contract_trial_key_state SET opened_at = clock_timestamp(), envelope_sha256 = $1,
		open_error = NULL, open_error_at = NULL`, sum[:])
	return err
}

// TrialKeyOpenFailed records the class of a failed open (retired, kms,
// decrypt, ...), kept since its first time.
func (c *Contract) TrialKeyOpenFailed(ctx context.Context, class string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_trial_key_state SET open_error = $1,
		open_error_at = CASE WHEN open_error IS NOT DISTINCT FROM $1 THEN open_error_at ELSE clock_timestamp() END`, class)
	return err
}

// RecordLinkCheck keeps one link check for contract status: the workspace,
// the act, whether a signed answer came, and the first reason an enforcing
// release would refuse ("" for none). Checks older than LinkCheckFor go.
func (c *Contract) RecordLinkCheck(ctx context.Context, ws uuid.UUID, act string, answered bool, wouldRefuse string) error {
	var reason *string
	if wouldRefuse != "" {
		reason = &wouldRefuse
	}
	_, err := c.pool.Exec(ctx, `WITH old AS (DELETE FROM contract_link_checks WHERE at < clock_timestamp() - $5::interval)
		INSERT INTO contract_link_checks (workspace_id, act, answered, would_refuse) VALUES ($1, $2, $3, $4)`,
		ws, act, answered, reason, LinkCheckFor)
	return err
}

// LinkCheckCounts are the link checks of the last LinkCheckFor.
type LinkCheckCounts struct {
	Answered, Failed, WouldRefuse int
}

// LinkChecks counts the link checks of the last LinkCheckFor.
func (c *Contract) LinkChecks(ctx context.Context) (LinkCheckCounts, error) {
	var n LinkCheckCounts
	err := c.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE answered), count(*) FILTER (WHERE NOT answered),
		count(*) FILTER (WHERE would_refuse IS NOT NULL) FROM contract_link_checks WHERE at >= clock_timestamp() - $1::interval`,
		LinkCheckFor).Scan(&n.Answered, &n.Failed, &n.WouldRefuse)
	return n, err
}

// HostedNumbers is Wappie's own count of ws's places taken (spec 15.5):
// its numbers linked, not deleted and hosted, pending rows left out. E0
// counts no licence binding (slice 22).
func (c *Contract) HostedNumbers(ctx context.Context, ws uuid.UUID) (int64, error) {
	var n int64
	err := pg.InTenantTx(ctx, c.pool, ws.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id = $1 AND deleted_at IS NULL
			AND (lid IS NOT NULL OR pn IS NOT NULL OR last_connected_at IS NOT NULL)`, ws).Scan(&n)
	})
	return n, err
}

// EntGetNow makes ws's GET computed now due at once, for a link's check
// (spec 15.11; slice 17's gets), and wakes the leader's GETs wherever it
// runs ('ent_get' on the mode channel). A workspace with no row gets a
// placeholder.
func (c *Contract) EntGetNow(ctx context.Context, ws uuid.UUID) error {
	return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO contract_ent_docs (workspace_id, get_due_at) VALUES ($1, clock_timestamp())
			ON CONFLICT (workspace_id) DO UPDATE SET get_due_at = clock_timestamp()`, ws); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT pg_notify($1, 'ent_get')`, ContractModeChannel)
		return err
	})
}

// NumberIdentity reads device's phone number and LID in ws, "" for a half
// not known: a move's codes are made from the identity Wappie holds (spec
// 15.10). Personal data: never logged.
func (c *Contract) NumberIdentity(ctx context.Context, ws, device uuid.UUID) (pn, lid string, err error) {
	err = pg.InTenantTx(ctx, c.pool, ws.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(pn, ''), coalesce(lid, '') FROM devices WHERE id = $1`, device).Scan(&pn, &lid)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", fmt.Errorf("%w: %s", ErrNotFound, device)
	}
	return pn, lid, err
}
