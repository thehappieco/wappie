package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/store"
)

// The owner's strand override (decision 0040; the plan's DB13, with DB2's
// gate as the owner confirmed it on 2026-10-14): test 13's release B part.

// contractGate puts the contract in a mode, and records the world's team
// as a platform workspace (status, "" for none) or forgets it (recorded
// false).
func (w *delWorld) contractGate(t *testing.T, mode string, observed, recorded bool, status string) {
	t.Helper()
	ctx := context.Background()
	switch {
	case mode == "observe":
		w.exec(t, `UPDATE contract_state SET mode = 'observe', events_from = coalesce(events_from, clock_timestamp()), events_paused_at = NULL`)
	case observed:
		w.exec(t, `UPDATE contract_state SET mode = 'off', events_from = coalesce(events_from, clock_timestamp()), events_paused_at = clock_timestamp()`)
	default:
		w.exec(t, `UPDATE contract_state SET mode = 'off', events_from = NULL, events_paused_at = NULL`)
	}
	w.exec(t, `DELETE FROM contract_workspaces WHERE workspace_id = $1`, w.tenant)
	if recorded {
		var s *string
		if status != "" {
			s = &status
		}
		if _, err := w.pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind, status) VALUES ($1, 'team', $2)`, w.tenant, s); err != nil {
			t.Fatal(err)
		}
	}
}

func (w *delWorld) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := w.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// strandedRow is a stranded item_events row as a test reads it.
type strandedRow struct {
	person, actorSub, actorUser *uuid.UUID
	cause, actorKind            string
	readerSubs, readerUsers     []uuid.UUID
	label, hint                 *string
	ledgered                    bool
	occurredAt                  time.Time
}

func (w *delWorld) stranded(t *testing.T, device uuid.UUID) []strandedRow {
	t.Helper()
	ctx := context.Background()
	var out []strandedRow
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT person_sub, actor_sub, actor_user_id, coalesce(cause, ''), actor_kind, reader_subs,
			reader_user_ids, label, hint, ledgered_at IS NOT NULL, occurred_at
			FROM item_events WHERE item_id = $1 AND type = 'stranded' ORDER BY seq`, device)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (strandedRow, error) {
			var r strandedRow
			err := row.Scan(&r.person, &r.actorSub, &r.actorUser, &r.cause, &r.actorKind, &r.readerSubs, &r.readerUsers,
				&r.label, &r.hint, &r.ledgered, &r.occurredAt)
			return r, err
		})
		return err
	})
	return out
}

// noticesOfKind are user's unseen notices of kind.
func (w *delWorld) noticesOfKind(t *testing.T, user uuid.UUID, kind string) []store.DeviceNotice {
	t.Helper()
	var out []store.DeviceNotice
	for _, n := range w.notices(t, user) {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

func TestStrandDeletedOverride(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	ownerSub := linkSub(t, w.pool, w.owner)
	admin := w.person(t, "admin", "admin")
	coOwner := w.person(t, "co-owner", "owner")
	member := w.person(t, "member", "member")
	disabled := w.person(t, "disabled", "member")
	// target reads the deleted number alone, as its last key holder, and has
	// a platform sub; bystander, who reads nothing, stays.
	target := w.person(t, "target", "member")
	targetSub := linkSub(t, w.pool, target)
	device := w.number(t, "Suporte")
	w.reads(t, target, device)
	q := w.quarantine(t, device, target)
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, disabled, "member", "disabled"); err != nil {
		t.Fatal(err)
	}
	// A live number's last reader is never stranded, the gate open.
	liveTarget := w.person(t, "live", "member")
	live := w.number(t, "Vivo")
	w.reads(t, liveTarget, live)
	w.contractGate(t, "observe", true, true, "open")
	if err := w.users.UpdateMemberStrandDeleted(ctx, w.tenant, w.owner, liveTarget, "member", "disabled"); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("a live number's last reader, disabled with the flag: %v", err)
	}
	if err := w.users.RemoveMemberStrandDeleted(ctx, w.tenant, w.owner, liveTarget); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("a live number's last reader, removed with the flag: %v", err)
	}

	acts := map[string]func(actor uuid.UUID) error{
		"disable": func(actor uuid.UUID) error {
			return w.users.UpdateMemberStrandDeleted(ctx, w.tenant, actor, target, "member", "disabled")
		},
		"remove": func(actor uuid.UUID) error { return w.users.RemoveMemberStrandDeleted(ctx, w.tenant, actor, target) },
	}
	unchanged := func(what string) {
		t.Helper()
		if n := w.count(t, `SELECT count(*) FROM workspace_memberships WHERE user_id=$1 AND tenant_id=$2 AND status='active'`, target, w.tenant); n != 1 {
			t.Fatalf("%s changed the membership", what)
		}
		if n := w.count(t, `SELECT count(*) FROM device_key_grants WHERE user_id=$1`, target); n != 1 {
			t.Fatalf("%s changed the grants", what)
		}
		if n := w.count(t, `SELECT count(*) FROM item_events WHERE type='stranded'`); n != 0 {
			t.Fatalf("%s recorded a stranding", what)
		}
		if n := w.count(t, `SELECT count(*) FROM device_notices WHERE kind='number_stranded'`); n != 0 {
			t.Fatalf("%s raised a notice", what)
		}
	}

	// Where the platform will not mail the other owners, the flag is
	// ignored and release A's refusal stands, the owner's list with it.
	for _, gate := range []struct {
		name               string
		mode               string
		observed, recorded bool
		status             string
	}{
		{"off before the first observe", "off", false, true, "open"},
		{"off after an observe", "off", true, true, "open"},
		{"observing, the team unnamed", "observe", true, false, ""},
		{"observing, the team closed on the platform", "observe", true, true, "closed"},
	} {
		w.contractGate(t, gate.mode, gate.observed, gate.recorded, gate.status)
		for name, act := range acts {
			var refused *store.ErrLastReaderOfDeleted
			if err := act(w.owner); !errors.As(err, &refused) || len(refused.Numbers) != 1 || refused.Numbers[0].DeviceID != device {
				t.Fatalf("%s, %s by an owner with the flag: %v", gate.name, name, err)
			}
		}
		unchanged(gate.name)
	}

	// Observing, in a team the platform names.
	w.contractGate(t, "observe", true, true, "")
	for name, act := range acts {
		// Only an owner: an admin gets owner_only, the gate open or not.
		if err := act(admin); !errors.Is(err, store.ErrOwnerOnly) {
			t.Fatalf("%s by an admin with the flag: %v", name, err)
		}
	}
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, target, "member", "disabled"); !errors.As(err, new(*store.ErrLastReaderOfDeleted)) {
		t.Fatalf("an owner without the flag: %v", err)
	}
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, target); !errors.As(err, new(*store.ErrLastReaderOfDeleted)) {
		t.Fatalf("an owner's removal without the flag: %v", err)
	}
	unchanged("an admin, or no flag")

	// The owner's disable goes on.
	if err := acts["disable"](w.owner); err != nil {
		t.Fatalf("the owner's disable with the flag: %v", err)
	}
	if n := w.count(t, `SELECT count(*) FROM workspace_memberships WHERE user_id=$1 AND tenant_id=$2 AND status='disabled'`, target, w.tenant); n != 1 {
		t.Fatal("the target is not disabled")
	}
	if n := w.count(t, `SELECT count(*) FROM device_key_grants WHERE user_id=$1`, target); n != 0 {
		t.Fatal("the target kept the grant")
	}
	// The number keeps its 30 days.
	var purgeAfter time.Time
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT purge_after FROM devices WHERE id=$1 AND deleted_at IS NOT NULL`, device).Scan(&purgeAfter)
	})
	if !purgeAfter.Equal(q.PurgeAfter) {
		t.Fatalf("purge_after moved: %v, was %v", purgeAfter, q.PurgeAfter)
	}
	rows := w.stranded(t, device)
	if len(rows) != 1 {
		t.Fatalf("%d stranded rows, want one", len(rows))
	}
	r := rows[0]
	if r.person == nil || *r.person != targetSub || r.cause != "disabled" || r.actorKind != "person" ||
		r.actorSub == nil || *r.actorSub != ownerSub || r.actorUser == nil || *r.actorUser != w.owner || !r.ledgered {
		t.Fatalf("the stranded row: %+v", r)
	}
	// Its readers are the number's just before: the target.
	if !sameSubs(r.readerSubs, targetSub) || !sameSubs(r.readerUsers, target) {
		t.Fatalf("the readers: %v %v", r.readerSubs, r.readerUsers)
	}
	if r.label == nil || *r.label != "Suporte" || r.hint == nil || *r.hint == "" {
		t.Fatalf("the label: %v %v", r.label, r.hint)
	}
	// The other active owner is told, until the purge; the actor, the
	// target, an admin, a member and a disabled member are not.
	got := w.noticesOfKind(t, coOwner, store.NoticeNumberStranded)
	if len(got) != 1 || got[0].DeviceID != device || got[0].Until == nil || !got[0].Until.Equal(q.PurgeAfter) ||
		got[0].Label == nil || *got[0].Label != "Suporte" || got[0].RaisedByKind != "person" || got[0].RaisedByName == nil {
		t.Fatalf("the co-owner's notices: %+v", got)
	}
	for _, other := range []uuid.UUID{w.owner, target, admin, member, disabled} {
		if n := w.count(t, `SELECT count(*) FROM device_notices WHERE user_id=$1 AND kind='number_stranded'`, other); n != 0 {
			t.Fatalf("%s got a stranded notice", other)
		}
	}

	// A removal, of a target with no sub: person null, cause revoked; one
	// more row, for this number.
	noSub := w.person(t, "no-sub", "member")
	second := w.number(t, "Vendas")
	w.reads(t, noSub, second)
	w.quarantine(t, second, noSub)
	if err := acts["remove"](w.owner); err != nil {
		t.Fatalf("removing the disabled target, who strands nothing now: %v", err)
	}
	if n := len(w.stranded(t, device)); n != 1 {
		t.Fatalf("an act that strands nothing recorded a row: %d", n)
	}
	if err := w.users.RemoveMemberStrandDeleted(ctx, w.tenant, w.owner, noSub); err != nil {
		t.Fatalf("the owner's removal with the flag: %v", err)
	}
	if n := w.count(t, `SELECT count(*) FROM workspace_memberships WHERE user_id=$1 AND tenant_id=$2`, noSub, w.tenant); n != 0 {
		t.Fatal("the target is still a member")
	}
	rows = w.stranded(t, second)
	if len(rows) != 1 || rows[0].person != nil || rows[0].cause != "revoked" || len(rows[0].readerSubs) != 0 ||
		!sameSubs(rows[0].readerUsers, noSub) {
		t.Fatalf("a removal's stranded row: %+v", rows)
	}
	if n := len(w.noticesOfKind(t, coOwner, store.NoticeNumberStranded)); n != 2 {
		t.Fatalf("the co-owner has %d stranded notices, want two", n)
	}

	// An owner who held the last key, disabled by the other: the owners
	// told are the third, never the target.
	ownerTarget := w.person(t, "owner-target", "owner")
	third := w.number(t, "Financeiro")
	w.reads(t, ownerTarget, third)
	w.quarantine(t, third, ownerTarget)
	if err := w.users.UpdateMemberStrandDeleted(ctx, w.tenant, w.owner, ownerTarget, "owner", "disabled"); err != nil {
		t.Fatalf("disabling an owner with the flag: %v", err)
	}
	if rows := w.stranded(t, third); len(rows) != 1 || rows[0].cause != "disabled" || !sameSubs(rows[0].readerUsers, ownerTarget) {
		t.Fatalf("an owner's stranding: %+v", rows)
	}
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE user_id=$1 AND kind='number_stranded'`, ownerTarget); n != 0 {
		t.Fatalf("the disabled owner got %d stranded notices", n)
	}
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE device_id=$1 AND kind='number_stranded'`, third); n != 1 {
		t.Fatalf("%d notices of the owner's stranding, want the co-owner's", n)
	}

	// Recovered, the number has nobody who can open its history.
	r2, err := w.devices.Recover(ctx, w.tenant, w.owner, second)
	if err != nil {
		t.Fatal(err)
	}
	if r2.KeyHolders != 0 {
		t.Fatalf("a stranded number recovered with %d key holders", r2.KeyHolders)
	}
}

// The gate's share lock (ownersMailedTx): a switch to off that comes while
// an override is in flight waits for its commit, so the stranded row is
// never written in an off period, and the override, having read the gate
// open, goes on.
func TestStrandOverrideHoldsTheMode(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	target := w.person(t, "target", "member")
	device := w.number(t, "Suporte")
	w.reads(t, target, device)
	w.quarantine(t, device, target)
	w.contractGate(t, "observe", true, true, "")
	// A blocker holds the workspace, so the override waits there, holding
	// the gate's share lock.
	blocker, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE`, w.tenant); err != nil {
		t.Fatal(err)
	}
	blockerPID := int(blocker.Conn().PgConn().PID())
	done := make(chan error, 1)
	go func() { done <- w.users.RemoveMemberStrandDeleted(ctx, w.tenant, w.owner, target) }()
	waitBlocked(t, w, blockerPID, 1)
	switched := make(chan error, 1)
	go func() {
		_, err := store.NewContract(w.pool).SetMode(ctx, store.ContractOff)
		switched <- err
	}()
	// The switch waits behind the override, which waits behind the blocker.
	waitBlocked(t, w, blockerPID, 2)
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the override: %v", err)
	}
	if err := <-switched; err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, `SELECT count(*) FROM item_events e, contract_state s WHERE e.type = 'stranded' AND e.created_at < s.events_paused_at`); n != 1 {
		t.Fatalf("%d stranded rows written before the switch, want one", n)
	}
}
