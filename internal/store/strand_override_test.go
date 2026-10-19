package store_test

import (
	"context"
	"encoding/json"
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
// as a platform workspace of kind (status, "" for none) or forgets it (kind
// "").
func (w *delWorld) contractGate(t *testing.T, mode string, observed bool, kind, status string) {
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
	if kind != "" {
		var s *string
		if status != "" {
			s = &status
		}
		if _, err := w.pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind, status) VALUES ($1, $2, $3)`, w.tenant, kind, s); err != nil {
			t.Fatal(err)
		}
	}
}

// disableAccount disables user's account, in the workspace it was made in.
func (w *delWorld) disableAccount(t *testing.T, user uuid.UUID) {
	t.Helper()
	inTenantTx(context.Background(), t, w.pool, w.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(context.Background(), `UPDATE users SET status = 'disabled' WHERE id = $1`, user)
		if err == nil && tag.RowsAffected() != 1 {
			return errors.New("no such account")
		}
		return err
	})
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
	// Two owners who are not active: one's membership is disabled, the
	// other's account.
	disabledOwner := w.person(t, "disabled-owner", "owner")
	inactiveOwner := w.person(t, "inactive-owner", "owner")
	// target reads two deleted numbers alone, as their last key holder, and
	// has a platform sub.
	target := w.person(t, "target", "member")
	targetSub := linkSub(t, w.pool, target)
	device := w.number(t, "Suporte")
	w.reads(t, target, device)
	q := w.quarantine(t, device, target)
	other := w.number(t, "Atendimento")
	w.reads(t, target, other)
	qOther := w.quarantine(t, other, target)
	for u, role := range map[uuid.UUID]string{disabled: "member", disabledOwner: "owner"} {
		if err := w.users.UpdateMember(ctx, w.tenant, w.owner, u, role, "disabled"); err != nil {
			t.Fatal(err)
		}
	}
	w.disableAccount(t, inactiveOwner)
	targetsNumbers := func(refused *store.ErrLastReaderOfDeleted) bool {
		got := []uuid.UUID{}
		for _, n := range refused.Numbers {
			got = append(got, n.DeviceID)
		}
		return sameSubs(got, device, other)
	}
	// A live number's last reader is never stranded, the gate open.
	liveTarget := w.person(t, "live", "member")
	live := w.number(t, "Vivo")
	w.reads(t, liveTarget, live)
	w.contractGate(t, "observe", true, "team", "open")
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
		if n := w.count(t, `SELECT count(*) FROM device_key_grants WHERE user_id=$1`, target); n != 2 {
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
	// ignored and release A's refusal stands, the owner's list of both
	// numbers with it; an admin still gets owner_only.
	for _, gate := range []struct {
		name         string
		mode         string
		observed     bool
		kind, status string
	}{
		{"off before the first observe", "off", false, "team", "open"},
		{"off after an observe", "off", true, "team", "open"},
		{"observing, the team unnamed", "observe", true, "", ""},
		{"observing, the team closed on the platform", "observe", true, "team", "closed"},
		{"observing, recorded as personal", "observe", true, "personal", ""},
	} {
		w.contractGate(t, gate.mode, gate.observed, gate.kind, gate.status)
		for name, act := range acts {
			var refused *store.ErrLastReaderOfDeleted
			if err := act(w.owner); !errors.As(err, &refused) || !targetsNumbers(refused) {
				t.Fatalf("%s, %s by an owner with the flag: %v", gate.name, name, err)
			}
			if err := act(admin); !errors.Is(err, store.ErrOwnerOnly) {
				t.Fatalf("%s, %s by an admin with the flag: %v", gate.name, name, err)
			}
		}
		unchanged(gate.name)
	}

	// Observing, in a team the platform names.
	w.contractGate(t, "observe", true, "team", "")
	for name, act := range acts {
		// Only an owner: an admin gets owner_only here too.
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

	// The owner's disable goes on, stranding both numbers in one act.
	if err := acts["disable"](w.owner); err != nil {
		t.Fatalf("the owner's disable with the flag: %v", err)
	}
	if n := w.count(t, `SELECT count(*) FROM workspace_memberships WHERE user_id=$1 AND tenant_id=$2 AND status='disabled'`, target, w.tenant); n != 1 {
		t.Fatal("the target is not disabled")
	}
	if n := w.count(t, `SELECT count(*) FROM device_key_grants WHERE user_id=$1`, target); n != 0 {
		t.Fatal("the target kept the grant")
	}
	// Each number keeps its 30 days.
	purges := map[uuid.UUID]time.Time{device: q.PurgeAfter, other: qOther.PurgeAfter}
	for d, want := range purges {
		var purgeAfter time.Time
		w.scoped(t, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT purge_after FROM devices WHERE id=$1 AND deleted_at IS NOT NULL`, d).Scan(&purgeAfter)
		})
		if !purgeAfter.Equal(want) {
			t.Fatalf("purge_after moved: %v, was %v", purgeAfter, want)
		}
	}
	// One row per number, both at the act's one time.
	otherRows := w.stranded(t, other)
	rows := w.stranded(t, device)
	if len(rows) != 1 || len(otherRows) != 1 {
		t.Fatalf("%d and %d stranded rows, want one each", len(rows), len(otherRows))
	}
	if !otherRows[0].occurredAt.Equal(rows[0].occurredAt) || otherRows[0].cause != "disabled" ||
		otherRows[0].label == nil || *otherRows[0].label != "Atendimento" {
		t.Fatalf("the act's rows: %+v and %+v", rows[0], otherRows[0])
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
	// The other active owner is told of each, until its purge; the actor,
	// the target, an admin, a member, a disabled member, a disabled owner
	// and an owner whose account is disabled are not.
	got := w.noticesOfKind(t, coOwner, store.NoticeNumberStranded)
	labels := map[uuid.UUID]string{device: "Suporte", other: "Atendimento"}
	if len(got) != 2 {
		t.Fatalf("the co-owner's notices: %+v", got)
	}
	for _, n := range got {
		if n.Until == nil || !n.Until.Equal(purges[n.DeviceID]) || n.Label == nil || *n.Label != labels[n.DeviceID] ||
			n.RaisedByKind != "person" || n.RaisedByName == nil {
			t.Fatalf("a co-owner's notice: %+v", n)
		}
	}
	for _, u := range []uuid.UUID{w.owner, target, admin, member, disabled, disabledOwner, inactiveOwner} {
		if n := w.count(t, `SELECT count(*) FROM device_notices WHERE user_id=$1 AND kind='number_stranded'`, u); n != 0 {
			t.Fatalf("%s got a stranded notice", u)
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
	if n := len(w.noticesOfKind(t, coOwner, store.NoticeNumberStranded)); n != 3 {
		t.Fatalf("the co-owner has %d stranded notices, want three", n)
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

	// Recovered, the number has nobody who can open its history, and its
	// notice stays but names no purge; the numbers still deleted keep
	// theirs.
	r2, err := w.devices.Recover(ctx, w.tenant, w.owner, second)
	if err != nil {
		t.Fatal(err)
	}
	if r2.KeyHolders != 0 {
		t.Fatalf("a stranded number recovered with %d key holders", r2.KeyHolders)
	}
	got = w.noticesOfKind(t, coOwner, store.NoticeNumberStranded)
	if len(got) != 4 {
		t.Fatalf("after the recovery, the co-owner's notices: %+v", got)
	}
	for _, n := range got {
		if (n.DeviceID == second) != (n.Until == nil) {
			t.Fatalf("after the recovery of %s, a notice: %+v", second, n)
		}
	}
}

// The gate's share lock (holdOwnersMailedTx): a switch to off that comes
// while an override is in flight waits for its commit, so the stranded row
// is never written in an off period, and the override, having read the
// gate open, goes on.
func TestStrandOverrideHoldsTheMode(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	// The override waits for the blocker as long as the test takes.
	store.SetStrandLockTimeoutForTest(t, time.Minute)
	target := w.person(t, "target", "member")
	device := w.number(t, "Suporte")
	w.reads(t, target, device)
	w.quarantine(t, device, target)
	w.contractGate(t, "observe", true, "team", "")
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

// blockWorkspace holds w's workspace row, as another member change does,
// until the test rolls it back or ends; it answers its backend's pid.
func (w *delWorld) blockWorkspace(t *testing.T) (pgx.Tx, int) {
	t.Helper()
	ctx := context.Background()
	blocker, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocker.Rollback(context.Background()) })
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE`, w.tenant); err != nil {
		t.Fatal(err)
	}
	return blocker, int(blocker.Conn().PgConn().PID())
}

// A closed gate holds nothing (holdOwnersMailedTx): a flagged act that
// waits for the workspace keeps no switch of the mode waiting. Under the
// share lock it would, and a stream of such acts would starve every
// writer of contract_state, since each new share goes past the writer
// that waits.
func TestStrandGateClosedHoldsNothing(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	blocker, blockerPID := w.blockWorkspace(t)
	acts := make(chan error, 2)
	go func() {
		acts <- w.users.UpdateMemberStrandDeleted(ctx, w.tenant, w.owner, uuid.New(), "member", "disabled")
	}()
	go func() { acts <- w.users.RemoveMemberStrandDeleted(ctx, w.tenant, w.owner, uuid.New()) }()
	waitBlocked(t, w, blockerPID, 2)
	switched := make(chan error, 1)
	go func() {
		_, err := store.NewContract(w.pool).SetMode(ctx, store.ContractObserve)
		switched <- err
	}()
	select {
	case err := <-switched:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the switch waited for flagged acts at a closed gate")
	}
	select {
	case err := <-acts:
		t.Fatalf("an act went on with the workspace held: %v", err)
	default:
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-acts; !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a flagged act on nobody: %v", err)
		}
	}
}

// An open gate holds contract_state, so the act waits for each lock from
// then on for strandLockTimeout at most: one queued behind a long change
// to the workspace gives up (ErrWorkspaceBusy, nothing changed) and lets
// the switch of the mode through, the workspace still held.
func TestStrandOverrideGivesUpOnABusyWorkspace(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	target := w.person(t, "target", "member")
	device := w.number(t, "Suporte")
	w.reads(t, target, device)
	w.quarantine(t, device, target)
	w.contractGate(t, "observe", true, "team", "")
	_, blockerPID := w.blockWorkspace(t)
	done := make(chan error, 1)
	go func() { done <- w.users.RemoveMemberStrandDeleted(ctx, w.tenant, w.owner, target) }()
	waitBlocked(t, w, blockerPID, 1)
	switched := make(chan error, 1)
	go func() {
		_, err := store.NewContract(w.pool).SetMode(ctx, store.ContractOff)
		switched <- err
	}()
	wait := func(name string, ch chan error) error {
		t.Helper()
		select {
		case err := <-ch:
			return err
		case <-time.After(15 * time.Second):
			t.Fatalf("%s waited for the workspace past the lock timeout", name)
			return nil
		}
	}
	if err := wait("the override", done); !errors.Is(err, store.ErrWorkspaceBusy) {
		t.Fatalf("the override: %v", err)
	}
	if err := wait("the switch", switched); err != nil {
		t.Fatalf("the switch: %v", err)
	}
	if n := w.count(t, `SELECT count(*) FROM workspace_memberships WHERE user_id=$1 AND tenant_id=$2`, target, w.tenant); n != 1 {
		t.Fatal("a busy override removed the target")
	}
	if n := w.count(t, `SELECT count(*) FROM item_events WHERE type='stranded'`); n != 0 {
		t.Fatal("a busy override recorded a stranding")
	}
}

// The members list tells the console where the override's dialog opens
// (the plan's 4.12): an owner reads each deleted number a member is the
// last key holder of, with its purge date, and the gate as strand_override
// on every row; an admin reads only that there is one, and never the gate;
// a member who would strand a live number, or nothing, is not listed.
func TestMembersListTheStrandOverride(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	admin := w.person(t, "admin", "admin")
	target := w.person(t, "target", "member")
	device := w.number(t, "Suporte")
	w.reads(t, target, device)
	q := w.quarantine(t, device, target)
	other := w.number(t, "Atendimento")
	w.reads(t, target, other)
	qOther := w.quarantine(t, other, target)
	// Both a live and a deleted number: the live one decides.
	mixed := w.person(t, "mixed", "member")
	live := w.number(t, "Vivo")
	w.reads(t, mixed, live)
	gone := w.number(t, "Antigo")
	w.reads(t, mixed, gone)
	w.quarantine(t, gone, mixed)
	// A deleted number someone else also reads strands nobody.
	shared := w.number(t, "Compartilhado")
	reader := w.person(t, "reader", "member")
	w.reads(t, reader, shared)
	w.reads(t, w.owner, shared)
	w.quarantine(t, shared, reader, w.owner)

	list := func(actor uuid.UUID) map[uuid.UUID]store.Member {
		t.Helper()
		members, err := w.users.Members(ctx, w.tenant, actor)
		if err != nil {
			t.Fatal(err)
		}
		out := map[uuid.UUID]store.Member{}
		for _, m := range members {
			out[m.ID] = m
		}
		return out
	}
	for _, gate := range []struct {
		name   string
		open   bool
		mode   string
		kind   string
		status string
	}{
		{"off before the first observe", false, "off", "team", ""},
		{"observing, the team unnamed", false, "observe", "", ""},
		{"observing, the team closed on the platform", false, "observe", "team", "closed"},
		{"observing, in a team the platform names", true, "observe", "team", ""},
	} {
		w.contractGate(t, gate.mode, gate.mode == "observe", gate.kind, gate.status)
		owners := list(w.owner)
		got := owners[target].LastKeyHolderOfDeleted
		if len(got) != 2 || owners[target].LastKeyHolderOfDeletedAny {
			t.Fatalf("%s: the owner reads %+v for the target", gate.name, owners[target])
		}
		purges := map[uuid.UUID]time.Time{device: q.PurgeAfter, other: qOther.PurgeAfter}
		labels := map[uuid.UUID]string{device: "Suporte", other: "Atendimento"}
		for _, n := range got {
			if !n.PurgeAfter.Equal(purges[n.DeviceID]) || n.Label != labels[n.DeviceID] || n.PN == "" {
				t.Fatalf("%s: the target's number %+v", gate.name, n)
			}
		}
		for _, id := range []uuid.UUID{w.owner, admin, mixed, reader} {
			if m := owners[id]; len(m.LastKeyHolderOfDeleted) != 0 || m.LastKeyHolderOfDeletedAny {
				t.Fatalf("%s: the owner reads %+v for %s", gate.name, m, id)
			}
		}
		for id, m := range owners {
			if m.StrandOverride != gate.open {
				t.Fatalf("%s: strand_override %t for %s", gate.name, m.StrandOverride, id)
			}
		}
		admins := list(admin)
		if m := admins[target]; len(m.LastKeyHolderOfDeleted) != 0 || !m.LastKeyHolderOfDeletedAny || m.StrandOverride {
			t.Fatalf("%s: the admin reads %+v for the target", gate.name, m)
		}
		for id, m := range admins {
			if id != target && (m.LastKeyHolderOfDeletedAny || m.StrandOverride) {
				t.Fatalf("%s: the admin reads %+v for %s", gate.name, m, id)
			}
		}
	}
	// The JSON a console reads: the fields' names, and nothing for a member
	// with nothing to say.
	owners := list(w.owner)
	b, err := json.Marshal([]store.Member{owners[target], owners[reader]})
	if err != nil {
		t.Fatal(err)
	}
	var wire []map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if numbers, ok := wire[0]["last_key_holder_of_deleted"].([]any); !ok || len(numbers) != 2 || wire[0]["strand_override"] != true {
		t.Fatalf("the target on the wire: %s", b)
	}
	if _, ok := wire[1]["last_key_holder_of_deleted"]; ok {
		t.Fatalf("a member with nothing to strand: %s", b)
	}
	// A recovered number is live again: its last key holder is not listed.
	w.recover(t, device)
	if m := list(w.owner)[target]; len(m.LastKeyHolderOfDeleted) != 0 {
		t.Fatalf("after a recovery: %+v", m)
	}
}
