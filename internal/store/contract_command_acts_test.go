package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The console's acts on a workspace's numbers (the plan's 6.2 and 6.3),
// each in one transaction: the target before the role, both roles, the
// published value, and the result at the act's seq.

// actWorld is a platform team Wappie holds and has recorded, with a
// snapshot numbered and a generation, where acts run.
type actWorld struct {
	*delWorld
	c    *store.Contract
	gen  uuid.UUID
	cseq int64
}

func newActWorld(t *testing.T) *actWorld {
	t.Helper()
	w := &actWorld{delWorld: newDelWorld(t), gen: uuid.New()}
	w.c = store.NewContract(w.pool)
	w.recordLocal(t, w.c)
	if _, err := w.c.SetMode(context.Background(), store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	w.execOne(t, `UPDATE contract_state SET generation = $1`, w.gen)
	return w
}

// actor is a person of the team with local role, linked to a sub whose
// stored document of the current generation gives the team docRole ("" for
// a document that does not name it).
func (w *actWorld) actor(t *testing.T, role, docRole string) (user, sub uuid.UUID) {
	t.Helper()
	user = w.person(t, "actor", role)
	sub = linkSub(t, w.pool, user)
	w.docRole(t, sub, docRole, "active")
	return user, sub
}

// docRole stores sub's document of the current generation, naming the
// team with role (none for ""), with status.
func (w *actWorld) docRole(t *testing.T, sub uuid.UUID, role, status string) {
	t.Helper()
	workspaces := []map[string]any{}
	if role != "" {
		workspaces = append(workspaces, map[string]any{"id": w.tenant.String(), "kind": "team", "role": role, "status": "open", "wversion": 1})
	}
	doc, err := json.Marshal(map[string]any{"v": 1, "sub": sub, "workspaces": workspaces})
	if err != nil {
		t.Fatal(err)
	}
	w.execOne(t, `INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, $3, $4)
		ON CONFLICT (sub) DO UPDATE SET generation = excluded.generation, version = excluded.version, status = excluded.status,
		  doc = excluded.doc`,
		sub, w.gen, status, doc)
}

// command takes a command of kind by sub in the team, with no result yet.
func (w *actWorld) command(t *testing.T, kind string, user, sub uuid.UUID) store.ContractRun {
	t.Helper()
	w.cseq++
	id := uuid.New()
	ws := &w.tenant
	section := kc.SectionNumbers
	if kind == kc.OpPersonSignOutEverywhere || kind == kc.OpPersonNoticesDismiss {
		ws, section = nil, kc.SectionPerson
	}
	var wseq *int64
	if ws != nil {
		wseq = &w.cseq
	}
	w.execOne(t, `INSERT INTO contract_commands (id, generation, cseq, workspace_id, wseq, kind, section, actor, issued_at,
		body, body_key, signed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, clock_timestamp(), '{}', $9, clock_timestamp())`,
		id, w.gen, w.cseq, ws, wseq, kind, section, sub, make([]byte, 32))
	run := store.ContractRun{ID: id, Sub: sub, User: user}
	if ws != nil {
		run.Workspace = *ws
	}
	return run
}

// actLedger is a command's result as the ledger holds it.
type actLedger struct {
	outcome, code string
	seq           *int64
	retryAfter    *int
	detail        string
}

func (w *actWorld) ledger(t *testing.T, id uuid.UUID) actLedger {
	t.Helper()
	var l actLedger
	var detail []byte
	if err := w.pool.QueryRow(context.Background(), `SELECT coalesce(outcome, ''), coalesce(code, ''), state_seq, retry_after, detail
		FROM contract_commands WHERE id = $1`, id).Scan(&l.outcome, &l.code, &l.seq, &l.retryAfter, &detail); err != nil {
		t.Fatal(err)
	}
	l.detail = string(detail)
	return l
}

// clock is the team's two seq columns and its numbers section's due time
// ahead of the database's clock.
func (w *actWorld) clock(t *testing.T) (sections, snapshot int64, numbersDue, snapshotDue time.Duration) {
	t.Helper()
	var due, snapDue, now time.Time
	if err := w.pool.QueryRow(context.Background(), `SELECT w.sections_seq, w.snapshot_seq, s.due_at, w.snapshot_due_at, clock_timestamp()
		FROM contract_workspaces w JOIN contract_sections s ON s.workspace_id = w.workspace_id AND s.section = 'numbers'
		WHERE w.workspace_id = $1`, w.tenant).Scan(&sections, &snapshot, &due, &snapDue, &now); err != nil {
		t.Fatal(err)
	}
	return sections, snapshot, due.Sub(now), snapDue.Sub(now)
}

// later makes the team's numbers section and snapshot due in an hour.
func (w *actWorld) later(t *testing.T) {
	t.Helper()
	w.execOne(t, `UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour' WHERE workspace_id = $1`, w.tenant)
	w.execOne(t, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '1 hour' WHERE workspace_id = $1`, w.tenant)
}

func (w *actWorld) device(t *testing.T, id uuid.UUID) store.Device {
	t.Helper()
	d, err := w.devices.Get(context.Background(), w.tenant.String(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func refusedWith(t *testing.T, what string, act store.ContractAct, err error, code string) {
	t.Helper()
	if err != nil || act.Result.Outcome != store.CommandRefused || act.Result.Code != code || act.Result.StateSeq == nil ||
		*act.Result.StateSeq != act.Seq {
		t.Fatalf("%s: %+v %v, want refused %s at the act's seq", what, act, err, code)
	}
}

func ranAct(t *testing.T, what string, act store.ContractAct, err error) {
	t.Helper()
	if err != nil || act.Result.Outcome != store.CommandRan || act.Result.StateSeq == nil || *act.Result.StateSeq != act.Seq || act.Open {
		t.Fatalf("%s: %+v %v, want ran", what, act, err)
	}
}

// TestRunRename: the target first (a deleted number, another workspace's,
// a workspace Wappie does not hold: not_found), then the role, then the
// label Wappie publishes (never the one stored) against params.before,
// then the contract's cleaning (label_changed with the cleaned text); a
// rename stores the label, writes ran at the act's seq, which the
// workspace's clock passed, and makes the numbers section and the
// snapshot due now. A label Wappie sets aside runs and publishes null
// (DS10).
func TestRunRename(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "admin", "admin")
	device := w.number(t, "Vendas")
	w.later(t)
	vendas := "Vendas"

	other := w.number(t, "Outro")
	w.quarantine(t, other)
	act, err := w.c.RunRename(ctx, w.command(t, kc.OpItemRename, user, sub), other, &vendas, "X")
	refusedWith(t, "a deleted number", act, err, kc.CodeNotFound)
	act, err = w.c.RunRename(ctx, w.command(t, kc.OpItemRename, user, sub), uuid.New(), &vendas, "X")
	refusedWith(t, "a number of no workspace here", act, err, kc.CodeNotFound)

	member, memberSub := w.actor(t, "member", "member")
	act, err = w.c.RunRename(ctx, w.command(t, kc.OpItemRename, member, memberSub), device, &vendas, "X")
	refusedWith(t, "a member without Manage", act, err, kc.CodeNotAuthorized)

	// The stored label is not what Wappie publishes when it is set aside:
	// before must be what the snapshot says, null.
	act, err = w.c.RunRename(ctx, w.command(t, kc.OpItemRename, user, sub), device, nil, "X")
	refusedWith(t, "a before that is not the published label", act, err, kc.CodeStateChanged)

	decomposed := "Café"
	cmd := w.command(t, kc.OpItemRename, user, sub)
	act, err = w.c.RunRename(ctx, cmd, device, &vendas, decomposed)
	refusedWith(t, "a label the contract cleans", act, err, kc.CodeLabelChanged)
	if l := w.ledger(t, cmd.ID); l.detail != `{"cleaned": "Café"}` {
		t.Fatalf("label_changed's detail: %s", l.detail)
	}
	if got := w.device(t, device).Label; got != "Vendas" {
		t.Fatalf("a refused rename stored %q", got)
	}

	cmd = w.command(t, kc.OpItemRename, user, sub)
	act, err = w.c.RunRename(ctx, cmd, device, &vendas, "Vendas SP")
	ranAct(t, "a rename", act, err)
	sections, snapshot, numbersDue, snapshotDue := w.clock(t)
	if l := w.ledger(t, cmd.ID); l.outcome != "ran" || l.seq == nil || *l.seq != act.Seq || act.Seq != sections || act.Seq <= snapshot {
		t.Fatalf("the ledger %+v, the act's seq %d, the clock %d/%d", l, act.Seq, sections, snapshot)
	}
	if numbersDue > 0 || snapshotDue > 0 {
		t.Fatalf("after a rename the numbers section is due in %v, the snapshot in %v", numbersDue, snapshotDue)
	}
	if got := w.device(t, device).Label; got != "Vendas SP" {
		t.Fatalf("the label is %q", got)
	}
	// Once answered, never again.
	if _, err := w.c.RunRename(ctx, cmd, device, &vendas, "Vendas RJ"); !errors.Is(err, store.ErrCommandFinished) {
		t.Fatalf("a second run of an answered command: %v", err)
	}

	// A label set aside (a placeholder) is stored, and published as null.
	vendasSP := "Vendas SP"
	act, err = w.c.RunRename(ctx, w.command(t, kc.OpItemRename, user, sub), device, &vendasSP, "Número sem nome")
	ranAct(t, "a rename to a placeholder", act, err)
	if got := w.device(t, device).Label; got != "Número sem nome" {
		t.Fatalf("the label set aside is %q", got)
	}
	act, err = w.c.RunRename(ctx, w.command(t, kc.OpItemRename, user, sub), device, nil, "Loja")
	ranAct(t, "a rename from the null it publishes", act, err)
}

// TestLocalRolesFailClosed (a gate; the plan's 6.2 table, kind by kind):
// the local role (Wappie's own screens) and the stored document's role
// must both allow a kind; where they differ it is not_authorized, both
// ways; a document not active, or one that does not name the workspace,
// counts as none.
func TestLocalRolesFailClosed(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	device := w.number(t, "Vendas")
	// A reader remains whatever the flags a case sets.
	w.reads(t, w.owner, device)
	pending, err := w.devices.Create(ctx, w.tenant.String(), "device", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	type person struct {
		local, doc string
		flag, read bool
		status     string
	}
	run := func(kind string, p person) string {
		t.Helper()
		user, sub := w.actor(t, p.local, p.doc) //nolint:contextcheck // the world's helpers run on a context of their own
		if p.status != "" {
			w.docRole(t, sub, p.doc, p.status) //nolint:contextcheck // the world's helpers run on a context of their own
		}
		if p.read {
			w.reads(t, user, device) //nolint:contextcheck // the world's helpers run on a context of their own
		}
		if p.flag {
			if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: user,
				Read: p.read, Manage: true}); err != nil {
				t.Fatal(err)
			}
		}
		cmd := w.command(t, kind, user, sub) //nolint:contextcheck // the world's helpers run on a context of their own
		var act store.ContractAct
		switch kind {
		case kc.OpItemRename:
			label := "Vendas"
			act, err = w.c.RunRename(ctx, cmd, device, &label, "Vendas")
		case kc.OpItemSyncStop:
			act, _, err = w.c.RunSyncStop(ctx, cmd, device)
		case kc.OpItemSyncResume:
			act, _, err = w.c.RunSyncResume(ctx, cmd, device)
		case kc.OpItemSyncNow:
			act, _, err = w.c.JudgeSyncNow(ctx, cmd, device, nil)
		case kc.OpItemRegistrationDelete:
			act, err = w.c.JudgeRegistrationDelete(ctx, cmd, uuid.MustParse(pending.ID))
		}
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if act.Open || act.Result.Outcome == store.CommandRan {
			return "runs"
		}
		// A resume of a number that is not paused gets past the roles.
		if act.Result.Code == kc.CodeStateChanged || act.Result.Code == kc.CodePaused {
			return "runs"
		}
		return act.Result.Code
	}
	const no = kc.CodeNotAuthorized
	for _, c := range []struct {
		kind string
		p    person
		want string
	}{
		{kc.OpItemSyncStop, person{local: "member", doc: "admin"}, no},
		{kc.OpItemSyncStop, person{local: "admin", doc: "member"}, no},
		{kc.OpItemSyncStop, person{local: "member", doc: "admin", flag: true}, no},
		{kc.OpItemSyncStop, person{local: "admin", doc: "admin"}, "runs"},
		{kc.OpItemSyncResume, person{local: "member", doc: "admin"}, no},
		{kc.OpItemSyncResume, person{local: "admin", doc: "member"}, no},
		{kc.OpItemSyncResume, person{local: "admin", doc: "owner"}, "runs"},
		{kc.OpItemRegistrationDelete, person{local: "member", doc: "admin"}, no},
		{kc.OpItemRegistrationDelete, person{local: "admin", doc: "member"}, no},
		{kc.OpItemRegistrationDelete, person{local: "admin", doc: "admin"}, "runs"},
		{kc.OpItemRename, person{local: "member", doc: "admin", flag: true}, "runs"},
		{kc.OpItemRename, person{local: "admin", doc: "member"}, no},
		{kc.OpItemRename, person{local: "member", doc: "member", flag: true}, "runs"},
		{kc.OpItemRename, person{local: "member", doc: "member"}, no},
		{kc.OpItemRename, person{local: "member", doc: "admin"}, no},
		{kc.OpItemSyncNow, person{local: "member", doc: "member", read: true}, "runs"},
		{kc.OpItemSyncNow, person{local: "member", doc: "owner", read: true}, "runs"},
		{kc.OpItemSyncNow, person{local: "admin", doc: "admin"}, no},
		{kc.OpItemSyncNow, person{local: "member", doc: "", read: true}, no},
	} {
		if got := run(c.kind, c.p); got != c.want {
			t.Errorf("%s by %+v: %s, want %s", c.kind, c.p, got, c.want)
		}
	}
	// A document that is not active, or names no workspace, is none, for
	// every kind.
	for _, kind := range []string{kc.OpItemRename, kc.OpItemSyncStop, kc.OpItemSyncResume, kc.OpItemSyncNow, kc.OpItemRegistrationDelete} {
		for _, p := range []person{
			{local: "admin", doc: "admin", status: "disabled", read: true},
			{local: "admin", doc: "", read: true},
		} {
			if got := run(kind, p); got != no {
				t.Errorf("%s by %+v: %s, want %s", kind, p, got, no)
			}
		}
	}
	// A document of another generation is none too.
	user, sub := w.actor(t, "admin", "admin")
	w.execOne(t, `UPDATE contract_accounts SET generation = $2 WHERE sub = $1`, sub, uuid.New())
	act, _, err := w.c.RunSyncStop(ctx, w.command(t, kc.OpItemSyncStop, user, sub), device)
	refusedWith(t, "a document of another generation", act, err, no)
	// The deleted number and another workspace's are not_found before any
	// role: the target first.
	stranger, strangerSub := w.actor(t, "member", "")
	device = w.number(t, "Gone")
	w.quarantine(t, device)
	for _, kind := range []string{kc.OpItemRename, kc.OpItemSyncStop, kc.OpItemSyncResume, kc.OpItemSyncNow} {
		cmd := w.command(t, kind, stranger, strangerSub)
		var act store.ContractAct
		switch kind {
		case kc.OpItemRename:
			act, err = w.c.RunRename(ctx, cmd, device, nil, "X")
		case kc.OpItemSyncStop:
			act, _, err = w.c.RunSyncStop(ctx, cmd, device)
		case kc.OpItemSyncResume:
			act, _, err = w.c.RunSyncResume(ctx, cmd, device)
		case kc.OpItemSyncNow:
			act, _, err = w.c.JudgeSyncNow(ctx, cmd, device, nil)
		}
		refusedWith(t, kind+" of a deleted number", act, err, kc.CodeNotFound)
	}
}

// TestRunSyncStopAndResume: a stop pauses as the person (readers but the
// actor told, the event written, paused_by the person), a stop of a
// paused number counts as done and tells nobody, a stop of a moved number
// makes its pause the person's and names the actor; a resume lifts any
// pause (a move's too), marks the notices resumed in its transaction and
// returns the number; one of a number not paused, or logged out, is
// state_changed.
func TestRunSyncStopAndResume(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "admin", "admin")
	device := w.number(t, "Vendas")
	reader := w.person(t, "reader", "member")
	w.reads(t, reader, device)
	w.reads(t, user, device)

	act, paused, err := w.c.RunSyncStop(ctx, w.command(t, kc.OpItemSyncStop, user, sub), device)
	ranAct(t, "a stop", act, err)
	if !paused.Changed || len(paused.Notices) != 1 || paused.Notices[0].UserID != reader || !paused.Recorded {
		t.Fatalf("the stop: %+v", paused)
	}
	var kind string
	var by *uuid.UUID
	var events int
	w.scoped(t, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT pause_cause, paused_by_user FROM devices WHERE id = $1`, device).Scan(&kind, &by); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM item_events WHERE item_id = $1 AND type = 'sync_paused'`, device).Scan(&events)
	})
	if kind != "person" || by == nil || *by != user || events != 1 {
		t.Fatalf("the pause: cause %s by %v, %d events", kind, by, events)
	}
	act, paused, err = w.c.RunSyncStop(ctx, w.command(t, kc.OpItemSyncStop, user, sub), device)
	ranAct(t, "a stop of a paused number", act, err)
	if paused.Changed || len(paused.Notices) != 0 {
		t.Fatalf("a second stop told someone: %+v", paused)
	}

	act, dev, err := w.c.RunSyncResume(ctx, w.command(t, kc.OpItemSyncResume, user, sub), device)
	ranAct(t, "a resume", act, err)
	if dev.Paused || dev.ID != device.String() || !dev.Identity.Known() {
		t.Fatalf("the number returned: %+v", dev)
	}
	if n := w.notices(t, reader); len(n) != 1 || n[0].ResumedAt == nil {
		t.Fatalf("the reader's notice after the resume: %+v", n)
	}
	act, _, err = w.c.RunSyncResume(ctx, w.command(t, kc.OpItemSyncResume, user, sub), device)
	refusedWith(t, "a resume of a number not paused", act, err, kc.CodeStateChanged)

	// A move's pause: stopped, it becomes the person's, named; resumed
	// as any.
	w.execOne(t, `UPDATE devices SET paused = true, pause_cause = 'move', pause_seq = pause_seq + 1 WHERE id = $1`, device)
	act, paused, err = w.c.RunSyncStop(ctx, w.command(t, kc.OpItemSyncStop, user, sub), device)
	ranAct(t, "a stop of a moved number", act, err)
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT pause_cause, paused_by_user FROM devices WHERE id = $1`, device).Scan(&kind, &by)
	})
	if paused.Changed || kind != "person" || by == nil || *by != user {
		t.Fatalf("a moved number's stop: %+v, cause %s by %v", paused, kind, by)
	}
	w.execOne(t, `UPDATE devices SET pause_cause = 'move' WHERE id = $1`, device)
	act, _, err = w.c.RunSyncResume(ctx, w.command(t, kc.OpItemSyncResume, user, sub), device)
	ranAct(t, "a resume of a moved number", act, err)

	// Logged out: no resume, the relink is the way.
	w.execOne(t, `UPDATE devices SET paused = true, status = 'logged_out', status_reason = 'unlinked (test)' WHERE id = $1`, device)
	act, _, err = w.c.RunSyncResume(ctx, w.command(t, kc.OpItemSyncResume, user, sub), device)
	refusedWith(t, "a resume of a logged-out number", act, err, kc.CodeStateChanged)
}

// TestRegistrationDelete: a registration that never linked is deleted;
// one that linked is state_changed and stays; the judgement writes nothing
// when it passes.
func TestRegistrationDelete(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "admin", "admin")
	pending, err := w.devices.Create(ctx, w.tenant.String(), "device", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	row := uuid.MustParse(pending.ID)
	cmd := w.command(t, kc.OpItemRegistrationDelete, user, sub)
	before, _, _, _ := w.clock(t)
	act, err := w.c.JudgeRegistrationDelete(ctx, cmd, row)
	if err != nil || !act.Open {
		t.Fatalf("the judgement: %+v %v", act, err)
	}
	if after, _, _, _ := w.clock(t); after != before || w.ledger(t, cmd.ID).outcome != "" {
		t.Fatal("a judgement that passed wrote something")
	}
	act, err = w.c.RunRegistrationDelete(ctx, cmd, row)
	ranAct(t, "the delete", act, err)
	if _, err := w.devices.Get(ctx, w.tenant.String(), row.String()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the registration is still there: %v", err)
	}

	linked := w.number(t, "Vendas")
	act, err = w.c.JudgeRegistrationDelete(ctx, w.command(t, kc.OpItemRegistrationDelete, user, sub), linked)
	refusedWith(t, "a linked number", act, err, kc.CodeStateChanged)
	// One that links between the judgement and the delete.
	other, err := w.devices.Create(ctx, w.tenant.String(), "device", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	cmd = w.command(t, kc.OpItemRegistrationDelete, user, sub)
	if act, err := w.c.JudgeRegistrationDelete(ctx, cmd, uuid.MustParse(other.ID)); err != nil || !act.Open {
		t.Fatalf("the judgement: %+v %v", act, err)
	}
	w.pns++
	w.execOne(t, `UPDATE devices SET pn = $2 WHERE id = $1`, other.ID, fmt.Sprintf("55119%04d5678@s.whatsapp.net", w.pns))
	act, err = w.c.RunRegistrationDelete(ctx, cmd, uuid.MustParse(other.ID))
	refusedWith(t, "a registration that linked meanwhile", act, err, kc.CodeStateChanged)
	if _, err := w.devices.Get(ctx, w.tenant.String(), other.ID); err != nil {
		t.Fatalf("the number that linked is gone: %v", err)
	}
}

// TestJudgeSyncNow: the frame's order of refusals, then the act left open
// and answered at a new seq.
func TestJudgeSyncNow(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "member", "member")
	device := w.number(t, "Vendas")
	w.reads(t, user, device)
	judge := func(busy func(uuid.UUID) (int, bool)) (store.ContractRun, store.ContractAct, error) {
		cmd := w.command(t, kc.OpItemSyncNow, user, sub) //nolint:contextcheck // the world's helpers run on a context of their own
		act, _, err := w.c.JudgeSyncNow(ctx, cmd, device, busy)
		return cmd, act, err
	}
	busy := func(uuid.UUID) (int, bool) { return 42, true }

	cmd, act, err := judge(busy)
	refusedWith(t, "a number pairing", act, err, kc.CodeItemBusy)
	if l := w.ledger(t, cmd.ID); l.retryAfter == nil || *l.retryAfter != 42 {
		t.Fatalf("item_busy's retry_after: %+v", l)
	}
	cmd, act, err = judge(nil)
	if err != nil || !act.Open {
		t.Fatalf("a number that may connect: %+v %v", act, err)
	}
	done, err := w.c.FinishSyncNow(ctx, cmd, store.CommandResult{Outcome: store.CommandRan})
	ranAct(t, "the sync now", done, err)
	if done.Seq <= act.Seq {
		t.Fatalf("the answer's seq %d is not above the judgement's %d", done.Seq, act.Seq)
	}
	for _, c := range []struct {
		set, code string
	}{
		{`status = 'logged_out', status_reason = 'unlinked (test)'`, kc.CodeReadOnly},
		{`status = 'banned', status_reason = 'test'`, kc.CodeReadOnly},
		{`paused = true`, kc.CodePaused},
	} {
		w.execOne(t, `UPDATE devices SET `+c.set+` WHERE id = $1`, device)
		_, act, err := judge(busy)
		refusedWith(t, c.set, act, err, c.code)
	}
	w.execOne(t, `UPDATE tenants SET storage_paused_at = clock_timestamp() WHERE id = $1`, w.tenant)
	_, act, err = judge(nil)
	refusedWith(t, "a paused number, storage stopped", act, err, kc.CodePaused)
	w.execOne(t, `UPDATE devices SET paused = false WHERE id = $1`, device)
	_, act, err = judge(nil)
	refusedWith(t, "storage stopped", act, err, kc.CodeStoragePaused)
	w.execOne(t, `UPDATE tenants SET storage_paused_at = NULL WHERE id = $1`, w.tenant)
	w.execOne(t, `UPDATE devices SET pn = NULL, lid = NULL, status = 'offline', status_reason = '' WHERE id = $1`, device)
	_, act, err = judge(nil)
	refusedWith(t, "a number with no identity", act, err, kc.CodeNotLinked)
}
