package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The acts' guards beyond the executor's checks: a team closed after R3
// read it open, another workspace's rows, the documents an act shows in
// parked, a disabled membership's notices, and the repair's lock.

// TestActRefusesClosedTeam: a team the record holds closed is team_closed
// in the act's own transaction, whatever the executor's R3 read before
// (R4's freshness may store the closing in between); the number keeps its
// label, and the result is written at the act's seq.
func TestActRefusesClosedTeam(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "admin", "admin")
	device := w.number(t, "Vendas")
	w.execOne(t, `UPDATE contract_workspaces SET status = 'closed' WHERE workspace_id = $1`, w.tenant)
	before := "Vendas"
	act, err := w.c.RunRename(ctx, w.command(t, kc.OpItemRename, user, sub), device, &before, "Vendas SP")
	refusedWith(t, "a rename in a closed team", act, err, kc.CodeTeamClosed)
	if d := w.device(t, device); d.Label != "Vendas" {
		t.Fatalf("the label in a closed team: %q", d.Label)
	}
	act, _, err = w.c.RunSyncStop(ctx, w.command(t, kc.OpItemSyncStop, user, sub), device)
	refusedWith(t, "a stop in a closed team", act, err, kc.CodeTeamClosed)
	if d := w.device(t, device); d.Paused {
		t.Fatal("a closed team's number was paused")
	}
	w.execOne(t, `UPDATE contract_workspaces SET status = 'open' WHERE workspace_id = $1`, w.tenant)
	act, err = w.c.RunRename(ctx, w.command(t, kc.OpItemRename, user, sub), device, &before, "Vendas SP")
	ranAct(t, "a rename once it reopened", act, err)
}

// TestActsReadTheirWorkspace: an admin of two teams, in Wappie and in the
// documents, names one team and the other's number or registration: every
// act answers not_found and the other team's rows stay as they were. Each
// act reads its number by the command's workspace, beside the scope's
// row-level security.
func TestActsReadTheirWorkspace(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "admin", "admin")
	other := uuid.MustParse(newTenant(t, w.pool, "other"))
	w.execOne(t, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, other)
	inTenantTx(ctx, t, w.pool, other, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO workspace_memberships (tenant_id, user_id, role) VALUES ($1, $2, 'admin')`, other, user)
		return err
	})
	w.docRoles(t, sub, map[uuid.UUID]string{w.tenant: "admin", other: "admin"})
	w.pns++
	theirs := linkedNumber(t, w.pool, other, "Theirs", fmt.Sprintf("55119%04d5678", w.pns), fmt.Sprintf("1000000%08d", w.pns))
	pending, err := w.devices.Create(ctx, other.String(), "device", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	row := uuid.MustParse(pending.ID)
	before := "Theirs"
	act, err := w.c.RunRename(ctx, w.command(t, kc.OpItemRename, user, sub), theirs, &before, "Mine")
	refusedWith(t, "a rename of the other team's number", act, err, kc.CodeNotFound)
	act, _, err = w.c.RunSyncStop(ctx, w.command(t, kc.OpItemSyncStop, user, sub), theirs)
	refusedWith(t, "a stop of the other team's number", act, err, kc.CodeNotFound)
	act, _, err = w.c.RunSyncResume(ctx, w.command(t, kc.OpItemSyncResume, user, sub), theirs)
	refusedWith(t, "a resume of the other team's number", act, err, kc.CodeNotFound)
	act, _, err = w.c.JudgeSyncNow(ctx, w.command(t, kc.OpItemSyncNow, user, sub), theirs, nil)
	refusedWith(t, "a sync now of the other team's number", act, err, kc.CodeNotFound)
	act, err = w.c.JudgeRegistrationDelete(ctx, w.command(t, kc.OpItemRegistrationDelete, user, sub), row)
	refusedWith(t, "the judgement of the other team's registration", act, err, kc.CodeNotFound)
	act, err = w.c.RunRegistrationDelete(ctx, w.command(t, kc.OpItemRegistrationDelete, user, sub), row)
	refusedWith(t, "a delete of the other team's registration", act, err, kc.CodeNotFound)
	d, err := w.devices.Get(ctx, other.String(), theirs.String())
	if err != nil || d.Label != "Theirs" || d.Paused {
		t.Fatalf("the other team's number: %+v %v", d, err)
	}
	if _, err := w.devices.Get(ctx, other.String(), row.String()); err != nil {
		t.Fatalf("the other team's registration: %v", err)
	}
}

// TestActShowsParkedDocuments: an act makes the documents it shows in due
// now even when parked, for one try: a parked numbers section never goes,
// and the console would wait for the act's result to show forever.
func TestActShowsParkedDocuments(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "admin", "admin")
	device := w.number(t, "Vendas")
	w.execOne(t, `UPDATE contract_sections SET parked_at = clock_timestamp(), due_at = clock_timestamp() + interval '1 hour'
		WHERE workspace_id = $1`, w.tenant)
	before := "Vendas"
	act, err := w.c.RunRename(ctx, w.command(t, kc.OpItemRename, user, sub), device, &before, "Vendas SP")
	ranAct(t, "a rename", act, err)
	var parked bool
	var due time.Duration
	if err := w.pool.QueryRow(ctx, `SELECT parked_at IS NOT NULL, extract(epoch FROM due_at - clock_timestamp()) * interval '1 second'
		FROM contract_sections WHERE workspace_id = $1`, w.tenant).Scan(&parked, &due); err != nil {
		t.Fatal(err)
	}
	if parked || due > 0 {
		t.Fatalf("the parked section after an act: parked %v, due in %v", parked, due)
	}
	if next, ok, err := w.c.NextSection(ctx); err != nil || !ok || next.Workspace != w.tenant || !next.Due {
		t.Fatalf("the section the sender reads next: %+v %v %v", next, ok, err)
	}

	// A person's: dismissing notices shows in their document.
	follow(t, w.delWorld, sub, "active")
	if _, ok, err := w.c.PersonOf(ctx, sub); err != nil || !ok {
		t.Fatalf("the person: %v %v", ok, err)
	}
	w.execOne(t, `UPDATE contract_persons SET parked_at = clock_timestamp(), due_at = clock_timestamp() + interval '1 hour' WHERE sub = $1`, sub)
	act, err = w.c.RunNoticesDismiss(ctx, w.command(t, kc.OpPersonNoticesDismiss, user, sub), []store.NoticeRef{{ID: "1", Version: 1}})
	if err != nil || act.Result.Outcome != store.CommandRan {
		t.Fatalf("a dismiss: %+v %v", act, err)
	}
	if next, ok, err := w.c.NextPerson(ctx); err != nil || !ok || next.Sub != sub || !next.Due {
		t.Fatalf("the person's document after an act: %+v %v %v", next, ok, err)
	}
}

// TestNoticesDismissActiveOnly: a person whose membership is disabled
// dismisses nothing there (their document lists none of its notices);
// enabled again, the same batch dismisses it.
func TestNoticesDismissActiveOnly(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "member", "member")
	device := w.number(t, "Vendas")
	w.quarantine(t, device)
	id := w.notice(t, w.tenant, device, user, store.NoticeNumberDeleted, &w.owner, "")
	setStatus := func(status string) {
		t.Helper()
		inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET status = $3 WHERE tenant_id = $1 AND user_id = $2`, w.tenant, user, status)
			return err
		})
	}
	seen := func() bool {
		t.Helper()
		var at *time.Time
		inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT seen_at FROM device_notices WHERE id = $1`, id).Scan(&at)
		})
		return at != nil
	}
	refs := []store.NoticeRef{{ID: strconv.FormatInt(id, 10), Version: 1}}
	setStatus("disabled")
	act, err := w.c.RunNoticesDismiss(ctx, w.command(t, kc.OpPersonNoticesDismiss, user, sub), refs)
	if err != nil || act.Result.Outcome != store.CommandRan || seen() {
		t.Fatalf("a disabled member's dismiss: %+v %v, seen %v", act, err, seen())
	}
	setStatus("active")
	act, err = w.c.RunNoticesDismiss(ctx, w.command(t, kc.OpPersonNoticesDismiss, user, sub), refs)
	if err != nil || act.Result.Outcome != store.CommandRan || !seen() {
		t.Fatalf("an active member's dismiss: %+v %v, seen %v", act, err, seen())
	}
}

// TestResumeLostMarksTakesNoLockForNothing: before a person's document,
// the repair takes no workspace's tenants row when it has nothing to mark
// there, so it never waits on (or blocks) the workspace's writers.
func TestResumeLostMarksTakesNoLockForNothing(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "member", "member")
	device := w.number(t, "Vendas")
	w.reads(t, user, device)
	w.pause(t, device, store.PauseActor{User: w.owner})
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // the lock's holder, ended here
	if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if n, err := w.c.ResumeLostMarks(bounded, sub); err != nil || n != 0 {
		t.Fatalf("the repair while a writer holds the workspace, with nothing to mark: %d %v", n, err)
	}
}

// docRoles stores sub's document of the current generation naming each
// team with its role.
func (w *actWorld) docRoles(t *testing.T, sub uuid.UUID, roles map[uuid.UUID]string) {
	t.Helper()
	var workspaces []map[string]any
	for id, role := range roles {
		workspaces = append(workspaces, map[string]any{"id": id.String(), "kind": "team", "role": role, "status": "open", "wversion": 1})
	}
	doc, err := json.Marshal(map[string]any{"v": 1, "sub": sub, "workspaces": workspaces})
	if err != nil {
		t.Fatal(err)
	}
	w.execOne(t, `UPDATE contract_accounts SET doc = $2 WHERE sub = $1`, sub, doc)
}
