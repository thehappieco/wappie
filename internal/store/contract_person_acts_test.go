package store_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// A person's acts (the plan's 6.5 to 6.7): the notices dismissed at the
// version seen, and the repair of a resume whose mark was lost.

// resumedAt is a notice's resumed_at.
func (w *actWorld) resumedAt(t *testing.T, id int64) *time.Time {
	t.Helper()
	var at *time.Time
	inTenantTx(context.Background(), t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT resumed_at FROM device_notices WHERE id = $1`, id).Scan(&at)
	})
	return at
}

// raisedAgo moves a notice's times back by d.
func (w *actWorld) raisedAgo(t *testing.T, id int64, d time.Duration) {
	t.Helper()
	w.execOne(t, `UPDATE device_notices SET raised_at = raised_at - $2::interval, last_raised_at = last_raised_at - $2::interval
		WHERE id = $1`, id, d)
}

// unpausedAgo moves device's unpause back by d, with the trigger that
// stamps it off for the statement.
func (w *actWorld) unpausedAgo(t *testing.T, device uuid.UUID, d time.Duration) {
	t.Helper()
	ctx := context.Background()
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `ALTER TABLE devices DISABLE TRIGGER devices_pause_times`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET unpaused_at = unpaused_at - $2::interval WHERE id = $1`, device, d); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `ALTER TABLE devices ENABLE TRIGGER devices_pause_times`)
		return err
	})
}

// TestResumeLostMarks (a gate; the platform's correction 3, DS17): a
// frame's resume whose mark was lost is marked resumed by the repair once
// its number has been unpaused a minute, at the unpause's time; one
// paused again within the minute is not; a resume from before 0052, which
// stamped no unpause, is marked at 0052's migrate time; and the console's
// resume marks in its own transaction.
func TestResumeLostMarks(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	reader := w.person(t, "reader", "member")
	device := w.number(t, "Vendas")
	w.reads(t, reader, device)
	w.pause(t, device, store.PauseActor{User: w.owner})
	notice := w.notices(t, reader)[0].ID

	// The frame lifted the pause; its mark was lost.
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), false); err != nil {
		t.Fatal(err)
	}
	if n, err := w.c.ResumeLostMarks(ctx); err != nil || n != 0 || w.resumedAt(t, notice) != nil {
		t.Fatalf("within the minute: %d %v", n, err)
	}
	w.raisedAgo(t, notice, 3*time.Minute)
	w.unpausedAgo(t, device, 2*time.Minute)
	var unpaused time.Time
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT unpaused_at FROM devices WHERE id = $1`, device).Scan(&unpaused)
	})
	if n, err := w.c.ResumeLostMarks(ctx); err != nil || n != 1 {
		t.Fatalf("after the minute: %d %v", n, err)
	}
	if at := w.resumedAt(t, notice); at == nil || !at.Equal(unpaused) {
		t.Fatalf("resumed_at %v, the unpause at %v", at, unpaused)
	}
	if n, err := w.c.ResumeLostMarks(ctx); err != nil || n != 0 {
		t.Fatalf("a second repair: %d %v", n, err)
	}

	// Paused again within the minute: the notice folds open, and the
	// repair leaves it while the number is paused.
	w.pause(t, device, store.PauseActor{User: w.owner})
	if n := w.notices(t, reader); len(n) != 1 || n[0].ID != notice || n[0].ResumedAt != nil {
		t.Fatalf("the notice after a second pause: %+v", n)
	}
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), false); err != nil {
		t.Fatal(err)
	}
	w.raisedAgo(t, notice, 3*time.Minute)
	w.unpausedAgo(t, device, 2*time.Minute)
	w.pause(t, device, store.PauseActor{User: w.owner})
	// The fold raised it now: back before the unpause, so only the pause
	// keeps it open.
	w.raisedAgo(t, notice, 3*time.Minute)
	if n, err := w.c.ResumeLostMarks(ctx, linkSub(t, w.pool, reader)); err != nil || n != 0 || w.resumedAt(t, notice) != nil {
		t.Fatalf("a number paused again: %d %v", n, err)
	}

	// A resume before 0052 left no unpause time: 0052's migrate time.
	w.execOne(t, `UPDATE devices SET paused = false WHERE id = $1`, device)
	w.execOne(t, `UPDATE device_notices SET raised_at = raised_at - interval '1 day', last_raised_at = last_raised_at - interval '1 day'
		WHERE id = $1`, notice)
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `ALTER TABLE devices DISABLE TRIGGER devices_pause_times`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET unpaused_at = NULL WHERE id = $1`, device); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `ALTER TABLE devices ENABLE TRIGGER devices_pause_times`)
		return err
	})
	if _, err := w.pool.Exec(ctx, `UPDATE contract_settings_state SET label_cutover_at = clock_timestamp() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	state, err := w.c.SettingsState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.c.ResumeLostMarks(ctx); err != nil || n != 1 {
		t.Fatalf("a resume before 0052: %d %v", n, err)
	}
	if at := w.resumedAt(t, notice); at == nil || !at.Equal(state.LabelCutoverAt) {
		t.Fatalf("resumed_at %v, the cutover %v", at, state.LabelCutoverAt)
	}

	// The console's resume marks in the transaction that lifts the pause.
	user, sub := w.actor(t, "admin", "admin")
	w.pause(t, device, store.PauseActor{User: w.owner})
	act, _, err := w.c.RunSyncResume(ctx, w.command(t, kc.OpItemSyncResume, user, sub), device)
	ranAct(t, "the console's resume", act, err)
	if at := w.resumedAt(t, notice); at == nil {
		t.Fatal("the console's resume did not mark the notice")
	}
}

// TestNoticesDismiss: a batch is not all or nothing: the notices named are
// seen, a pause notice only at the version seen; one whose version rose
// stays, and the result is state_changed; one already seen, gone, or not a
// Wappie id counts as done; another person's is never touched; the
// person's seq rises and their document is due now.
func TestNoticesDismiss(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "member", "member")
	other := w.person(t, "other", "member")
	a, b := w.number(t, "A"), w.number(t, "B")
	paused := w.notice(t, w.tenant, a, user, store.NoticeSyncPaused, &w.owner, "")
	rose := w.notice(t, w.tenant, b, user, store.NoticeSyncPaused, &w.owner, "pauses = 3, last_raised_at = clock_timestamp()")
	deleted := w.notice(t, w.tenant, uuid.New(), user, store.NoticeNumberDeleted, &w.owner, "")
	theirs := w.notice(t, w.tenant, a, other, store.NoticeSyncPaused, &w.owner, "")
	id := func(n int64) string { return strconv.FormatInt(n, 10) }
	unseen := func(n int64) bool {
		var seen *time.Time
		inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT seen_at FROM device_notices WHERE id = $1`, n).Scan(&seen)
		})
		return seen == nil
	}
	w.execOne(t, `UPDATE contract_persons SET due_at = clock_timestamp() + interval '1 hour' WHERE sub = $1`, sub)

	cmd := w.command(t, kc.OpPersonNoticesDismiss, user, sub)
	act, err := w.c.RunNoticesDismiss(ctx, cmd, []store.NoticeRef{
		{ID: id(paused), Version: 1}, {ID: id(rose), Version: 2}, {ID: id(deleted), Version: 1}, {ID: id(theirs), Version: 1},
		{ID: "999999", Version: 1}, {ID: "mbe_x", Version: 1}, {ID: "0" + id(paused), Version: 1},
	})
	if err != nil || act.Result.Outcome != store.CommandRefused || act.Result.Code != kc.CodeStateChanged || *act.Result.StateSeq != act.Seq {
		t.Fatalf("the batch: %+v %v", act, err)
	}
	if unseen(paused) || unseen(deleted) || !unseen(rose) || !unseen(theirs) {
		t.Fatalf("seen: paused %v, deleted %v, rose %v, theirs %v", !unseen(paused), !unseen(deleted), !unseen(rose), !unseen(theirs))
	}
	var seq int64
	var due time.Duration
	if err := w.pool.QueryRow(ctx, `SELECT seq, extract(epoch FROM due_at - clock_timestamp()) * interval '1 second'
		FROM contract_persons WHERE sub = $1`, sub).Scan(&seq, &due); err != nil {
		t.Fatal(err)
	}
	if seq != act.Seq || due > 0 {
		t.Fatalf("the person's seq %d (the act's %d), due in %v", seq, act.Seq, due)
	}
	// The version the person sees now: ran.
	act, err = w.c.RunNoticesDismiss(ctx, w.command(t, kc.OpPersonNoticesDismiss, user, sub), []store.NoticeRef{
		{ID: id(rose), Version: 3}, {ID: id(paused), Version: 1}})
	if err != nil || act.Result.Outcome != store.CommandRan || act.Seq <= seq || unseen(rose) {
		t.Fatalf("the second batch: %+v %v", act, err)
	}
}
