package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/store"
)

// pauseCause reads a number's pause_cause, excluded or not; "" when it is
// live.
func pauseCause(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenant, device uuid.UUID) string {
	t.Helper()
	var cause *string
	inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error {
			return tx.QueryRow(ctx, `SELECT pause_cause FROM devices WHERE id = $1`, device).Scan(&cause)
		})
	})
	if cause == nil {
		return ""
	}
	return *cause
}

// TestPauseCause is the plan's TB12 (the column; the snapshot's reason
// lands with its sender): every writer of a pause says why, so a snapshot
// can tell a person's pause from Wappie's own (the plan's DB12).
func TestPauseCause(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Vendas")
	want := func(step, cause string) {
		t.Helper()
		if got := pauseCause(ctx, t, w.pool, w.tenant, device); got != cause {
			t.Fatalf("%s: pause_cause %q, want %q", step, got, cause)
		}
		if cause == store.PauseForDeletion {
			return
		}
		d, err := w.devices.Get(ctx, w.tenant.String(), device.String())
		if err != nil || d.PauseCause != cause || d.Paused != (cause != "") {
			t.Fatalf("%s: the device reads paused %v, cause %q (%v)", step, d.Paused, d.PauseCause, err)
		}
	}
	want("a live number", "")

	w.pause(t, device, store.PauseActor{User: w.owner})
	want("a person's stop", store.PauseByPerson)
	w.resume(t, device)
	want("a resume", "")

	// Wappie's own pause for a move, taken back when the move does not
	// happen.
	p, err := w.devices.PauseForMove(ctx, w.tenant, device)
	if err != nil || !p.Changed {
		t.Fatalf("the move's pause: %+v %v", p, err)
	}
	want("the move's pause", store.PauseForMove)
	if undone, err := w.devices.UndoMovePause(ctx, w.tenant, device, p); err != nil || !undone {
		t.Fatalf("the undo: %v %v", undone, err)
	}
	want("the move's pause undone", "")

	// A person's stop while the move holds its pause makes it theirs, and
	// the undo then leaves it.
	if p, err = w.devices.PauseForMove(ctx, w.tenant, device); err != nil || !p.Changed {
		t.Fatalf("the move's pause again: %+v %v", p, err)
	}
	if got := w.pause(t, device, store.PauseActor{User: w.owner}); got.Changed {
		t.Fatalf("a stop on a paused number changed it: %+v", got)
	}
	want("a person's stop during the move", store.PauseByPerson)
	if undone, err := w.devices.UndoMovePause(ctx, w.tenant, device, p); err != nil || undone {
		t.Fatalf("the undo after a person's stop: %v %v", undone, err)
	}
	want("the undo after a person's stop", store.PauseByPerson)
	w.resume(t, device)

	// A key's stop is a person's pause too: its creator's, or nobody's.
	w.pause(t, device, store.PauseActor{Key: w.keyBy(t, &w.owner, device)})
	want("a key's stop", store.PauseByPerson)

	// A failed resume puts back the pause it took, with its cause.
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), false); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.RestorePause(ctx, w.tenant.String(), device.String(), store.PauseForMove); err != nil {
		t.Fatal(err)
	}
	want("a move's pause restored", store.PauseForMove)
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), false); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.RestorePause(ctx, w.tenant.String(), device.String(), ""); err != nil {
		t.Fatal(err)
	}
	want("a pause restored on a number that had none", store.PauseByPerson)
	w.resume(t, device)

	// Excluded, a number's pause is the deletion's, whatever it was; the
	// owner's recovery leaves it paused as theirs.
	w.pause(t, device, store.PauseActor{User: w.owner})
	w.quarantine(t, device)
	want("an excluded number", store.PauseForDeletion)
	w.recover(t, device)
	want("a recovered number", store.PauseByPerson)
}

// The move to Personal keeps a person's pause theirs, and makes any other
// pause the move's.
func TestMoveKeepsAPersonsPause(t *testing.T) {
	for _, c := range []struct {
		name  string
		pause func(ctx context.Context, d *store.Devices, a *archive) error
		want  string
	}{
		{"a person's pause", func(ctx context.Context, d *store.Devices, a *archive) error {
			return d.SetPaused(ctx, a.tenant.String(), a.device.String(), true)
		}, store.PauseByPerson},
		{"the move's own pause", func(ctx context.Context, d *store.Devices, a *archive) error {
			_, err := d.PauseForMove(ctx, a.tenant, a.device)
			return err
		}, store.PauseForMove},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newArchive(t)
			owner, target := transferOwner(t, a, "owner")
			ctx := context.Background()
			d := store.NewDevices(a.pool)
			if err := c.pause(ctx, d, a); err != nil {
				t.Fatal(err)
			}
			if _, err := d.TransferPersonal(ctx, a.tenant, owner, a.device, target); err != nil {
				t.Fatal(err)
			}
			if got := pauseCause(ctx, t, a.pool, target, a.device); got != c.want {
				t.Fatalf("after the move: pause_cause %q, want %q", got, c.want)
			}
		})
	}
}
