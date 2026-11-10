package membership

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// A platform token's pause (step 7's plan, 6.3 and 10.5): its creator's,
// folded with that creator's own pauses, never with another creator's.

// sqlToken is a platform token of ws, written straight into the token
// tables as the applier leaves one: created by creator, expiring after
// the interval expires, with perms applied on device. Only where no token
// follower runs, whose reset's pass would unlist it.
func (w *world) sqlToken(t *testing.T, ws, device, creator uuid.UUID, expires string, perms ...string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	w.exec(ctx, t, `INSERT INTO contract_token_selectors (selector, token_id, tenant_id, hash, until)
		VALUES ($1, $2, $3, decode(repeat('ab', 32), 'hex'), clock_timestamp() + interval '1 day')`,
		hex.EncodeToString(random(t, 8)), id, ws)
	if err := pg.InTenantTx(ctx, w.pool, ws.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO contract_tokens (id, tenant_id, name, created_by, created_at, expires_at)
			VALUES ($1, $2, 'Nightly', $3, clock_timestamp(), clock_timestamp() + $4::interval)`, id, ws, creator, expires); err != nil {
			return err
		}
		for _, p := range perms {
			if _, err := tx.Exec(ctx, `INSERT INTO contract_token_perms (token_id, tenant_id, device_id, perm, granted_by, granted_at,
					generation, version, state)
				VALUES ($1, $2, $3, $4, $5, clock_timestamp(), $6, 1, 'applied')`, id, ws, device, p, creator, uuid.New()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestPauseCoalescingByATokensCreator (the plan's 10.5): two tokens whose
// creators have no local account are two actors, so their pauses under
// the hour make two events, each with its creator's sub, and one of them
// again under the hour folds into its delivered event; a person's pause
// and their own token's fold into one, and the person is not told of
// their own token's.
func TestPauseCoalescingByATokensCreator(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	devices := store.NewDevices(w.pool)
	s := w.sender(t, w.members, &membershiptest.Logs{})
	first, second := uuid.New(), uuid.New()
	a := w.sqlToken(t, w.team, w.device, first, "1 day", "manage")
	b := w.sqlToken(t, w.team, w.device, second, "1 day", "manage")
	own := w.sqlToken(t, w.team, w.device, w.sub, "1 day", "manage")
	pause := func(by store.PauseActor) store.Paused {
		t.Helper()
		p, err := devices.Pause(ctx, w.team, w.device, by)
		if err != nil {
			t.Fatal(err)
		}
		if err := devices.SetPaused(ctx, w.team.String(), w.device.String(), false); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pause(store.PauseActor{Token: a})
	pause(store.PauseActor{Token: b})
	flush(t, s, w.team)
	sent := w.sentTo(w.team)
	if len(sent) != 2 {
		t.Fatalf("two creators' pauses: %d events", len(sent))
	}
	for i, sub := range []uuid.UUID{first, second} {
		if ev := sent[i]; ev.ActorKind != "key" || ev.Actor == nil || *ev.Actor != sub.String() {
			t.Fatalf("pause %d: %+v", i, ev)
		}
	}
	// The first creator again, under the hour after their delivered one:
	// folded into it, nothing sent.
	pause(store.PauseActor{Token: a})
	flush(t, s, w.team)
	if sent := w.sentTo(w.team); len(sent) != 2 {
		t.Fatalf("a creator's second pause under the hour: %d events", len(sent))
	}

	pause(store.PauseActor{User: w.owner})
	if p := pause(store.PauseActor{Token: own}); len(p.Notices) != 1 || p.Notices[0].UserID != w.second || p.ActorUser == nil || *p.ActorUser != w.owner {
		t.Fatalf("the owner's own token's pause: %+v", p)
	}
	flush(t, s, w.team)
	if sent := w.sentTo(w.team); len(sent) != 3 || sent[2].ActorKind != "person" || *sent[2].Actor != w.sub.String() {
		t.Fatalf("a person's pause and their own token's: %d events %+v", len(sent), sent)
	}
}
