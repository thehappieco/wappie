package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
)

// Step 7's snapshot items and the token's pause (the plan's 6.2, 6.3 and
// 10.5): each item's ordinal and tokens while the token mode is on, and
// none of them while it is off; and a token's pause as its creator's.

// snapshotNumber is a number of w's workspace that a snapshot lists: a
// phone number of its own, read by the owner.
func snapshotNumber(w *tokentest.World, label, pn string) uuid.UUID {
	w.T.Helper()
	device := w.Number(label)
	w.ExecIn(`UPDATE devices SET pn = $2 WHERE id = $1`, device, pn+"@s.whatsapp.net")
	return device
}

// snapshotItems is the workspace's snapshot now, its items by id.
func snapshotItems(t *testing.T, w *tokentest.World, ws uuid.UUID) (store.ContractSnapshot, map[uuid.UUID]store.ContractSnapshotItem) {
	t.Helper()
	snap, err := store.NewContract(w.Pool).Snapshot(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	items := map[uuid.UUID]store.ContractSnapshotItem{}
	for _, it := range snap.Items {
		items[it.ID] = it
	}
	return snap, items
}

func ordinalOf(it store.ContractSnapshotItem) int {
	if it.Ordinal == nil {
		return 0
	}
	return *it.Ordinal
}

// TestSnapshotOrdinal (the plan's 10.5): with the token mode on, each item
// carries its number's ordinal: the lowest free one at its creation, kept
// across a rename, a deletion and a recovery; a purge frees it for the
// next number; a moved-out number takes a free one in its new workspace;
// a number with none (past 9999) goes without. An unlabelled number has
// no label, never its push name, and its ordinal names it. With the mode
// off no item has one.
func TestSnapshotOrdinal(t *testing.T) {
	w := newAuthWorld(t)
	ctx := context.Background()
	one := snapshotNumber(w, "Vendas", "5511900000001")
	two := snapshotNumber(w, "Suporte", "5511900000002")
	three := snapshotNumber(w, "Entregas", "5511900000003")
	// No label of its own, a push name: the snapshot names it by its
	// ordinal alone.
	w.ExecIn(`UPDATE devices SET label = '', push_name = 'Loja da Ana' WHERE id = $1`, three)
	want := func(when string, ws uuid.UUID, ordinals map[uuid.UUID]int) map[uuid.UUID]store.ContractSnapshotItem {
		t.Helper()
		snap, items := snapshotItems(t, w, ws)
		if !snap.TokenMode {
			t.Fatalf("%s: the token mode is off", when)
		}
		for id, o := range ordinals {
			it, ok := items[id]
			if !ok {
				t.Fatalf("%s: %s is not listed", when, id)
			}
			if got := ordinalOf(it); got != o {
				t.Errorf("%s: %s has ordinal %d, want %d", when, id, got, o)
			}
			if it.Tokens == nil {
				t.Errorf("%s: %s has no token list", when, id)
			}
		}
		return items
	}
	items := want("at creation", w.Tenant, map[uuid.UUID]int{one: 1, two: 2, three: 3})
	if l := items[three].Label; l != nil {
		t.Fatalf("an unlabelled number's label: %q", *l)
	}

	if err := w.Devices.Rename(ctx, w.Tenant.String(), two.String(), "Suporte 2"); err != nil {
		t.Fatal(err)
	}
	want("after a rename", w.Tenant, map[uuid.UUID]int{two: 2})
	w.Delete(two)
	if items := want("after a deletion", w.Tenant, map[uuid.UUID]int{two: 2}); items[two].State != store.SnapshotDeleted {
		t.Fatalf("the deleted number: %+v", items[two])
	}
	if _, err := w.Devices.Recover(ctx, w.Tenant, w.Owner, two); err != nil {
		t.Fatal(err)
	}
	want("after a recovery", w.Tenant, map[uuid.UUID]int{two: 2})

	// A purge frees the ordinal: the next number takes it.
	w.Delete(three)
	w.Scoped(func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error {
			_, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1`, three)
			return err
		})
	})
	four := snapshotNumber(w, "Cobrança", "5511900000004")
	if items := want("after a purge", w.Tenant, map[uuid.UUID]int{one: 1, two: 2, four: 3}); len(items) != 3 {
		t.Fatalf("after the purge: %d items", len(items))
	}

	// A move-out, as TransferPersonal's session moves it: the target's
	// lowest free ordinal, which holds one number already.
	target := uuid.New()
	w.Exec(`INSERT INTO tenants (id, name) VALUES ($1, 'Pessoal')`, target)
	if err := pg.InTenantTx(ctx, w.Pool, target.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO devices (tenant_id, label, pn) VALUES ($1, 'Minha', '5511900000099@s.whatsapp.net')`, target)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w.Scoped(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.device_move_id', $1, true), set_config('app.device_move_source', $2, true),
			set_config('app.device_move_target', $3, true)`, one.String(), w.Tenant.String(), target.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE devices SET tenant_id = $2 WHERE id = $1`, one, target)
		return err
	})
	want("in the target after a move-out", target, map[uuid.UUID]int{one: 2})
	want("in the source after a move-out", w.Tenant, map[uuid.UUID]int{two: 2, four: 3})

	// Past 9999 a number has none, and goes without.
	w.ExecIn(`UPDATE devices SET ordinal = NULL WHERE id = $1`, four)
	if _, items := snapshotItems(t, w, w.Tenant); items[four].Ordinal != nil || items[four].Tokens == nil {
		t.Fatalf("a number with no ordinal: %+v", items[four])
	}

	// The mode off: no ordinal and no token list, on any item.
	w.Exec(`UPDATE contract_token_state SET mode = 'off'`)
	for _, ws := range []uuid.UUID{w.Tenant, target} {
		snap, _ := snapshotItems(t, w, ws)
		if snap.TokenMode || snap.TokensExpire != nil || len(snap.Items) == 0 {
			t.Fatalf("the mode off: %+v", snap)
		}
		for _, it := range snap.Items {
			if it.Ordinal != nil || it.Tokens != nil {
				t.Fatalf("the mode off, %s: ordinal %v, tokens %v", it.ID, it.Ordinal, it.Tokens)
			}
		}
	}
}

// tokenOn is tok's standing on the item, and whether it is listed there.
func tokenOn(it store.ContractSnapshotItem, tok *tokentest.Token) (store.ContractSnapshotToken, bool) {
	for _, s := range it.Tokens {
		if s.ID == tok.ID {
			return s, true
		}
	}
	return store.ContractSnapshotToken{}, false
}

// TestSnapshotTokens (the plan's 10.5): each item lists, by id and in id
// order, the tokens with a perm Wappie applied on it: reads with a grant to
// the token's identity at the number's current epoch, waiting without it
// (after a key rotation); a perm pending, waiting for its judge or refused
// lists nothing; a token revoked (on its row, in the sticky set, or by the
// belt), expired or unlisted is left out, and one Wappie stops on its own
// is listed; a deleted number lists none; a token is never one of the
// people, the protected or the backups. The earliest expiry of a token
// listed, by its row or its sticky row, is the snapshot's TokensExpire.
func TestSnapshotTokens(t *testing.T) {
	w := newAuthWorld(t)
	ctx := context.Background()
	a := snapshotNumber(w, "Vendas", "5511900000001")
	b := snapshotNumber(w, "Suporte", "5511900000002")

	reader := w.Token(tokentest.Read(a), tokentest.Send(a))
	manager := w.Token(tokentest.Manage(a))
	rotated := w.Token(tokentest.Read(b))
	stopped := w.Token(tokentest.Send(a))
	revoked := w.Token(tokentest.Send(a))
	sticky := w.Token(tokentest.Send(a))
	expired := w.Token(tokentest.Send(a))
	unlisted := w.Token(tokentest.Send(a))
	// The belt: a token created before its creator's credentials were
	// revoked, the others after.
	belt := &tokentest.Token{ID: uuid.New(), Key: reader.Key, Perms: []tokentest.Perm{tokentest.Send(a)},
		Created: time.Now().UTC().Truncate(time.Second).Add(-72 * time.Hour)}
	belt.Text, belt.Selector, belt.Hash = tokentest.Mint()
	w.Commit(belt)
	if _, err := w.Tokens.JudgeTokenGrants(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	w.Exec(`UPDATE contract_accounts SET credentials_revoked_at = clock_timestamp() - interval '48 hours' WHERE sub = $1`, w.OwnerSub)

	w.Rotate(b, 2)
	w.Exec(`INSERT INTO contract_token_stops (selector, cause, stopped_by) VALUES ($1, 'operator', 'test')`, stopped.Selector)
	w.ExecIn(`UPDATE contract_tokens SET revoked_at = clock_timestamp(), revoked_reason = 'revoked' WHERE id = $1`, revoked.ID)
	w.Exec(`INSERT INTO contract_token_sticky (token_id, ended, until) VALUES ($1, 'revoked', clock_timestamp() + interval '1 day')`, sticky.ID)
	w.ExecIn(`UPDATE contract_tokens SET expires_at = clock_timestamp() - interval '1 minute' WHERE id = $1`, expired.ID)
	w.ExecIn(`UPDATE contract_tokens SET unlisted_at = clock_timestamp() WHERE id = $1`, unlisted.ID)
	// On b, perms Wappie has not applied: the manager's read pending, its
	// send waiting for its judge, its manage refused.
	for _, p := range []struct{ perm, state, code string }{{"read", "pending", ""}, {"send", "waiting", ""}, {"manage", "refused", "local_role"}} {
		var code *string
		if p.code != "" {
			code = &p.code
		}
		w.ExecIn(`INSERT INTO contract_token_perms (token_id, tenant_id, device_id, perm, granted_by, granted_at, generation, version, state, code)
			VALUES ($1, $2, $3, $4, $5, clock_timestamp(), $6, 1, $7, $8)`, manager.ID, w.Tenant, b, p.perm, w.OwnerSub, w.Gen, p.state, code)
	}
	// The manager's expiry is the soonest.
	var soonest time.Time
	w.Scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE contract_tokens SET expires_at = date_trunc('second', clock_timestamp()) + interval '1 hour'
			WHERE id = $1 RETURNING expires_at`, manager.ID).Scan(&soonest)
	})

	snap, items := snapshotItems(t, w, w.Tenant)
	if snap.TokensExpire == nil || !snap.TokensExpire.Equal(soonest) {
		t.Fatalf("TokensExpire %v, want the manager's %v", snap.TokensExpire, soonest)
	}
	for _, c := range []struct {
		name   string
		item   uuid.UUID
		tok    *tokentest.Token
		listed bool
		want   store.ContractSnapshotToken
	}{
		{"a reader", a, reader, true, store.ContractSnapshotToken{Read: true, Send: true, Reads: true}},
		{"a manager", a, manager, true, store.ContractSnapshotToken{Manage: true}},
		{"a reader after the key's rotation", b, rotated, true, store.ContractSnapshotToken{Read: true, Waiting: true}},
		{"an operator's stop", a, stopped, true, store.ContractSnapshotToken{Send: true}},
		{"perms not applied", b, manager, false, store.ContractSnapshotToken{}},
		{"revoked", a, revoked, false, store.ContractSnapshotToken{}},
		{"revoked in the sticky set", a, sticky, false, store.ContractSnapshotToken{}},
		{"the belt", a, belt, false, store.ContractSnapshotToken{}},
		{"expired", a, expired, false, store.ContractSnapshotToken{}},
		{"unlisted", a, unlisted, false, store.ContractSnapshotToken{}},
	} {
		got, listed := tokenOn(items[c.item], c.tok)
		c.want.ID = c.tok.ID
		if listed != c.listed || (listed && got != c.want) {
			t.Errorf("%s: listed %v %+v, want %v %+v", c.name, listed, got, c.listed, c.want)
		}
	}
	// A token is never a person: its identity, which holds the key of a,
	// is never among the people, the protected or the backups.
	if it := items[a]; len(it.People) != 1 || it.People[0].Sub != w.OwnerSub || it.OtherBackups != 0 ||
		len(it.Protected) != 1 || it.Protected[0] != w.OwnerSub {
		t.Fatalf("a token in the people of a: %+v", it)
	}
	for _, it := range snap.Items {
		for i, tok := range it.Tokens {
			if (tok.Reads || tok.Waiting) && !tok.Read || tok.Reads && tok.Waiting {
				t.Errorf("%s: %+v reads or waits without Read, or both", it.ID, tok)
			}
			if i > 0 && it.Tokens[i-1].ID.String() >= tok.ID.String() {
				t.Errorf("%s: the tokens are not in id order: %v", it.ID, it.Tokens)
			}
		}
	}

	// A sticky expiry sooner than any row's is the token's.
	var stickier time.Time
	if err := w.Pool.QueryRow(ctx, `INSERT INTO contract_token_sticky (token_id, earliest_expires_at, until)
		VALUES ($1, date_trunc('second', clock_timestamp()) + interval '30 minutes', clock_timestamp() + interval '1 day')
		RETURNING earliest_expires_at`, stopped.ID).Scan(&stickier); err != nil {
		t.Fatal(err)
	}
	if snap, items := snapshotItems(t, w, w.Tenant); snap.TokensExpire == nil || !snap.TokensExpire.Equal(stickier) {
		t.Fatalf("TokensExpire %v, want the sticky row's %v", snap.TokensExpire, stickier)
	} else if _, listed := tokenOn(items[a], stopped); !listed {
		t.Fatal("a token with a sticky expiry still ahead is not listed")
	}

	// A deleted number: no token holds it, though a perm row were left
	// on it (its deletion deletes them in its own write).
	w.Delete(a)
	w.Scoped(func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error {
			_, err := tx.Exec(ctx, `INSERT INTO contract_token_perms (token_id, tenant_id, device_id, perm, granted_by, granted_at,
					generation, version, state)
				VALUES ($1, $2, $3, 'send', $4, clock_timestamp(), $5, 1, 'applied')`, reader.ID, w.Tenant, a, w.OwnerSub, w.Gen)
			return err
		})
	})
	if _, items := snapshotItems(t, w, w.Tenant); items[a].State != store.SnapshotDeleted || items[a].Tokens == nil || len(items[a].Tokens) != 0 {
		t.Fatalf("the deleted number: %+v", items[a])
	}
}

// TestTheTokenGateMakesEverySnapshotDue (the plan's 6.2): turning the token
// mode on, or off, makes every recorded workspace's snapshot due now, a
// parked one's included, so the snapshots follow the gate at once; a
// switch to the mode it is in changes nothing.
func TestTheTokenGateMakesEverySnapshotDue(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	if _, err := w.contract.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	team, home := recordWorkspace(t, w.pool, "team"), recordWorkspace(t, w.pool, "personal")
	later := func() {
		t.Helper()
		w.exec(`UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '1 hour',
			parked_at = CASE WHEN workspace_id = $1 THEN clock_timestamp() END`, home)
	}
	for _, mode := range []string{store.TokensOn, store.TokensOn, store.TokensOff} {
		later()
		change, err := w.tokens.SetMode(ctx, mode, w.now)
		if err != nil {
			t.Fatal(err)
		}
		for _, ws := range []uuid.UUID{team, home} {
			r := readSnapshotRow(t, w.pool, ws)
			due := r.DueIn <= 0 && r.ParkedAt == nil
			if due != change.Changed {
				t.Errorf("tokens %s (changed %v): %s due in %v, parked %v", mode, change.Changed, ws, r.DueIn, r.ParkedAt)
			}
		}
	}
}

// TestSnapshotDueAtATokensExpiry (the plan's 6.2): an accepted snapshot
// that lists a token is due again the debounce after the token's expiry,
// in the same write as its outcome, when that is sooner than the hourly
// one: so expiries under the debounce apart share one snapshot. A later
// expiry leaves the hourly one, an expiry already past makes it due at
// once, a due time set since the measurement stands unless the expiry's is
// sooner, and a failure keeps its backoff whatever the expiry.
func TestSnapshotDueAtATokensExpiry(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	ws := recordWorkspace(t, pool, "team")
	times := snapshotTimes
	times.Debounce = 2 * time.Second
	// sent records outcome for a snapshot measured now that lists a token
	// expiring at expires from now, after a due time set since at set from
	// now (none if empty); it gives the expiry and the row after it.
	sent := func(name string, outcome store.ContractSnapshotOutcome, expires time.Duration, set string) (time.Time, snapshotRow) {
		t.Helper()
		// The sender measures a snapshot once it is due.
		if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = least(snapshot_due_at, clock_timestamp())
			WHERE workspace_id = $1`, ws); err != nil {
			t.Fatal(err)
		}
		measured := dbClock(t, pool, "0")
		seq, ok, err := c.SnapshotSeqForTest(ctx, ws, measured)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", name, ok, err)
		}
		if set != "" {
			if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + $2::interval
				WHERE workspace_id = $1`, ws, set); err != nil {
				t.Fatal(err)
			}
		}
		at := measured.Add(expires).Truncate(time.Second)
		rec, err := c.SnapshotSent(ctx, ws, seq, measured, &at, outcome, "", times)
		if err != nil || !rec.Recorded || rec.Again != (set != "") {
			t.Fatalf("%s: %+v %v", name, rec, err)
		}
		return at, readSnapshotRow(t, pool, ws)
	}
	at, r := sent("an expiry in a minute", store.SnapshotAccepted, time.Minute, "")
	if !r.DueAt.Equal(at.Add(2 * time.Second)) {
		t.Errorf("an expiry in a minute: due %v, want %v", r.DueAt, at.Add(2*time.Second))
	}
	if _, r := sent("an expiry in two hours", store.SnapshotAccepted, 2*time.Hour, ""); r.DueIn < 54*time.Minute || r.DueIn > 55*time.Minute {
		t.Errorf("an expiry after the hourly one: due in %v", r.DueIn)
	}
	at, r = sent("an expiry just past", store.SnapshotAccepted, -10*time.Second, "")
	if !r.DueAt.Equal(at.Add(2*time.Second)) || r.DueIn > 0 {
		t.Errorf("an expiry just past: due %v (in %v), want %v", r.DueAt, r.DueIn, at.Add(2*time.Second))
	}
	if _, r := sent("a sooner due time set since", store.SnapshotAccepted, time.Minute, "10 seconds"); r.DueIn > 10*time.Second {
		t.Errorf("a due time set since, sooner than the expiry: due in %v", r.DueIn)
	}
	at, r = sent("a later due time set since", store.SnapshotAccepted, 3*time.Second, "1 minute")
	if !r.DueAt.Equal(at.Add(2 * time.Second)) {
		t.Errorf("a due time set since, later than the expiry: due %v, want %v", r.DueAt, at.Add(2*time.Second))
	}
	if _, r := sent("a failure", store.SnapshotFailed, -time.Minute, ""); r.DueIn <= 0 || r.Tries != 1 {
		t.Errorf("a failure with an expiry past: due in %v, tries %d", r.DueIn, r.Tries)
	}
}
