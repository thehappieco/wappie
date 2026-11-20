package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
)

// TestEveryWaitingTokenWaitsInTheSnapshot ties PR 7 to PR 8: every token
// that token.waiting lists on a number is waiting: true on that number's
// item of the snapshot. It is a subset, not equality. The snapshot says
// what the spec says: an applied Read without a grant at the number's
// current epoch. token.waiting lists only what a person can seal now, so
// it also needs a live token (no stop of Wappie's own, an active
// workspace), a reading key Wappie pinned and never saw change, and an
// archive key on the number. Each pair the snapshot alone reports waiting
// is one of those cases (docs/contract.md, "The grant page"). The one
// exception is a number not linked yet: it is no item of the snapshot,
// and token.waiting still lists a token that waits on it.
func TestEveryWaitingTokenWaitsInTheSnapshot(t *testing.T) {
	w := newAuthWorld(t)
	ctx := context.Background()
	a := snapshotNumber(w, "Vendas", "5511900000001")
	b := snapshotNumber(w, "Suporte", "5511900000002")
	c := snapshotNumber(w, "Entregas", "5511900000003")

	// Sealed: it reads a, so it waits nowhere.
	sealed := w.Token(tokentest.Read(a))
	// Unsealed: it waits on a and b in both.
	unsealed := w.TokenUnsealed(tokentest.Read(a), tokentest.Read(b))
	// Sealed on c, then c's key rotates: it waits on c in both.
	rotated := w.Token(tokentest.Read(c))
	// Send only: no Read, so it waits nowhere.
	sender := w.TokenUnsealed(tokentest.Send(b))
	// An operator's stop: the snapshot lists it, token.waiting does not.
	stopped := w.TokenUnsealed(tokentest.Read(b))
	// Its record brings another reading key: the snapshot only.
	changed := w.TokenUnsealed(tokentest.Read(b))
	// No reading key, so no identity to seal for: the snapshot only.
	keyless := &tokentest.Token{ID: uuid.New(), Perms: []tokentest.Perm{tokentest.Read(b)}}
	keyless.Text, keyless.Selector, keyless.Hash = tokentest.Mint()
	w.Commit(keyless)
	if _, err := w.Tokens.JudgeTokenGrants(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}

	w.Rotate(c, 2)
	w.Exec(`INSERT INTO contract_token_stops (selector, cause, stopped_by) VALUES ($1, 'operator', 'test')`, stopped.Selector)
	changed.Version++
	changed.Key = tokentest.ReadingKey(t)
	w.Commit(changed)
	var keyChanged bool
	w.Scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT key_changed_at IS NOT NULL FROM contract_tokens WHERE id = $1`, changed.ID).Scan(&keyChanged)
	})
	if !keyChanged {
		t.Fatal("the second reading key was not seen as a change")
	}

	// check reads both at one moment. Every pair token.waiting lists must
	// be waiting in the snapshot. both is what token.waiting lists, and
	// only is what the snapshot alone reports waiting.
	check := func(when string, both, only []string) {
		t.Helper()
		listed := waitingNow(t, w)
		snap, items := snapshotItems(t, w, w.Tenant)
		waits := map[string]bool{}
		for _, it := range snap.Items {
			for _, tok := range it.Tokens {
				if tok.Waiting {
					waits[it.ID.String()+"/"+tok.ID.String()] = true
				}
			}
		}
		got := []string{}
		for _, l := range listed {
			key := l.Device.String() + "/" + l.Token.String()
			got = append(got, key)
			it, ok := items[l.Device]
			if !ok {
				t.Errorf("%s: token.waiting lists %s, a number the snapshot does not list", when, key)
				continue
			}
			if !waits[key] {
				tok, _ := tokenOn(it, &tokentest.Token{ID: l.Token})
				t.Errorf("%s: token.waiting lists %s, the snapshot has %+v", when, key, tok)
			}
			delete(waits, key)
		}
		slices.Sort(got)
		if !slices.Equal(got, both) {
			t.Errorf("%s: token.waiting lists %v, want %v", when, got, both)
		}
		rest := []string{}
		for key := range waits {
			rest = append(rest, key)
		}
		slices.Sort(rest)
		if !slices.Equal(rest, only) {
			t.Errorf("%s: the snapshot alone has %v waiting, want %v", when, rest, only)
		}
	}
	type pair = [2]uuid.UUID
	onB := []pair{{b, stopped.ID}, {b, changed.ID}, {b, keyless.ID}}

	check("tokens on", pairs(pair{a, unsealed.ID}, pair{b, unsealed.ID}, pair{c, rotated.ID}), pairs(onB...))
	// The sender is listed on b, and waits nowhere.
	_, items := snapshotItems(t, w, w.Tenant)
	if tok, ok := tokenOn(items[b], sender); !ok || !tok.Send || tok.Read || tok.Waiting {
		t.Fatalf("the sender on b: listed %v, %+v", ok, tok)
	}

	// A workspace that is not active: no token is live, so token.waiting
	// lists none, while the snapshot still reports every Read without a
	// grant.
	w.Exec(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, w.Tenant)
	check("the workspace suspended", pairs(),
		pairs(append([]pair{{a, unsealed.ID}, {b, unsealed.ID}, {c, rotated.ID}}, onB...)...))
	w.Exec(`UPDATE tenants SET status = 'active' WHERE id = $1`, w.Tenant)

	// An archive reset that keeps the numbers: no key and no grant, so
	// nothing to seal and every Read waits in the snapshot.
	w.ResetArchive()
	everyRead := append([]pair{{a, sealed.ID}, {a, unsealed.ID}, {b, unsealed.ID}, {c, rotated.ID}}, onB...)
	check("after an archive reset", pairs(), pairs(everyRead...))
	// a gets a key again: its Reads wait in both.
	w.Rotate(a, 1)
	check("a with a new key", pairs(pair{a, sealed.ID}, pair{a, unsealed.ID}),
		pairs(append([]pair{{b, unsealed.ID}, {c, rotated.ID}}, onB...)...))

	// The one exception: a number not linked yet is no item of the
	// snapshot, while token.waiting lists a token that waits on it.
	pending := w.Number("Nova")
	early := w.TokenUnsealed(tokentest.Read(pending))
	if got, want := pairsOf(t, w, pending), pairs(pair{pending, early.ID}); !slices.Equal(got, want) {
		t.Fatalf("a number not linked yet: token.waiting lists %v, want %v", got, want)
	}
	if _, items := snapshotItems(t, w, w.Tenant); len(items) != 3 {
		t.Fatalf("the snapshot lists %d numbers, want the 3 linked ones", len(items))
	}

	// Tokens off: the snapshot has no tokens, and token.waiting lists none.
	w.Exec(`UPDATE contract_token_state SET mode = 'off'`)
	check("tokens off", pairs(), pairs())
}

// waitingNow is token.waiting on devices now (every number with none).
func waitingNow(t *testing.T, w *tokentest.World, devices ...uuid.UUID) []store.TokenWaiting {
	t.Helper()
	listed, err := w.Tokens.WaitingTokens(context.Background(), w.Tenant, devices, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return listed
}

// pairsOf is token.waiting on devices now, as "device/token" sorted.
func pairsOf(t *testing.T, w *tokentest.World, devices ...uuid.UUID) []string {
	t.Helper()
	out := []string{}
	for _, l := range waitingNow(t, w, devices...) {
		out = append(out, l.Device.String()+"/"+l.Token.String())
	}
	slices.Sort(out)
	return out
}
