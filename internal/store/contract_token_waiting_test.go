package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
)

// waiting is WaitingTokens of devices in ws, as "device/token" sorted.
func (w *tokenWorld) waiting(ws uuid.UUID, devices ...uuid.UUID) []string {
	w.t.Helper()
	got, err := w.tokens.WaitingTokens(context.Background(), ws, devices, w.now)
	if err != nil {
		w.t.Fatal(err)
	}
	out := []string{}
	for _, t := range got {
		out = append(out, t.Device.String()+"/"+t.Token.String())
	}
	slices.Sort(out)
	return out
}

func pairs(ps ...[2]uuid.UUID) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p[0].String()+"/"+p[1].String())
	}
	slices.Sort(out)
	return out
}

// TestTokenWaitingListsWhatAwaitsAKey (token.waiting, the plan's 5.4): a
// live token with an applied Read and no grant at the number's current
// epoch waits there; a sealed one waits again after a rotation. A Read not
// applied, a key changed, no key at all, a revoked token, tokens off, a
// number with no archive key, and another workspace list nothing.
func TestTokenWaitingListsWhatAwaitsAKey(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	a, b := w.number(uuid.Nil), w.number(uuid.Nil)
	w.tokensOn()
	both, unsealed, notApplied, changed, keyless, revoked := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	waitingSub := uuid.New()
	w.linked("waiting", "admin", waitingSub, false)
	key := func() func(*kc.TokenRecord) {
		k := readingKey(t)
		return func(r *kc.TokenRecord) { r.ReadingKey = k }
	}
	changedKey := key()
	w.page(false,
		w.record(both, 1, grants(a, w.ownerSub, w.now, kc.CanRead), grants(b, w.ownerSub, w.now, kc.CanRead), key()),
		w.record(unsealed, 1, grants(b, w.ownerSub, w.now, kc.CanRead), key()),
		w.record(notApplied, 1, grants(b, waitingSub, w.now, kc.CanRead), key()),
		w.record(changed, 1, grants(b, w.ownerSub, w.now, kc.CanRead), changedKey),
		w.record(keyless, 1, grants(b, w.ownerSub, w.now, kc.CanRead)),
		w.record(revoked, 1, grants(b, w.ownerSub, w.now, kc.CanRead), key()))
	w.judge()
	if err := w.seal(both, a, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	// Another key for changed, and revoked revoked.
	w.page(false, w.record(changed, 2, grants(b, w.ownerSub, w.now, kc.CanRead), key()),
		w.record(revoked, 2, revokedBy(kc.RevokedInConsole, w.now)))
	if s := w.token(changed); !s.KeyChanged {
		t.Fatal("no key change")
	}

	want := pairs([2]uuid.UUID{b, both}, [2]uuid.UUID{b, unsealed})
	if got := w.waiting(w.tenant); !slices.Equal(got, want) {
		t.Fatalf("every number: %v, want %v", got, want)
	}
	if got := w.waiting(w.tenant, b, uuid.New()); !slices.Equal(got, want) {
		t.Fatalf("b and a number that is not: %v, want %v", got, want)
	}
	if got := w.waiting(w.tenant, a); len(got) != 0 {
		t.Fatalf("a, sealed: %v", got)
	}
	// A rotation leaves the sealed token waiting again.
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, a, 2, pub); err != nil {
		t.Fatal(err)
	}
	if got, want := w.waiting(w.tenant, a), pairs([2]uuid.UUID{a, both}); !slices.Equal(got, want) {
		t.Fatalf("a after a rotation: %v, want %v", got, want)
	}
	// Another workspace sees none of them.
	other := uuid.MustParse(newTenant(t, w.pool, "other"))
	if got := w.waiting(other); len(got) != 0 {
		t.Fatalf("another workspace: %v", got)
	}
	if got := w.waiting(other, a, b); len(got) != 0 {
		t.Fatalf("another workspace, naming the numbers: %v", got)
	}
	// Tokens off: none is live.
	w.exec(`UPDATE contract_token_state SET mode = 'off'`)
	if got := w.waiting(w.tenant); len(got) != 0 {
		t.Fatalf("tokens off: %v", got)
	}
	w.exec(`UPDATE contract_token_state SET mode = 'on'`)
	// An archive reset that keeps the numbers: no key, nothing to seal.
	if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
		t.Fatal(err)
	}
	if got := w.waiting(w.tenant); len(got) != 0 {
		t.Fatalf("with no archive key: %v", got)
	}
	w.rekey(a)
	if got, want := w.waiting(w.tenant), pairs([2]uuid.UUID{a, both}); !slices.Equal(got, want) {
		t.Fatalf("after the new key: %v, want %v", got, want)
	}
}

// TestATokensIdentityIsItsGrantsUser: Identity is the user a token's
// grants are sealed to; a token with no reading key has none, and a
// revoked one's was dropped.
func TestATokensIdentityIsItsGrantsUser(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	reading := w.readingToken(device, readingKey(t))
	keyless, revoked := uuid.New(), uuid.New()
	w.page(false, w.record(keyless, 1, grants(device, w.ownerSub, w.now, kc.CanRead)))
	gone := w.readingToken(device, readingKey(t))
	w.page(false, w.record(gone, 2, revokedBy(kc.RevokedInConsole, w.now)))
	identity, _ := w.identityOf(reading)
	got, err := w.tokens.Identity(ctx, store.TokenAuth{ID: reading, Tenant: w.tenant})
	if err != nil || identity == nil || got != *identity {
		t.Fatalf("the identity: %s %v, want %v", got, err, identity)
	}
	for name, id := range map[string]uuid.UUID{"no reading key": keyless, "revoked": gone, "unknown": revoked} {
		if _, err := w.tokens.Identity(ctx, store.TokenAuth{ID: id, Tenant: w.tenant}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Another workspace's token is unknown.
	other := uuid.MustParse(newTenant(t, w.pool, "other"))
	if _, err := w.tokens.Identity(ctx, store.TokenAuth{ID: reading, Tenant: other}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("under another workspace: %v", err)
	}
}
