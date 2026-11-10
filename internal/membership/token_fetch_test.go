package membership

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/pg"
)

// fetchedAt is the token's fetched_at, nil while no GET stamped it.
func (w *tokenWorld) fetchedAt(t *testing.T, id uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := pg.InTenantTx(context.Background(), w.pool, w.home.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT fetched_at FROM contract_tokens WHERE id = $1`, id).Scan(&at)
	}); err != nil {
		t.Fatal(err)
	}
	return at
}

// setFetched sets the token's fetched_at to at.
func (w *tokenWorld) setFetched(t *testing.T, id uuid.UUID, at time.Time) {
	t.Helper()
	if err := pg.InTenantTx(context.Background(), w.pool, w.home.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE contract_tokens SET fetched_at = $2 WHERE id = $1`, id, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestATokenGrantNeedsAFreshSignedGET (the plan's 10.4), the GET's part: a
// token whose last signed GET is 61 s old is asked again, and the answer
// stamps fetched_at with the time the GET was sent; a narrowing the feed
// has not brought yet is applied by it; a signed not_found stamps nothing
// and is kept a minute, in which the token is not asked again; with no
// transport nothing is asked.
func TestATokenGrantNeedsAFreshSignedGET(t *testing.T) {
	w := newTokenWorld(t)
	stop := run(t, w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t)))
	id, _ := w.token(t, kc.CanRead, kc.CanSend)
	eventually(t, 10*time.Second, "the token's perms applied", func() bool {
		p := w.perms(t, id)
		return p[kc.CanRead] == "applied" && p[kc.CanSend] == "applied"
	})
	// The feed brings nothing more: only the GETs below do.
	stop()
	ctx := context.Background()
	tok := uuid.MustParse(id)
	gets := func() int { return w.fake.Count(contracttest.CallToken) }

	stale := time.Now().Add(-61 * time.Second)
	w.setFetched(t, tok, stale)
	before, sent := gets(), time.Now()
	if err := w.members.FetchToken(ctx, w.home, tok); err != nil {
		t.Fatalf("the GET: %v", err)
	}
	if at := w.fetchedAt(t, tok); at == nil || at.Before(sent) || at.After(time.Now()) {
		t.Fatalf("fetched_at %v, want the GET's send time, at or after %v", at, sent)
	}
	if n := gets() - before; n != 1 {
		t.Fatalf("%d GETs", n)
	}

	// A narrowing the feed has not brought: the GET applies it.
	if err := w.fake.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	if err := w.fake.UngrantToken(id, "wappie", w.number.String(), kc.CanSend); err != nil {
		t.Fatal(err)
	}
	if err := w.members.FetchToken(ctx, w.home, tok); err != nil {
		t.Fatalf("the narrowing GET: %v", err)
	}
	if p := w.perms(t, id); p[kc.CanSend] != "" || p[kc.CanRead] != "applied" {
		t.Fatalf("after the narrowing GET: %v", p)
	}

	// A signed not_found stamps nothing, and is kept a minute.
	w.setFetched(t, tok, stale)
	if err := w.fake.Refuse("wappie", contracttest.CallToken, kc.CodeNotFound); err != nil {
		t.Fatal(err)
	}
	before = gets()
	if err := w.members.FetchToken(ctx, w.home, tok); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("a not_found: %v", err)
	}
	if err := w.members.FetchToken(ctx, w.home, tok); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("within the minute: %v", err)
	}
	if n := gets() - before; n != 1 {
		t.Fatalf("%d GETs for a not_found and a second try within its minute", n)
	}
	if at := w.fetchedAt(t, tok); at == nil || !at.Equal(stale) {
		t.Fatalf("a not_found stamped %v", at)
	}
	// A minute on, it is asked again.
	w.members.mu.Lock()
	w.members.tokenMisses[tok] = time.Now().Add(-tokenMissFor)
	w.members.mu.Unlock()
	if err := w.members.FetchToken(ctx, w.home, tok); err != nil {
		t.Fatalf("a minute after the not_found: %v", err)
	}
	if n := gets() - before; n != 2 {
		t.Fatalf("%d GETs after the minute", n)
	}

	// No transport: nothing is asked.
	off := &Members{Contract: w.contract, Tokens: w.tokens, Log: w.members.Log}
	before = gets()
	if err := off.FetchToken(ctx, w.home, tok); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no transport: %v", err)
	}
	if gets() != before {
		t.Fatal("a GET with no transport")
	}
}

// TestATokensGETTakesItsPlaceInTheBudget: the grant page's GETs spend the
// freshness hook's budget, the workspace's among it, and one that would not
// get its place within the call's bound is throttled, with no call.
func TestATokensGETTakesItsPlaceInTheBudget(t *testing.T) {
	w := newTokenWorld(t)
	stop := run(t, w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t)))
	id, _ := w.token(t, kc.CanRead)
	eventually(t, 10*time.Second, "the token applied", func() bool { return w.perms(t, id)[kc.CanRead] == "applied" })
	stop()
	m := w.membersOn(w.members.Client, &membershiptest.Logs{})
	m.calls = &callBudget{perSecond: hookPerSecond, burst: hookBurst, tenantPerSecond: 0.001, tenantBurst: 1,
		tenants: map[uuid.UUID]*bucket{}, now: time.Now}
	tok := uuid.MustParse(id)
	before := w.fake.Count(contracttest.CallToken)
	if err := m.FetchToken(context.Background(), w.home, tok); err != nil {
		t.Fatalf("the first GET: %v", err)
	}
	if err := m.FetchToken(context.Background(), w.home, tok); !errors.Is(err, errThrottled) {
		t.Fatalf("a GET past the workspace's budget: %v", err)
	}
	if n := w.fake.Count(contracttest.CallToken) - before; n != 1 {
		t.Fatalf("%d GETs", n)
	}
}
