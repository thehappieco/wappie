package access_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/vectors"

	"whatserver2/internal/access"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
)

// kitTokens is the kit's tokens.json (v0.9.0).
type kitTokens struct {
	Tokens []struct {
		Name, Token, Selector, Hash string
	} `json:"tokens"`
	Refused []struct {
		Name, Token string
		Step        int
	} `json:"refused"`
	Authorization []struct {
		Name   string
		Values []string
		Valid  bool
	} `json:"authorization"`
}

func readKitTokens(t *testing.T) kitTokens {
	t.Helper()
	raw, err := fs.ReadFile(vectors.FS, "platform/contract-v1/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var v kitTokens
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Tokens) == 0 || len(v.Refused) == 0 || len(v.Authorization) == 0 {
		t.Fatal("the kit's token vectors are empty")
	}
	return v
}

// TestTheDispatchOnTheKitsVectors: every authorization case that holds
// thc_ in some case is a token request, valid or not; "no header" and
// "Bearer alone" are not. Every refused text that holds thc_ in some case
// is a token's text; "empty", "thc-" and "tch_" are not. Every valid token
// is one.
func TestTheDispatchOnTheKitsVectors(t *testing.T) {
	v := readKitTokens(t)
	for _, c := range v.Authorization {
		want := c.Name != "no header" && c.Name != "Bearer alone"
		if got := access.TokenRequest(c.Values); got != want {
			t.Errorf("authorization %q: a token request %v, want %v", c.Name, got, want)
		}
	}
	for _, c := range v.Refused {
		want := strings.Contains(strings.ToLower(c.Token), "thc_")
		if got := access.TokenText(c.Token); got != want {
			t.Errorf("refused %q: a token's text %v, want %v", c.Name, got, want)
		}
	}
	for _, c := range v.Tokens {
		if !access.TokenText(c.Token) || !access.TokenRequest([]string{"Bearer " + c.Token}) {
			t.Errorf("token %q is not dispatched as a token", c.Name)
		}
	}
}

// TestASessionOrKeyContainingThcIsNotAToken (F2): a well-formed session or
// key whose random part holds thc_ in some case keeps its own path; the
// same text with anything around it inside a header that is not exactly
// "Bearer <text>" is a token request.
func TestASessionOrKeyContainingThcIsNotAToken(t *testing.T) {
	for _, marker := range []string{"thc_", "THC_", "ThC_", "tHc_"} {
		session := "AAAA" + marker + strings.Repeat("B", 35)
		key := "0a1b2c3d." + marker + strings.Repeat("C", 39)
		for name, text := range map[string]string{"session": session, "key": key} {
			if access.TokenText(text) || access.TokenText(" "+text+"\t") {
				t.Errorf("a %s holding %s is a token's text", name, marker)
			}
			for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
				if access.TokenRequest([]string{scheme + " " + text}) {
					t.Errorf("%s %s holding %s is a token request", scheme, name, marker)
				}
			}
			if !access.TokenRequest([]string{"Basic " + text}) || !access.TokenRequest([]string{"Bearer " + text, "Bearer x"}) {
				t.Errorf("a %s holding %s in a malformed header is not a token request", name, marker)
			}
		}
	}
	// A key's prefix is lowercase hex: one with a thc_ prefix is no key.
	if !access.TokenText("thc_abcd.secret") || !access.TokenText("0A1B2C3D.thc_") {
		t.Error("a text that is no well-formed key took a key's exemption")
	}
}

// TestAThcTokenNeverReachesSessionsOrKeys: a thc_ text is classified
// before anything trims it, and a Checker without tokens refuses it as a
// token (ErrInvalidToken), never as a session or a key (ErrInvalidKey). A
// text a session or key would accept after a trim is still a token's.
func TestAThcTokenNeverReachesSessionsOrKeys(t *testing.T) {
	v := readKitTokens(t)
	c := &access.Checker{}
	for _, text := range []string{v.Tokens[0].Token, " " + v.Tokens[0].Token, v.Tokens[0].Token + "\n", "THC_" + v.Tokens[0].Token[4:], "xthc_"} {
		if _, err := c.Authenticate(context.Background(), text); !errors.Is(err, store.ErrInvalidToken) {
			t.Errorf("%q: %v, want the token refusal", text, err)
		}
		if _, err := c.Recheck(context.Background(), text); !errors.Is(err, store.ErrInvalidToken) {
			t.Errorf("recheck %q: %v, want the token refusal", text, err)
		}
	}
	if _, err := c.Authenticate(context.Background(), "0a1b2c3d.secret"); !errors.Is(err, store.ErrInvalidKey) {
		t.Errorf("a key's text: %v", err)
	}
}

// TestASessionOrKeyContainingThcStillAuthenticates (F2), against the
// database: a key and a session whose secret holds thc_, THC_ and ThC_
// authenticate as themselves through the Checker that also takes tokens.
func TestASessionOrKeyContainingThcStillAuthenticates(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	w := tokentest.New(t, pool, uuid.Nil)
	ctx := context.Background()
	c := &access.Checker{Keys: store.NewAPIKeys(pool), Users: w.Users, Tokens: w.Tokens}
	owner, err := w.Users.Get(ctx, w.Tenant, w.Owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"thc_", "THC_", "ThC_"} {
		key := tokentest.KeyHolding(t, pool, w.Tenant, store.ScopeRead, marker)
		if a, err := c.Authenticate(ctx, key); err != nil || a.Key == uuid.Nil || a.IsToken() {
			t.Errorf("a key holding %s: %+v %v", marker, a, err)
		}
		session := tokentest.SessionHolding(t, pool, owner, marker)
		if a, err := c.Authenticate(ctx, session); err != nil || a.User != w.Owner || a.IsToken() {
			t.Errorf("a session holding %s: %+v %v", marker, a, err)
		}
	}
}

// fakeUse records AddTokenUse's batches, failing when told to.
type fakeUse struct {
	mu      sync.Mutex
	batches []store.TokenUse
	fail    error
}

func (f *fakeUse) AddTokenUse(_ context.Context, u store.TokenUse) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.batches = append(f.batches, u)
	return nil
}

// TestTokenUseCountsOncePerDayAndKeepsAFailedFlush: used once per token
// and UTC day in a process, however often; refusals by (number, perm,
// code), token-wide ones with neither; a failed flush keeps its counts for
// the next.
func TestTokenUseCountsOncePerDayAndKeepsAFailedFlush(t *testing.T) {
	f := &fakeUse{}
	u := &access.TokenUse{Store: f, Log: slog.New(slog.DiscardHandler)}
	tok, device := uuid.New(), uuid.New()
	// Yesterday's last minute, by the real clock: Flush forgets the days
	// before yesterday by time.Now, so a fixed date would count again once
	// it is two days old.
	y, m, d := time.Now().UTC().Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	day := today.Add(-time.Minute)
	for range 3 {
		u.Used(tok, day)
		u.Refused(tok, day, device, kc.CanSend, kc.UseStaleFeed)
	}
	u.Refused(tok, day, uuid.Nil, kc.CanRead, kc.UseRevoked)
	f.fail = errors.New("down")
	if err := u.Flush(context.Background()); err == nil {
		t.Fatal("the failed flush said nothing")
	}
	f.fail = nil
	u.Refused(tok, day, device, kc.CanSend, kc.UseStaleFeed)
	if err := u.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.Used(tok, day)
	u.Used(tok, day.Add(2*time.Minute)) // the next UTC day
	if err := u.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 2 {
		t.Fatalf("%d batches", len(f.batches))
	}
	first := f.batches[0]
	if len(first.Used) != 1 || len(first.Refusals) != 2 {
		t.Fatalf("the first batch: %+v", first)
	}
	for _, r := range first.Refusals {
		switch r.Code {
		case kc.UseStaleFeed:
			if r.Count != 4 || r.Device == nil || *r.Device != device || r.Perm == nil || *r.Perm != kc.CanSend {
				t.Errorf("the stale feed refusals: %+v", r)
			}
		case kc.UseRevoked:
			if r.Count != 1 || r.Device != nil || r.Perm != nil {
				t.Errorf("the token-wide refusal: %+v", r)
			}
		}
	}
	if second := f.batches[1]; len(second.Used) != 1 || !second.Used[0].Day.Equal(today) {
		t.Fatalf("the second batch counts the same day again, or not the next: %+v", second)
	}
}

// TestTokenUseIsBounded: past MaxUseKeys new keys are dropped with one
// WARN, and counts of the keys held go on.
func TestTokenUseIsBounded(t *testing.T) {
	var logs bytes.Buffer
	u := &access.TokenUse{Store: &fakeUse{}, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	now := time.Now()
	first := uuid.New()
	u.Used(first, now)
	for range access.MaxUseKeys + 10 {
		u.Used(uuid.New(), now)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Fatalf("%d warnings:\n%s", n, logs.String())
	}
}

// TestTokenWatchWakesOnlyItsToken: a notice of one token wakes its
// registrations and no other token's; "all" wakes every one; a cancelled
// registration is never woken.
func TestTokenWatchWakesOnlyItsToken(t *testing.T) {
	w := access.NewTokenWatch()
	a, b := uuid.New(), uuid.New()
	wa, cancelA := w.Register(a)
	wb, cancelB := w.Register(b)
	defer cancelB()
	woken := func(ch <-chan struct{}) bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
	w.Notify(a.String())
	if !woken(wa) || woken(wb) {
		t.Fatal("a token's notice woke the wrong registrations")
	}
	w.Notify("all")
	if !woken(wa) || !woken(wb) {
		t.Fatal("all did not wake every token")
	}
	cancelA()
	w.Notify(a.String())
	if woken(wa) {
		t.Fatal("a cancelled registration was woken")
	}
}

// TestTokenRateLimits: an address that keeps failing is refused before
// its token is looked at, even with the right secret; a stranger's wrong
// secrets never lock a token out, and past five a minute log one WARN that
// names the selector alone; text that is no token makes no subject.
func TestTokenRateLimits(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	w := tokentest.New(t, pool, uuid.Nil)
	tok := w.Token(tokentest.Read(w.Number("Vendas")))
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	c := &access.Checker{Tokens: w.Tokens, Limits: access.NewTokenLimits(nil, log), Log: log}
	ctx := context.Background()
	wrong := tok.Text[:21] + strings.Repeat("A", 42) + "A"
	// The stranger, from many addresses, all with the token's selector.
	for i := range 30 {
		if _, err := c.AuthenticateToken(ctx, wrong, "198.51.100."+string(rune('0'+i%10))); !errors.Is(err, store.ErrInvalidToken) {
			t.Fatalf("a wrong secret: %v", err)
		}
	}
	if _, err := c.AuthenticateToken(ctx, tok.Text, "192.0.2.1"); err != nil {
		t.Fatalf("a stranger locked the token out: %v", err)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 || !strings.Contains(logs.String(), "selector="+tok.Selector) {
		t.Fatalf("the selector's warning:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), tok.Text[21:]) || strings.Contains(logs.String(), wrong[21:]) {
		t.Fatal("a log holds a secret")
	}
	// One address guessing: refused once over its budget, its own good
	// token included; another address is not.
	for range 20 {
		_, _ = c.AuthenticateToken(ctx, "thc_garbled", "203.0.113.9")
	}
	if _, err := c.AuthenticateToken(ctx, tok.Text, "203.0.113.9"); !errors.Is(err, store.ErrInvalidToken) {
		t.Fatalf("a guessing address was not refused: %v", err)
	}
	if _, err := c.AuthenticateToken(ctx, tok.Text, "203.0.113.10"); err != nil {
		t.Fatalf("another address was refused: %v", err)
	}
}

// TestTokenUsageCounts against the database: a successful auth counts
// used; a revoked token's attempt counts revoked with no number or perm; an
// act the client named counts its code on the number; Probe and TokenSets
// count nothing, nor does a made-up number; two processes add into one row.
func TestTokenUsageCounts(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	w := tokentest.New(t, pool, uuid.Nil)
	ctx := context.Background()
	readable, other := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Read(readable))
	newChecker := func() *access.Checker {
		return &access.Checker{Tokens: w.Tokens, Switches: store.TokenSwitches{Default: true}, Use: &access.TokenUse{Store: w.Tokens}}
	}
	one, two := newChecker(), newChecker()
	actor, err := one.AuthenticateToken(ctx, tok.Text, "")
	if err != nil || actor.Token.ID != tok.ID || actor.Tenant != w.Tenant || actor.User != uuid.Nil || actor.Key != uuid.Nil {
		t.Fatalf("the actor: %+v %v", actor, err)
	}
	for _, c := range []*access.Checker{one, two} {
		if ok, err := c.Allows(ctx, actor, other, store.ActionSend); ok || err != nil {
			t.Fatalf("send: %v %v", ok, err)
		}
		if ok, err := c.Probe(ctx, actor, other, store.ActionManage); ok || err != nil {
			t.Fatalf("a probe: %v %v", ok, err)
		}
		if ok, _ := c.Allows(ctx, actor, uuid.New(), store.ActionRead); ok {
			t.Fatal("a made-up number")
		}
		if _, err := c.TokenSets(ctx, actor); err != nil {
			t.Fatal(err)
		}
	}
	w.Revoke(tok)
	if _, err := one.AuthenticateToken(ctx, tok.Text, ""); !errors.Is(err, store.ErrInvalidToken) {
		t.Fatalf("a revoked token: %v", err)
	}
	for _, c := range []*access.Checker{one, two} {
		if err := c.Use.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := w.Refusals(tok)
	want := map[string]int64{other.String() + "/send=no_permission": 2, "-/-=revoked": 1}
	if len(got) != len(want) {
		t.Fatalf("the refusals: %v", got)
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("the refusals: %v, want %v", got, want)
		}
	}
	var used int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_token_used WHERE token_id = $1`, tok.ID).Scan(&used); err != nil || used != 1 {
		t.Fatalf("used: %d %v", used, err)
	}
}
