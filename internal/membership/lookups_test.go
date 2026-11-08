package membership

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/store"
)

// The leader's lookups (lookups.go) on a real database and the kit's fake
// platform, whose token feed refuses every call, so that no record reaches
// Wappie but through them.

// stopped is a selector's operator stop as the lookups leave it: its
// record_until, and whether it is settled (never asked again) or put off
// (asked again later).
func (w *tokenWorld) stopped(t *testing.T, selector string) (recordUntil *time.Time, settled, putOff bool) {
	t.Helper()
	if err := w.pool.QueryRow(context.Background(), `SELECT record_until, coalesce(lookup_after = 'infinity', false),
		coalesce(lookup_after <> 'infinity', false) FROM contract_token_stops WHERE selector = $1 AND cause = 'operator'`, selector).
		Scan(&recordUntil, &settled, &putOff); err != nil {
		t.Fatal(err)
	}
	return recordUntil, settled, putOff
}

// named waits until the fake names the home workspace to Wappie, so its
// tokens' GETs answer their records.
func (w *tokenWorld) named(t *testing.T) {
	t.Helper()
	eventually(t, 10*time.Second, "the home workspace named to Wappie", func() bool { return w.fake.Named("wappie", w.home.String()) })
}

// F2(ii): a stop of a selector Wappie does not hold, that no record dates,
// is looked up once by selector: one the platform knows takes its token's
// created_at + 365 days; one it does not is settled with no date, the
// operator's own record. A lookup with no answer is asked again only
// after LookupRetry, however often the leader looks, and dated once the
// platform answers.
func TestTheLeaderLooksUpUndatedStops(t *testing.T) {
	w := newTokenWorld(t)
	w.fake.RefuseAlways(contracttest.CallTokens, kc.CodeUnavailable)
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.members, logs, lockKey(t))
	l.LookupEvery, l.LookupRetry = 20*time.Millisecond, 300*time.Millisecond
	run(t, l)
	w.named(t)
	ctx := context.Background()
	stop := func(sel string) {
		t.Helper()
		if _, err := w.tokens.StopToken(ctx, sel, "root", "leak", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	date := func(id string) time.Time {
		t.Helper()
		rec, ok := w.fake.TokenRecord("wappie", id)
		if !ok {
			t.Fatalf("the fake holds no record of %s", id)
		}
		return rec.CreatedAt.Add(kc.MaxTokenLifetime).Truncate(time.Microsecond)
	}
	known, _ := w.token(t, kc.CanRead)
	knownRec, _ := w.fake.TokenRecord("wappie", known)
	const unknown = "0123456789abcdef"
	stop(knownRec.Selector)
	stop(unknown)
	eventually(t, 10*time.Second, "both stops looked up", func() bool {
		ru, _, _ := w.stopped(t, knownRec.Selector)
		_, settled, _ := w.stopped(t, unknown)
		return ru != nil && settled
	})
	if ru, _, _ := w.stopped(t, knownRec.Selector); !ru.Equal(date(known)) {
		t.Errorf("a stop the platform knows: record_until %v, want its token's created_at + 365 days %v", *ru, date(known))
	}
	if ru, settled, _ := w.stopped(t, unknown); ru != nil || !settled {
		t.Errorf("a stop the platform does not know: record_until %v, settled %v", ru, settled)
	}
	if held, _ := w.held(t, known); held != 0 {
		t.Error("a lookup's answer was applied as a token")
	}

	// No answer: put off, and asked again only every LookupRetry.
	w.fake.RefuseAlways(contracttest.CallTokenBySelector, kc.CodeUnavailable)
	third, _ := w.token(t, kc.CanRead)
	thirdRec, _ := w.fake.TokenRecord("wappie", third)
	stop(thirdRec.Selector)
	eventually(t, 10*time.Second, "the lookup put off", func() bool { _, _, off := w.stopped(t, thirdRec.Selector); return off })
	calls := w.fake.Count(contracttest.CallTokenBySelector)
	time.Sleep(time.Second)
	// Each lookup is two calls (the client's one retry on unavailable), at
	// most every 300 ms, where every 20 ms would be 100.
	if n := w.fake.Count(contracttest.CallTokenBySelector) - calls; n < 2 || n > 10 {
		t.Errorf("%d selector calls in a second with no answer, want 2 to 10", n)
	}
	if len(logs.Lines("level=WARN", "contract: a token lookup got no answer")) == 0 {
		t.Error("no WARN for a lookup with no answer")
	}
	w.fake.RefuseAlways(contracttest.CallTokenBySelector, "")
	eventually(t, 10*time.Second, "the third stop dated", func() bool { ru, _, _ := w.stopped(t, thirdRec.Selector); return ru != nil })
	if ru, _, _ := w.stopped(t, thirdRec.Selector); !ru.Equal(date(third)) {
		t.Errorf("a stop dated once the platform answers: %v, want %v", *ru, date(third))
	}
	eventually(t, 5*time.Second, "the lookups said to answer again", func() bool {
		return len(logs.Lines("contract: the token lookups answer again")) > 0
	})
}

// F3: a bad record's revocation of a token Wappie holds no selector of,
// dated by Wappie's clock, is looked up by id: a token the platform knows
// takes its own created_at + 365 days; one it answers not_found for keeps
// Wappie's clock's date and is not asked again.
func TestTheLeaderLooksUpABadRecordsToken(t *testing.T) {
	w := newTokenWorld(t)
	w.fake.RefuseAlways(contracttest.CallTokens, kc.CodeUnavailable)
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.members, logs, lockKey(t))
	l.LookupEvery = 20 * time.Millisecond
	ctx := context.Background()
	gen := w.generation(t)
	known, _ := w.token(t, kc.CanRead)
	unknown := uuid.New()
	for _, id := range []string{known, unknown.String()} {
		// As a bad revoked record of a token Wappie holds no selector of
		// leaves it (store.TestABadRecordsRevocationIsClockDated), come a
		// day after the token was made.
		w.exec(ctx, t, `INSERT INTO contract_token_sticky (token_id, revoked_at, ended, until, clock_until, clock_gen)
			VALUES ($1, clock_timestamp(), 'revoked', clock_timestamp() + interval '366 days', true, $2)`, id, gen)
	}
	run(t, l)
	w.named(t)
	rec, ok := w.fake.TokenRecord("wappie", known)
	if !ok {
		t.Fatal("the fake holds no record of the token")
	}
	want := rec.CreatedAt.Add(kc.MaxTokenLifetime).Truncate(time.Microsecond)
	sticky := func(id string) (exists, clock, settled bool, until time.Time) {
		t.Helper()
		err := w.pool.QueryRow(ctx, `SELECT clock_until, coalesce(lookup_after = 'infinity', false), until
			FROM contract_token_sticky WHERE token_id = $1`, id).Scan(&clock, &settled, &until)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false, false, time.Time{}
		}
		if err != nil {
			t.Fatal(err)
		}
		return true, clock, settled, until
	}
	_, _, _, kept := sticky(unknown.String())
	eventually(t, 10*time.Second, "both revocations looked up", func() bool {
		_, clock, _, _ := sticky(known)
		_, _, settled, _ := sticky(unknown.String())
		return !clock && settled
	})
	if exists, _, _, until := sticky(known); !exists || !until.Equal(want) {
		t.Errorf("a revocation the platform knows: there %v, until %v, want %v", exists, until, want)
	}
	if exists, clock, _, until := sticky(unknown.String()); !exists || !clock || !until.Equal(kept) {
		t.Errorf("a revocation the platform answers not_found for: there %v, clock-dated %v, until %v; want it kept to %v",
			exists, clock, until, kept)
	}
	if held, _ := w.held(t, known); held != 0 {
		t.Error("a lookup's answer was applied as a token")
	}
	if n := w.fake.Count(contracttest.CallToken); n < 2 {
		t.Errorf("%d GETs by id, want one for each", n)
	}
}

// An answer whose record Wappie cannot use, which the kit or the store
// refuses for anything but its signature (one that fails Validate, which
// the kit refuses as unverified and invalid; a valid record of another
// token, or of another app, and a body that does not decode, which the kit
// refuses as unverified alone; one whose reading key's fingerprint is not
// its key's, which the store refuses), is put off longer each time, from
// LookupRetry doubled to LookupBadMax, and its first logs one ERROR,
// recorded for contract status --check. The revocation keeps Wappie's
// clock's date. An answer whose signature fails is no answer: put off
// LookupRetry, with no ERROR.
func TestABadLookupAnswerIsPutOffAndToldOnce(t *testing.T) {
	w := newTokenWorld(t)
	w.fake.RefuseAlways(contracttest.CallTokens, kc.CodeUnavailable)
	ctx := context.Background()
	gen := w.generation(t)
	invalid, badKey, otherToken, otherApp, garbled, unsignedAnswer := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	bad := map[string]uuid.UUID{"an invalid record": invalid, "another key's fingerprint": badKey,
		"another token's record": otherToken, "another app's record": otherApp, "a body that does not decode": garbled}
	asked := map[string]bool{unsignedAnswer.String(): true}
	for _, id := range bad {
		asked[id.String()] = true
	}
	var calls sync.Map
	platform, err := url.Parse(w.fake.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := clientOn(func(r *http.Request) (*http.Response, error) {
		id, ok := strings.CutPrefix(r.URL.Path, "/contract/v1/tokens/")
		if !ok || !asked[id] {
			out := r.Clone(r.Context())
			out.URL.Scheme, out.URL.Host, out.Host = platform.Scheme, platform.Host, platform.Host
			return http.DefaultTransport.RoundTrip(out)
		}
		n, _ := calls.LoadOrStore(id, new(atomic.Int64))
		n.(*atomic.Int64).Add(1)
		rec := w.tokenRecord(gen, uuid.MustParse(id), 1)
		switch id {
		case invalid.String():
			rec.Hash = "not a hash"
		case badKey.String():
			key := make([]byte, 32)
			key[0] = 9
			rec.ReadingKey = &kc.ReadingKey{Suite: kc.ReadingKeySuite, Key: base64.RawURLEncoding.EncodeToString(key),
				Fingerprint: "0123456789abcdef0123456789abcdef", RegisteredAt: rec.CreatedAt}
			if rec.Validate() != nil || rec.ReadingKey.Check() == nil {
				t.Errorf("the record of another key's fingerprint: valid %v, its check %v; want valid, the check failing",
					rec.Validate(), rec.ReadingKey.Check())
			}
		case otherToken.String():
			rec = w.tokenRecord(gen, uuid.New(), 1)
		case otherApp.String():
			rec.App = "mailie"
		}
		body, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		switch id {
		case garbled.String():
			body = []byte(`[]`)
		case unsignedAnswer.String():
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
		}
		return signedAnswer(r, w.secret, http.StatusOK, body, time.Now()), nil
	}, nil)
	if err := client.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.membersOn(client, logs), logs, lockKey(t))
	l.LookupEvery, l.LookupRetry, l.LookupBadMax = 20*time.Millisecond, 100*time.Millisecond, 400*time.Millisecond
	for id := range asked {
		w.exec(ctx, t, `INSERT INTO contract_token_sticky (token_id, revoked_at, ended, until, clock_until, clock_gen)
			VALUES ($1, clock_timestamp(), 'revoked', clock_timestamp() + interval '365 days', true, $2)`, id, gen)
	}
	var until time.Time
	if err := w.pool.QueryRow(ctx, `SELECT until FROM contract_token_sticky WHERE token_id = $1`, invalid).Scan(&until); err != nil {
		t.Fatal(err)
	}
	count := func(id uuid.UUID) int64 {
		n, ok := calls.Load(id.String())
		if !ok {
			return 0
		}
		return n.(*atomic.Int64).Load()
	}
	run(t, l)
	eventually(t, 10*time.Second, "all looked up", func() bool {
		for id := range asked {
			if count(uuid.MustParse(id)) == 0 {
				return false
			}
		}
		return true
	})
	time.Sleep(2 * time.Second)
	// At 0, 100, 300, 700, 1100, 1500 and 1900 ms: 7 or so, where a
	// lookup put off by LookupRetry alone would be asked 20 times.
	for name, id := range bad {
		if n := count(id); n < 3 || n > 11 {
			t.Errorf("%s: %d GETs in about 2 seconds, want 3 to 11", name, n)
		}
	}
	if n := len(logs.Lines("level=ERROR", "contract: the platform answered a token lookup with a record Wappie cannot use")); n != len(bad) {
		t.Errorf("%d ERRORs for %d lookups answered badly, want one each:\n%s", n, len(bad), logs.String())
	}
	if s := w.state(t); s.ErrorClass != store.ContractErrorTokenLookupInvalid {
		t.Errorf("the ERROR was not recorded: %+v", s)
	}
	lookup := func(id uuid.UUID) (clock bool, until time.Time, badCount int, putOff bool) {
		t.Helper()
		if err := w.pool.QueryRow(ctx, `SELECT clock_until, until, lookup_bad, coalesce(lookup_after <> 'infinity', false)
			FROM contract_token_sticky WHERE token_id = $1`, id).Scan(&clock, &until, &badCount, &putOff); err != nil {
			t.Fatal(err)
		}
		return clock, until, badCount, putOff
	}
	for name, id := range bad {
		if _, _, n, _ := lookup(id); n < 2 {
			t.Errorf("%s: %d bad answers in a row counted, want 2 or more", name, n)
		}
	}
	if clock, now, _, _ := lookup(invalid); !clock || !now.Equal(until) {
		t.Errorf("a revocation answered badly: clock-dated %v, until %v, want %v", clock, now, until)
	}
	if clock, _, n, putOff := lookup(unsignedAnswer); !clock || n != 0 || !putOff {
		t.Errorf("an answer whose signature fails: clock-dated %v, %d bad answers, put off %v; want no bad answer, put off", clock, n, putOff)
	}
	if len(logs.Lines("level=WARN", "contract: a token lookup got no answer")) == 0 {
		t.Error("no WARN for an answer whose signature fails")
	}
}

// F3, as the platform ruled on 2026-11-08: a signed not_found by id never
// clears a revocation, even in the generation the bad record came in,
// which is Wappie's. The revocation keeps Wappie's clock's date, the
// lookup is settled, never asked again, and nothing else is asked to
// confirm it: no page of the account feed.
func TestANotFoundKeepsTheRevocation(t *testing.T) {
	w := newTokenWorld(t)
	w.fake.RefuseAlways(contracttest.CallTokens, kc.CodeUnavailable)
	ctx := context.Background()
	gen := w.generation(t)
	var pages atomic.Int64
	platform, err := url.Parse(w.fake.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := clientOn(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/contract/v1/feed" {
			pages.Add(1)
		}
		out := r.Clone(r.Context())
		out.URL.Scheme, out.URL.Host, out.Host = platform.Scheme, platform.Host, platform.Host
		return http.DefaultTransport.RoundTrip(out)
	}, nil)
	if err := client.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.membersOn(client, logs), logs, lockKey(t))
	id := uuid.New()
	w.exec(ctx, t, `INSERT INTO contract_token_sticky (token_id, revoked_at, ended, until, clock_until, clock_gen)
		VALUES ($1, clock_timestamp(), 'revoked', clock_timestamp() + interval '365 days', true, $2)`, id, gen)
	var kept time.Time
	if err := w.pool.QueryRow(ctx, `SELECT until FROM contract_token_sticky WHERE token_id = $1`, id).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	calls := w.fake.Count(contracttest.CallToken)
	l.lookUp(ctx, &lookupRun{})
	if w.fake.Count(contracttest.CallToken) == calls {
		t.Fatal("the pass asked nothing by id")
	}
	var clock, settled bool
	var until time.Time
	var badCount int
	err = w.pool.QueryRow(ctx, `SELECT clock_until, coalesce(lookup_after = 'infinity', false), until, lookup_bad
		FROM contract_token_sticky WHERE token_id = $1`, id).Scan(&clock, &settled, &until, &badCount)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		t.Fatal("a not_found let the revocation go")
	case err != nil:
		t.Fatal(err)
	}
	if !clock || !settled || !until.Equal(kept) || badCount != 0 {
		t.Errorf("after a not_found: clock-dated %v, settled %v, until %v (want %v), %d bad; want clock-dated and settled, until kept",
			clock, settled, until, kept, badCount)
	}
	if n := pages.Load(); n != 0 {
		t.Errorf("%d account feed GETs after a not_found, want none", n)
	}
	// Settled: the next pass asks nothing.
	calls = w.fake.Count(contracttest.CallToken)
	l.lookUp(ctx, &lookupRun{})
	if n := w.fake.Count(contracttest.CallToken) - calls; n != 0 {
		t.Errorf("%d GETs by id after the not_found settled it, want none", n)
	}
	if lines := logs.Lines("level=WARN", "token lookup"); len(lines) != 0 {
		t.Errorf("a not_found logged a WARN: %v", lines)
	}
}

// The lookups run while the contract is on, whatever the token mode: with
// tokens off, a bad record's revocation and an undated stop of a selector
// Wappie does not hold are still dated by the platform's answers.
func TestTheLookupsRunWithTokensOff(t *testing.T) {
	w := newTokenWorld(t)
	w.fake.RefuseAlways(contracttest.CallTokens, kc.CodeUnavailable)
	ctx := context.Background()
	w.exec(ctx, t, `UPDATE contract_token_state SET mode = 'off'`)
	gen := w.generation(t)
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.members, logs, lockKey(t))
	l.LookupEvery = 20 * time.Millisecond
	run(t, l)
	w.named(t)
	byID, _ := w.token(t, kc.CanRead)
	bySelector, _ := w.token(t, kc.CanRead)
	rec, ok := w.fake.TokenRecord("wappie", bySelector)
	if !ok {
		t.Fatal("the fake holds no record of the token")
	}
	w.exec(ctx, t, `INSERT INTO contract_token_sticky (token_id, revoked_at, ended, until, clock_until, clock_gen)
		VALUES ($1, clock_timestamp(), 'revoked', clock_timestamp() + interval '366 days', true, $2)`, byID, gen)
	if _, err := w.tokens.StopToken(ctx, rec.Selector, "root", "leak", time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "both looked up with tokens off", func() bool {
		var clock, dated bool
		if err := w.pool.QueryRow(ctx, `SELECT (SELECT clock_until FROM contract_token_sticky WHERE token_id = $1),
			(SELECT record_until IS NOT NULL FROM contract_token_stops WHERE selector = $2 AND cause = 'operator')`,
			byID, rec.Selector).Scan(&clock, &dated); err != nil {
			t.Fatal(err)
		}
		return !clock && dated
	})
	var mode string
	if err := w.pool.QueryRow(ctx, `SELECT mode FROM contract_token_state`).Scan(&mode); err != nil || mode != "off" {
		t.Fatalf("the token mode: %q %v", mode, err)
	}
}
