package membership

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// The token part in the leader (step 7's plan, 4.3 to 4.5 and 10.6), on a
// real database and the kit's fake platform: the token follower, the judge,
// the acknowledgement and the usage report.

// tokenWorld is a world whose held person (the platform's sub, Wappie's
// user) is at home in the platform's personal workspace, with a number of
// it they read, the token store wired and the token mode on.
type tokenWorld struct {
	*world
	tokens                  *store.Tokens
	user, sub, home, number uuid.UUID
}

func newTokenWorld(t *testing.T) *tokenWorld { return newTokenWorldAt(t, nil) }

func newTokenWorldAt(t *testing.T, clock func() time.Time) *tokenWorld {
	t.Helper()
	w := &tokenWorld{world: newWorldAt(t, clock)}
	w.tokens = store.NewTokens(w.pool)
	w.members.Tokens = w.tokens
	w.user, w.sub, w.home = w.heldAtHome(t)
	w.number = w.world.number(t, w.home, "Vendas", 1, w.user)
	w.exec(context.Background(), t, `UPDATE contract_token_state SET mode = 'on'`)
	return w
}

// tokenLeader is w.leader with the token part's timings shortened.
func (w *tokenWorld) tokenLeader(m *Members, logs *membershiptest.Logs, key string) *Leader {
	l := w.leader(m, logs, key)
	l.TokenBackoffMin, l.TokenBackoffMax = 20*time.Millisecond, 200*time.Millisecond
	l.AckSpacing, l.AckEvery = 50*time.Millisecond, time.Second
	l.AckBackoffMin, l.AckBackoffMax = 20*time.Millisecond, 200*time.Millisecond
	l.UsageEvery, l.JudgeEvery = 300*time.Millisecond, 200*time.Millisecond
	return l
}

// token is a token of the home workspace that the person made, with perms
// on the number that they gave.
func (w *tokenWorld) token(t *testing.T, perms ...string) (id, text string) {
	t.Helper()
	id, text, err := w.fake.AddToken(w.home.String(), w.sub.String(), "Nightly", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range perms {
		w.grant(t, id, p)
	}
	return id, text
}

func (w *tokenWorld) grant(t *testing.T, id, perm string) {
	t.Helper()
	if err := w.fake.GrantToken(id, "wappie", w.number.String(), kc.ItemNumber, perm, w.sub.String()); err != nil {
		t.Fatal(err)
	}
}

// version is the fake's latest version of the token's record.
func (w *tokenWorld) version(t *testing.T, id string) int64 {
	t.Helper()
	rec, ok := w.fake.TokenRecord("wappie", id)
	if !ok {
		t.Fatalf("the fake holds no record of %s", id)
	}
	return rec.Version
}

// feed is contract_token_state as the follower leaves it.
type tokenFeed struct {
	cursor                      int64
	readAt, caughtUp, published *time.Time
	failing                     string
	ackThrough                  int64
	ackError, usageError        string
	generation                  *uuid.UUID
	passGeneration              *uuid.UUID
	passDone                    bool
	slowCommit                  *time.Time
}

func (w *tokenWorld) feed(t *testing.T) tokenFeed {
	t.Helper()
	var f tokenFeed
	if err := w.pool.QueryRow(context.Background(), `SELECT s.feed_cursor, s.read_at, s.caught_up_at, s.published_through,
			coalesce(s.error, ''), s.ack_through, coalesce(s.ack_error, ''), coalesce(s.usage_error, ''), c.generation,
			s.pass_generation, s.pass_done_at IS NOT NULL, s.slow_commit_at
		FROM contract_token_state s CROSS JOIN contract_state c`).Scan(&f.cursor, &f.readAt, &f.caughtUp, &f.published, &f.failing,
		&f.ackThrough, &f.ackError, &f.usageError, &f.generation, &f.passGeneration, &f.passDone, &f.slowCommit); err != nil {
		t.Fatal(err)
	}
	return f
}

// perms are the token's perm rows on the number, as perm=state[:code].
func (w *tokenWorld) perms(t *testing.T, id string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := pg.InTenantTx(context.Background(), w.pool, w.home.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT perm, state, coalesce(code, '') FROM contract_token_perms WHERE token_id = $1`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var perm, state, code string
			if err := rows.Scan(&perm, &state, &code); err != nil {
				return err
			}
			if code != "" {
				state += ":" + code
			}
			out[perm] = state
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// stored is what Wappie holds of the token: its version, and whether it is
// revoked or unlisted.
func (w *tokenWorld) stored(t *testing.T, id string) (version int64, revoked, unlisted bool) {
	t.Helper()
	if err := pg.InTenantTx(context.Background(), w.pool, w.home.String(), func(tx pgx.Tx) error {
		var v *int64
		err := tx.QueryRow(context.Background(), `SELECT version, revoked_at IS NOT NULL, unlisted_at IS NOT NULL FROM contract_tokens WHERE id = $1`, id).
			Scan(&v, &revoked, &unlisted)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if v != nil {
			version = *v
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return version, revoked, unlisted
}

// held is what Wappie holds of the token, in whichever workspace: the
// version of the record it applied and that record's token feed seq (both
// 0 while it holds none).
func (w *tokenWorld) held(t *testing.T, id string) (version, seq int64) {
	t.Helper()
	ctx := context.Background()
	var ws uuid.UUID
	err := w.pool.QueryRow(ctx, `SELECT tenant_id FROM contract_token_selectors WHERE token_id = $1`, id).Scan(&ws)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, 0
	case err != nil:
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, w.pool, ws.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(version, 0), coalesce(seq, 0) FROM contract_tokens WHERE id = $1`, id).Scan(&version, &seq)
	}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	return version, seq
}

// latestSeq waits until Wappie holds the fake's latest record of the token,
// and is the token feed seq Wappie stored with it: contracttest's version is
// its seq, which no test may rely on (the plan's 10).
func (w *tokenWorld) latestSeq(t *testing.T, id string) int64 {
	t.Helper()
	var seq int64
	eventually(t, 10*time.Second, "Wappie holds the token's latest record", func() bool {
		var version int64
		version, seq = w.held(t, id)
		return version == w.version(t, id)
	})
	return seq
}

// settled waits for the pass of the generation the world adopted at its
// sign-up (every first adoption starts one), whose end is acknowledged at
// once, whatever the spacing.
func (w *tokenWorld) settled(t *testing.T) {
	t.Helper()
	eventually(t, 10*time.Second, "the first pass done", func() bool { return w.feed(t).passDone })
	time.Sleep(200 * time.Millisecond)
}

// acks are the acknowledgements the fake accepted.
func (w *tokenWorld) acks() []kc.TokenApplied { return w.fake.TokensApplied("wappie") }

// acked reports whether an acknowledgement the fake accepted reached
// through.
func (w *tokenWorld) acked(through int64) bool {
	for _, a := range w.acks() {
		if a.Through >= through {
			return true
		}
	}
	return false
}

// stamped records the arrival time of every request to call, on the test's
// clock, before the fake serves it.
func (w *tokenWorld) stamped(call string) func() []time.Time {
	var mu sync.Mutex
	var at []time.Time
	w.fake.Before(call, func(string) {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
	})
	return func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), at...)
	}
}

// A token works once its record reaches the token feed and a page with more
// false commits, within seconds of its making; its reading key, once
// registered, is pinned with the token's hidden identity; its revocation is
// acknowledged, the acknowledgement's through reaching the revocation's
// seq; and a token taken off Wappie is revoked here (app_removed) and
// acknowledged likewise.
func TestTokenFeedEndToEnd(t *testing.T) {
	w := newTokenWorld(t)
	logs := &membershiptest.Logs{}
	run(t, w.tokenLeader(w.members, logs, lockKey(t)))
	eventually(t, 10*time.Second, "the token feed's first page", func() bool { return w.feed(t).caughtUp != nil })

	id, _ := w.token(t, kc.CanRead, kc.CanSend)
	made := time.Now()
	eventually(t, 5*time.Second, "the token's perms applied", func() bool {
		p := w.perms(t, id)
		return p[kc.CanRead] == "applied" && p[kc.CanSend] == "applied"
	})
	if took := time.Since(made); took > 5*time.Second {
		t.Fatalf("the token worked %v after its making", took)
	}
	if v, revoked, _ := w.stored(t, id); v != w.version(t, id) || revoked {
		t.Fatalf("Wappie holds version %d (revoked %t), the fake %d", v, revoked, w.version(t, id))
	}
	if _, seq := w.held(t, id); seq == 0 {
		t.Fatal("Wappie stored no seq with the token's record")
	} else if f := w.feed(t); f.caughtUp == nil || f.cursor < seq || f.published == nil {
		t.Fatalf("the token feed's state %+v, the record's seq %d", f, seq)
	}

	// Its reading key, registered in the console, is pinned, and the
	// token's hidden identity made with it.
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.fake.SetReadingKey(id, base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the reading key pinned", func() bool {
		var pinned, identity bool
		if err := pg.InTenantTx(context.Background(), w.pool, w.home.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM contract_token_pins WHERE token_id = $1),
				EXISTS (SELECT 1 FROM contract_tokens WHERE id = $1 AND identity_user_id IS NOT NULL)`, id).Scan(&pinned, &identity)
		}); err != nil {
			t.Fatal(err)
		}
		return pinned && identity
	})

	if err := w.fake.RevokeToken(id, kc.RevokedInConsole); err != nil {
		t.Fatal(err)
	}
	seq := w.latestSeq(t, id)
	if _, revoked, _ := w.stored(t, id); !revoked {
		t.Fatal("Wappie holds the revocation's record, not revoked")
	}
	eventually(t, 5*time.Second, "the revocation acknowledged", func() bool { return w.acked(seq) })
	// Taken off the app: that app's record is revoked, app_removed.
	other, _ := w.token(t, kc.CanSend)
	eventually(t, 5*time.Second, "the other token applied", func() bool { return w.perms(t, other)[kc.CanSend] == "applied" })
	if err := w.fake.TakeTokenOffApp(other, "wappie"); err != nil {
		t.Fatal(err)
	}
	seq = w.latestSeq(t, other)
	eventually(t, 5*time.Second, "app_removed acknowledged", func() bool { return w.acked(seq) })
	if _, revoked, _ := w.stored(t, other); !revoked {
		t.Fatal("a token taken off Wappie is not revoked here")
	}
	for _, a := range w.acks() {
		if err := a.Validate(); err != nil {
			t.Fatalf("an acknowledgement the fake took is not valid: %v", err)
		}
	}
	if n := len(logs.Lines("contract: following the token feed")); n != 1 {
		t.Fatalf("the token loops started %d times:\n%s", n, logs.String())
	}
}

// After a reset the platform lists a token wider than Wappie held it at
// the reset (a grant of before the last published_through Wappie trusted,
// which it had dropped): Wappie keeps it off and says so in held; the fake
// takes it off its record in a new version, so both agree. The reset was a
// signed gone (the platform restored), which leaves no generation until the
// account feed adopts the new one: the pass of that one still finishes.
func TestHeldIsReportedAfterAReset(t *testing.T) {
	var offset atomic.Int64
	clock := func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	w := newTokenWorldAt(t, clock)
	logs := &membershiptest.Logs{}
	run(t, w.tokenLeader(w.members, logs, lockKey(t)))
	id, _ := w.token(t, kc.CanRead, kc.CanSend)
	eventually(t, 5*time.Second, "the token applied", func() bool {
		p := w.perms(t, id)
		return p[kc.CanRead] == "applied" && p[kc.CanSend] == "applied"
	})
	if err := w.fake.UngrantToken(id, "wappie", w.number.String(), kc.CanSend); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "send dropped and the page trusted", func() bool {
		_, ok := w.perms(t, id)[kc.CanSend]
		v, _ := w.held(t, id)
		f := w.feed(t)
		return !ok && v == w.version(t, id) && f.published != nil && f.published.After(time.Now().Add(-time.Minute))
	})
	gen := w.fake.Restore()
	// A grant the restored platform holds from before the last
	// published_through Wappie trusted, which Wappie no longer held: given
	// while its workspace is named to Wappie again by no document yet, on a
	// clock ten minutes back.
	offset.Store(int64(-10 * time.Minute))
	w.grant(t, id, kc.CanSend)
	offset.Store(0)

	eventually(t, 20*time.Second, "held, acknowledged in the new generation", func() bool {
		for _, a := range w.acks() {
			if a.Generation != gen {
				continue
			}
			for _, h := range a.Held {
				if h.Token == id && len(h.Removed) == 1 && h.Removed[0] == (kc.HeldPerm{Item: w.number.String(), Perm: kc.CanSend}) && !h.Revoked {
					return true
				}
			}
		}
		return false
	})
	eventually(t, 10*time.Second, "the fake's record narrowed to match", func() bool {
		rec, ok := w.fake.TokenRecord("wappie", id)
		if !ok {
			return false
		}
		for _, it := range rec.Items {
			for _, p := range it.Perms {
				if p.Perm == kc.CanSend {
					return false
				}
			}
		}
		return true
	})
	eventually(t, 10*time.Second, "the pass of the new generation done", func() bool {
		f := w.feed(t)
		return f.generation != nil && f.generation.String() == gen && f.passGeneration != nil && *f.passGeneration == *f.generation && f.passDone
	})
	p := w.perms(t, id)
	if p[kc.CanRead] != "applied" {
		t.Fatalf("read, held at the reset, is %q", p[kc.CanRead])
	}
	if _, ok := p[kc.CanSend]; ok {
		t.Fatalf("send, dropped before the reset, came back: %v", p)
	}
	if _, _, unlisted := w.stored(t, id); unlisted {
		t.Fatal("a token the pass listed is unlisted")
	}
	// Whichever saw the restore first (either feed's gone, or the
	// acknowledgement's), one generation reset both.
	if len(logs.Lines("generation changed: every sub is subscribed again")) == 0 {
		t.Fatalf("no reset was logged:\n%s", logs.String())
	}
}

// signedTokens is a client whose token feed requests get page(after), and
// whose acknowledgements and usage reports are kept and accepted, all
// signed with secret; its other calls go to the fake platform.
type signedTokens struct {
	calls atomic.Int64
	mu    sync.Mutex
	acks  []kc.TokenApplied
	usage []kc.TokenUsage
	// ack, when set, answers an acknowledgement instead, under mu.
	ack func(r *http.Request, body kc.TokenApplied) *http.Response
}

func (s *signedTokens) taken() []kc.TokenApplied {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]kc.TokenApplied(nil), s.acks...)
}

func (w *tokenWorld) signedTokens(t *testing.T, s *signedTokens, page func(after int64) kc.TokenFeed) *Client {
	t.Helper()
	platform, err := url.Parse(w.fake.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := clientOn(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/contract/v1/tokens":
			s.calls.Add(1)
			after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
			if err != nil {
				return nil, err
			}
			body, err := json.Marshal(page(after))
			if err != nil {
				return nil, err
			}
			return signedAnswer(r, w.secret, http.StatusOK, body, time.Now()), nil
		case "/contract/v1/tokens/applied", "/contract/v1/tokens/usage":
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			if strings.HasSuffix(r.URL.Path, "applied") {
				var a kc.TokenApplied
				if err := json.Unmarshal(raw, &a); err != nil {
					s.mu.Unlock()
					return nil, err
				}
				if s.ack != nil {
					// Under s.mu, which the answer's own keeping takes.
					res := s.ack(r, a)
					s.mu.Unlock()
					return res, nil
				}
				s.acks = append(s.acks, a)
			} else {
				var u kc.TokenUsage
				if err := json.Unmarshal(raw, &u); err != nil {
					s.mu.Unlock()
					return nil, err
				}
				s.usage = append(s.usage, u)
			}
			s.mu.Unlock()
			return signedAnswer(r, w.secret, http.StatusOK, []byte(`{"accepted":true}`), time.Now()), nil
		}
		out := r.Clone(r.Context())
		out.URL.Scheme, out.URL.Host, out.Host = platform.Scheme, platform.Host, platform.Host
		return http.DefaultTransport.RoundTrip(out)
	}, nil)
	if err := c.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	return c
}

// members is a Members of w on client.
func (w *tokenWorld) membersOn(client *Client, logs *membershiptest.Logs) *Members {
	return &Members{Client: client, Contract: w.contract, Tokens: w.tokens, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
}

// generation is the generation Wappie holds, which the fake's answers bear.
func (w *tokenWorld) generation(t *testing.T) string {
	t.Helper()
	gen, _ := w.fake.Generation()
	if g := w.feed(t).generation; g == nil || g.String() != gen {
		t.Fatalf("Wappie holds generation %v, the fake %s", g, gen)
	}
	return gen
}

// tokenRecord is a good record of a token of the home workspace that the
// person made, its id, selector and hash derived from id, at version.
func (w *tokenWorld) tokenRecord(gen string, id uuid.UUID, version int64, perms ...string) kc.TokenRecord {
	created := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	sum := sha256.Sum256(id[:])
	r := kc.TokenRecord{V: kc.TokenRecordV, Type: kc.TokenRecordType, App: "wappie", Generation: gen, ID: id.String(), Version: version,
		Selector: strings.ReplaceAll(id.String(), "-", "")[16:], Hash: hex.EncodeToString(sum[:]), WorkspaceID: w.home.String(), Name: "Nightly",
		CreatedBy: w.sub.String(), CreatedAt: kc.T(created), ExpiresAt: kc.T(created.Add(30 * 24 * time.Hour)), Items: []kc.TokenItem{}}
	if len(perms) > 0 {
		item := kc.TokenItem{ID: w.number.String(), Kind: kc.ItemNumber}
		for _, p := range perms {
			item.Perms = append(item.Perms, kc.TokenPerm{Perm: p, GrantedBy: w.sub.String(), GrantedAt: kc.T(created)})
		}
		r.Items = append(r.Items, item)
	}
	return r
}

// tokenItem is rec at seq on a page, or the raw JSON given.
func tokenItem(t *testing.T, seq int64, rec any) kc.TokenFeedItem {
	t.Helper()
	if raw, ok := rec.(json.RawMessage); ok {
		return kc.TokenFeedItem{Seq: seq, Token: raw}
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return kc.TokenFeedItem{Seq: seq, Token: b}
}

// A token record newer than the one Wappie holds is applied, and only a
// newer one; while the platform's publisher is held, the token feed's
// published_through stays at its oldest unpublished change and Wappie
// trusts no later one, and both move once it publishes again; a page with
// more stores no published_through, the last page of the run does.
func TestTokenFollowerNewerOnly(t *testing.T) {
	w := newTokenWorld(t)
	stop := run(t, w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t)))
	id, _ := w.token(t, kc.CanSend)
	eventually(t, 5*time.Second, "the token applied", func() bool { v, _, _ := w.stored(t, id); return v == w.version(t, id) })
	created := time.Now()
	if err := w.fake.ShortenToken(id, created.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the newer record applied", func() bool { v, _, _ := w.stored(t, id); return v == w.version(t, id) })

	if err := w.fake.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	held := time.Now()
	if err := w.fake.ShortenToken(id, created.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	before := w.version(t, id)
	// Pages keep coming (the long-poll's own), each vouching no later than
	// the held change.
	read := *w.feed(t).readAt
	eventually(t, 10*time.Second, "two more pages while held", func() bool {
		f := w.feed(t)
		return f.readAt.After(read.Add(1500 * time.Millisecond))
	})
	if f := w.feed(t); f.published == nil || f.published.After(held.Add(time.Second)) {
		t.Fatalf("while held, Wappie trusts published_through %v, past the held change at %v", f.published, held)
	}
	if v, _, _ := w.stored(t, id); v != before {
		t.Fatalf("while held Wappie holds version %d, want %d", v, before)
	}
	if err := w.fake.Release("wappie"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the held change applied", func() bool {
		v, _, _ := w.stored(t, id)
		f := w.feed(t)
		return v == w.version(t, id) && v > before && f.published != nil && f.published.After(held)
	})
	stop()

	// A run of two pages, the first with more, from a feed of the test's.
	gen := w.generation(t)
	f := w.feed(t)
	var released atomic.Bool
	first := uuid.Must(uuid.NewV7())
	s := &signedTokens{}
	page := func(after int64) kc.TokenFeed {
		p := kc.TokenFeed{Generation: gen, GenerationConfirmed: true, Head: f.cursor + 2, PublishedThrough: kc.T(time.Now()),
			Items: []kc.TokenFeedItem{}, NextAfter: f.cursor + 2}
		switch after {
		case f.cursor:
			p.Items = append(p.Items, tokenItem(t, f.cursor+1, w.tokenRecord(gen, first, f.cursor+1)))
			p.NextAfter, p.More = f.cursor+1, true
		case f.cursor + 1:
			// The second page, a long-poll's, waits for the test's look at
			// the first.
			for deadline := time.Now().Add(5 * time.Second); !released.Load() && time.Now().Before(deadline); {
				time.Sleep(10 * time.Millisecond)
			}
		}
		return p
	}
	logs := &membershiptest.Logs{}
	run(t, w.tokenLeader(w.membersOn(w.signedTokens(t, s, page), logs), logs, lockKey(t)))
	eventually(t, 5*time.Second, "the page with more", func() bool { return w.feed(t).cursor == f.cursor+1 })
	if g := w.feed(t); g.published == nil || !g.published.Equal(*f.published) {
		t.Fatalf("a page with more stored published_through %v (was %v)", g.published, f.published)
	}
	released.Store(true)
	eventually(t, 5*time.Second, "the last page of the run", func() bool {
		g := w.feed(t)
		return g.cursor == f.cursor+2 && g.published != nil && g.published.After(*f.published)
	})
}

// A signed token page that does not move the cursor as the design's 3.3
// describes (more with no items, or ending at the cursor, or before its
// last item's seq) is no page: nothing commits, and the token follower
// backs off as for any answer it cannot take, never asking again at once.
func TestTokenFollowerRefusesPagesThatDoNotMove(t *testing.T) {
	w := newTokenWorld(t)
	gen := w.generation(t)
	const cursor = 10
	w.exec(context.Background(), t, `UPDATE contract_token_state SET feed_cursor = $1`, cursor)
	id := uuid.Must(uuid.NewV7())
	item := func(seq int64) kc.TokenFeedItem { return tokenItem(t, seq, w.tokenRecord(gen, id, seq)) }
	page := func(after, next int64, more bool, items ...kc.TokenFeedItem) kc.TokenFeed {
		return kc.TokenFeed{Generation: gen, Head: after + 5, PublishedThrough: kc.T(time.Now().Add(-time.Minute)),
			Items: append([]kc.TokenFeedItem{}, items...), NextAfter: next, More: more}
	}
	for _, c := range []struct {
		name string
		page func(after int64) kc.TokenFeed
	}{
		{"more with no items", func(after int64) kc.TokenFeed { return page(after, after, true) }},
		{"more ending at the cursor", func(after int64) kc.TokenFeed { return page(after, after, true, item(after+1)) }},
		{"more ending before its last item", func(after int64) kc.TokenFeed { return page(after, after+1, true, item(after+1), item(after+2)) }},
	} {
		logs := &membershiptest.Logs{}
		s := &signedTokens{}
		stop := run(t, w.tokenLeader(w.membersOn(w.signedTokens(t, s, c.page), logs), logs, lockKey(t)))
		eventually(t, 5*time.Second, c.name+": a call", func() bool { return s.calls.Load() > 0 })
		time.Sleep(time.Second)
		stop()
		// 20 ms doubling to 200 ms: a handful in a second, never a loop.
		if n := s.calls.Load(); n > 15 {
			t.Fatalf("%s: %d token feed calls in about a second", c.name, n)
		}
		if f := w.feed(t); f.cursor != cursor || f.readAt != nil || f.failing != "unverified" {
			t.Fatalf("%s: the state %+v, want the cursor at %d, never read, unverified", c.name, f, cursor)
		}
		if _, err := w.tokens.Mode(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

// A signed empty token page with more false is a page, and commits; one
// that comes back well before the wait it asked for is followed by the
// backoff's first pause, never a loop of calls.
func TestTokenFollowerPausesAfterAnEarlyEmptyPage(t *testing.T) {
	w := newTokenWorld(t)
	gen := w.generation(t)
	const cursor = 10
	w.exec(context.Background(), t, `UPDATE contract_token_state SET feed_cursor = $1`, cursor)
	empty := func(after int64) kc.TokenFeed {
		return kc.TokenFeed{Generation: gen, Head: after, PublishedThrough: kc.T(time.Now().Add(-time.Minute)), Items: []kc.TokenFeedItem{},
			NextAfter: after}
	}
	logs := &membershiptest.Logs{}
	s := &signedTokens{}
	l := w.tokenLeader(w.membersOn(w.signedTokens(t, s, empty), logs), logs, lockKey(t))
	l.TokenBackoffMin = 100 * time.Millisecond
	stop := run(t, l)
	eventually(t, 5*time.Second, "the first page", func() bool { return w.feed(t).readAt != nil })
	before := s.calls.Load()
	time.Sleep(time.Second)
	n := s.calls.Load() - before
	stop()
	// One call every 100 ms or so: about ten in the second, never a loop.
	if n > 15 {
		t.Fatalf("%d token feed calls in about a second after empty pages that came back at once", n)
	}
	if f := w.feed(t); f.cursor != cursor || f.failing != "" || f.caughtUp == nil {
		t.Fatalf("the state %+v, want the cursor at %d, no error and caught up: an empty page is a page", f, cursor)
	}
}

// A token page behind the cursor in the same generation (its head, or its
// next_after) is a rewound feed: a reset never widens, so both feeds
// restart from 0, by compare-and-set on the generation, and the round runs;
// one rewound page resets once, never in a loop.
func TestARewoundTokenFeedResets(t *testing.T) {
	for _, c := range []struct {
		name string
		page func(gen string, after int64) kc.TokenFeed
	}{
		{"its head behind", func(gen string, after int64) kc.TokenFeed {
			return kc.TokenFeed{Generation: gen, Head: after - 1, PublishedThrough: kc.T(time.Now()), Items: []kc.TokenFeedItem{}, NextAfter: after - 1}
		}},
		{"its next_after behind", func(gen string, after int64) kc.TokenFeed {
			return kc.TokenFeed{Generation: gen, Head: after + 3, PublishedThrough: kc.T(time.Now()), Items: []kc.TokenFeedItem{}, NextAfter: after - 1}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newTokenWorld(t)
			gen := w.generation(t)
			const cursor = 10
			w.exec(context.Background(), t, `UPDATE contract_token_state SET feed_cursor = $1`, cursor)
			var rewound atomic.Bool
			page := func(after int64) kc.TokenFeed {
				if after == cursor && !rewound.Swap(true) {
					return c.page(gen, after)
				}
				return kc.TokenFeed{Generation: gen, Head: after, PublishedThrough: kc.T(time.Now()), Items: []kc.TokenFeedItem{}, NextAfter: after}
			}
			logs := &membershiptest.Logs{}
			run(t, w.tokenLeader(w.membersOn(w.signedTokens(t, &signedTokens{}, page), logs), logs, lockKey(t)))
			eventually(t, 10*time.Second, "the reset", func() bool {
				return len(logs.Lines("contract: the token feed says the platform's generation changed", "why=rewound")) == 1
			})
			// The account feed adopts the fake's generation again, and the
			// token feed reads from 0 in it.
			eventually(t, 10*time.Second, "both feeds again in the generation", func() bool {
				f := w.feed(t)
				return f.generation != nil && f.generation.String() == gen && f.readAt != nil && f.cursor == 0
			})
			time.Sleep(500 * time.Millisecond)
			if n := len(logs.Lines("contract: the token feed says the platform's generation changed")); n != 1 {
				t.Fatalf("%d resets for one rewound page:\n%s", n, logs.String())
			}
		})
	}
}

// While Wappie holds no generation (the first observe, or after a gone),
// the token follower asks the platform nothing: no reset can loop. The
// account feed's first page adopts the generation, and wakes the token
// follower, which asks at once: its pause with no generation is the
// backoff's most, here 30 seconds, which only that wake (or another test's
// generation notice) ends within seconds.
func TestTheTokenFollowerWaitsWithNoGeneration(t *testing.T) {
	w := newTokenWorld(t)
	w.exec(context.Background(), t, `UPDATE contract_state SET generation = NULL, feed_cursor = 0`)
	// The account side gets no page, and the round's PUTs no answer.
	w.fake.RefuseAlways(contracttest.CallFeed, kc.CodeUnavailable)
	w.fake.RefuseAlways(contracttest.CallSubscribe, kc.CodeUnavailable)
	calls := w.stamped(contracttest.CallTokens)
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.members, logs, lockKey(t))
	l.TokenBackoffMax = 30 * time.Second
	gens := w.generations(t)
	run(t, l)
	eventually(t, 5*time.Second, "the token loops", func() bool { return len(logs.Lines("contract: following the token feed")) == 1 })
	eventually(t, 5*time.Second, "the feed asked", func() bool { return w.fake.Count(contracttest.CallFeed) > 1 })
	time.Sleep(time.Second)
	if n := len(calls()); n != 0 {
		t.Fatalf("%d token feed calls with no generation", n)
	}
	w.fake.RefuseAlways(contracttest.CallFeed, "")
	var adopted time.Time
	eventually(t, 10*time.Second, "the generation adopted", func() bool {
		adopted = time.Now()
		return w.feed(t).generation != nil
	})
	eventually(t, 10*time.Second, "the token feed asked once the generation is adopted", func() bool { return len(calls()) > 0 })
	if took := calls()[0].Sub(adopted); took > 3*time.Second {
		t.Fatalf("the token feed was asked %v after the adoption (%d generation notices meanwhile)", took, gens())
	}
}

// A grant whose giver has an account here but no document waits; once the
// giver's document is stored (the token channel's all), the judge decides
// it at once, never only at its minute's pass.
func TestAWaitingGrantIsJudgedOnceItsDocumentComes(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	giver := uuid.New()
	w.exec(ctx, t, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'legacy')`,
		giver, w.localPerson(t), giver.String()[:8]+"@id.test")
	l := w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t))
	l.JudgeEvery = time.Hour
	run(t, l)
	id, _ := w.token(t)
	if err := w.fake.GrantToken(id, "wappie", w.number.String(), kc.ItemNumber, kc.CanSend, giver.String()); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the grant waits for its giver's document", func() bool { return w.perms(t, id)[kc.CanSend] == "waiting" })
	gen := w.state(t).Generation
	if _, err := w.contract.StoreDocuments(ctx, store.ContractAnswer, store.ContractDoc{Sub: giver, Generation: *gen, Version: 1,
		Status: kc.AccountActive, Raw: []byte(`{"v":1,"workspaces":[]}`)}); err != nil {
		t.Fatal(err)
	}
	// Judged: the giver is no owner or admin of the workspace here.
	eventually(t, 5*time.Second, "the grant judged once the document came", func() bool {
		return w.perms(t, id)[kc.CanSend] == "refused:"+kc.RefusedLocalRole
	})
}

// The token follower's silence: after SilentAfter without a page, one
// ERROR, recorded for contract status --check (token_feed_silent), however
// many calls fail after it; a page ends the run.
func TestTokenFollowerSilence(t *testing.T) {
	w := newTokenWorld(t)
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.members, logs, lockKey(t))
	l.SilentAfter = 300 * time.Millisecond
	run(t, l)
	eventually(t, 10*time.Second, "a token page", func() bool { return w.feed(t).caughtUp != nil })
	silence := func() int { return len(logs.Lines("level=ERROR", "contract: no token feed page for a long time")) }
	if n := silence(); n != 0 {
		t.Fatalf("%d silences while the token feed answers", n)
	}
	w.fake.RefuseAlways(contracttest.CallTokens, kc.CodeUnavailable)
	// The long-poll in flight began before the refusals.
	w.exec(context.Background(), t, `SELECT pg_notify($1, 'generation')`, store.ContractModeChannel)
	eventually(t, 5*time.Second, "the silence's ERROR", func() bool { return silence() == 1 })
	calls := w.fake.Count(contracttest.CallTokens)
	eventually(t, 5*time.Second, "more failed calls", func() bool { return w.fake.Count(contracttest.CallTokens) >= calls+6 })
	if n := silence(); n != 1 {
		t.Fatalf("%d silences over more failed calls, want one", n)
	}
	if s := w.state(t); s.ErrorClass != store.ContractErrorTokenFeedSilent || s.ErrorAt == nil {
		t.Fatalf("the silence was not recorded: %+v", s)
	}
	if f := w.feed(t); f.failing != kc.CodeUnavailable && f.failing != "refused:"+kc.CodeUnavailable {
		t.Fatalf("the token feed's failure class: %q", f.failing)
	}
	w.fake.RefuseAlways(contracttest.CallTokens, "")
	eventually(t, 10*time.Second, "the token feed answers again", func() bool { return len(logs.Lines("contract: the token feed answers again")) > 0 })
	if n := silence(); n != 1 {
		t.Fatalf("%d silences after the token feed came back", n)
	}
}

// A token page whose commit took over a second from its receipt is logged
// and recorded for --check (the design's bound on a narrowing).
func TestASlowTokenCommitIsRecorded(t *testing.T) {
	w := newTokenWorld(t)
	gen := w.generation(t)
	ctx := context.Background()
	cursor := w.feed(t).cursor
	var once sync.Once
	held := make(chan error, 1)
	page := func(after int64) kc.TokenFeed {
		p := kc.TokenFeed{Generation: gen, Head: cursor + 1, PublishedThrough: kc.T(time.Now()), Items: []kc.TokenFeedItem{}, NextAfter: cursor + 1}
		if after == cursor {
			p.Items = append(p.Items, tokenItem(t, cursor+1, w.tokenRecord(gen, uuid.Must(uuid.NewV7()), 1)))
			// The commit waits for the token state's lock, held from before
			// the page leaves for 1.5 seconds.
			once.Do(func() {
				tx, err := w.pool.Begin(ctx)
				if err == nil {
					_, err = tx.Exec(ctx, `SELECT 1 FROM contract_token_state FOR UPDATE`)
				}
				if err != nil {
					held <- err
					return
				}
				go func() {
					time.Sleep(1500 * time.Millisecond)
					held <- tx.Commit(ctx)
				}()
			})
		}
		return p
	}
	logs := &membershiptest.Logs{}
	run(t, w.tokenLeader(w.membersOn(w.signedTokens(t, &signedTokens{}, page), logs), logs, lockKey(t)))
	eventually(t, 10*time.Second, "the page committed", func() bool { return w.feed(t).cursor == cursor+1 })
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	// Recorded after the commit, by the follower.
	eventually(t, 5*time.Second, "the slow commit recorded", func() bool { return w.feed(t).slowCommit != nil })
	st, err := w.tokens.TokenStatus(ctx, time.Now().Add(-time.Hour))
	if err != nil || st.SlowCommit < time.Second {
		t.Fatalf("the slow commit's time: %v %v", st.SlowCommit, err)
	}
	if len(logs.Lines("level=WARN", "contract: a token page took over a second to commit")) != 1 {
		t.Fatalf("no WARN for the slow commit:\n%s", logs.String())
	}
}

// A token page whose record is of another generation than its page's
// resets both feeds; a platform that keeps sending such a page never
// restarts the contract in a loop: a reset that follows another with no
// page committed between waits the backoff first, from its least doubled
// to its most. (With no wait, the account side's adoption makes the next
// reset within milliseconds.)
func TestARecordOfAnotherGenerationNeverResetsInALoop(t *testing.T) {
	w := newTokenWorld(t)
	gen := w.generation(t)
	other := uuid.NewString()
	page := func(after int64) kc.TokenFeed {
		rec := w.tokenRecord(other, uuid.Must(uuid.NewV7()), 1)
		return kc.TokenFeed{Generation: gen, Head: after + 1, PublishedThrough: kc.T(time.Now()),
			Items: []kc.TokenFeedItem{tokenItem(t, after+1, rec)}, NextAfter: after + 1}
	}
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.membersOn(w.signedTokens(t, &signedTokens{}, page), logs), logs, lockKey(t))
	const least, most = 500 * time.Millisecond, 2 * time.Second
	l.TokenBackoffMin, l.TokenBackoffMax = least, most
	run(t, l)
	resets := func() []string {
		return logs.Lines("contract: the token feed says the platform's generation changed", "why=record_generation")
	}
	eventuallySteps(t, 10*time.Second, "five resets", 5, func() int { return len(resets()) })
	var at []time.Time
	for _, line := range resets() {
		field, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(line), "time="), " ")
		ts, err := time.Parse(time.RFC3339Nano, field)
		if err != nil {
			t.Fatalf("a log line's time: %v", err)
		}
		at = append(at, ts)
	}
	wait := least
	for i := 1; i < len(at); i++ {
		// The log's times are to the millisecond.
		if gap := at[i].Sub(at[i-1]); gap < wait-2*time.Millisecond {
			t.Fatalf("reset %d came %v after the one before, under the backoff's %v:\n%s", i+1, gap, wait, logs.String())
		}
		wait = min(wait*2, most)
	}
	if f := w.feed(t); f.cursor != 0 {
		t.Fatalf("a record of another generation moved the cursor to %d", f.cursor)
	}
}

// The token loops run only while the token mode is on: a leader that leads
// with it off asks the token feed nothing, and sends no acknowledgement and
// no usage report. The mode turned on while it leads starts them, with no
// restart of the leader: by the token channel's notice, well within the mode
// check, or, the notice lost, at the next check. Turned off, they stop, and
// the token feed is asked no more.
func TestTheTokenLoopsFollowTheTokenMode(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	w.exec(ctx, t, `UPDATE contract_token_state SET mode = 'off'`)
	// A use to report, which the usage sender sends at its start.
	if err := w.tokens.AddTokenUse(ctx, store.TokenUse{Used: []store.TokenDay{{Token: uuid.Must(uuid.NewV7()), Day: time.Now()}}}); err != nil {
		t.Fatal(err)
	}
	calls := func() [3]int {
		return [3]int{w.fake.Count(contracttest.CallTokens), w.fake.Count(contracttest.CallTokensApplied), w.fake.Count(contracttest.CallTokenUsage)}
	}
	following := func(logs *membershiptest.Logs) int { return len(logs.Lines("contract: following the token feed")) }
	stopped := func(logs *membershiptest.Logs) int {
		return len(logs.Lines("contract: no longer following the token feed"))
	}
	for _, c := range []struct {
		name      string
		modeCheck time.Duration
		switchTo  func(mode string)
	}{
		{"by the notice", time.Minute, func(mode string) {
			if _, err := w.tokens.SetMode(ctx, mode, time.Now()); err != nil {
				t.Fatal(err)
			}
		}},
		{"by the mode check, the notice lost", 300 * time.Millisecond, func(mode string) {
			// The EXCLUSIVE lock first waits out an ack sender holding the
			// row: the ALTER's own lock would let it keep the row and then
			// block its UPDATE, a deadlock.
			w.exec(ctx, t, `LOCK TABLE contract_token_state IN EXCLUSIVE MODE;
				ALTER TABLE contract_token_state DISABLE TRIGGER contract_token_state_notify;
				UPDATE contract_token_state SET mode = '`+mode+`', caught_up_at = NULL;
				ALTER TABLE contract_token_state ENABLE TRIGGER contract_token_state_notify`)
		}},
	} {
		logs := &membershiptest.Logs{}
		l := w.tokenLeader(w.members, logs, lockKey(t))
		l.ModeCheck = c.modeCheck
		stop := run(t, l)
		eventually(t, 10*time.Second, c.name+": the leader follows the account feed", func() bool {
			return len(logs.Lines("contract: leading")) == 1 && w.feed(t).generation != nil
		})
		before := calls()
		time.Sleep(time.Second)
		if after := calls(); after != before || following(logs) != 0 {
			t.Fatalf("%s: with the token mode off, token calls %v (were %v), the loops started %d times", c.name, after, before, following(logs))
		}

		c.switchTo(store.TokensOn)
		eventually(t, 5*time.Second, c.name+": the token loops started", func() bool { return following(logs) == 1 })
		eventually(t, 5*time.Second, c.name+": a token page, an acknowledgement and a usage report", func() bool {
			n := calls()
			return w.feed(t).caughtUp != nil && n[0] > before[0] && n[1] > before[1] && n[2] > before[2]
		})
		c.switchTo(store.TokensOff)
		eventually(t, 5*time.Second, c.name+": the token loops stopped", func() bool { return stopped(logs) == 1 })
		before = calls()
		time.Sleep(time.Second)
		if after := calls(); after[0] != before[0] {
			t.Fatalf("%s: the token feed was asked %d times after the loops stopped", c.name, after[0]-before[0])
		}
		if n := len(logs.Lines("contract: leading")); n != 1 || following(logs) != 1 {
			t.Fatalf("%s: the leader led %d times, the loops started %d times:\n%s", c.name, n, following(logs), logs.String())
		}
		stop()
		// The usage is reported again by the next run.
		w.exec(ctx, t, `UPDATE contract_token_used SET reported_at = NULL`)
	}
}

// The token feed's backoff is the design's: from 1 second doubled to
// 5 seconds, never the account feed's minute, and a leader's death hands the
// token feed to another process within its 5-second retry.
func TestTokenFollowerBackoffIsAtMostFiveSeconds(t *testing.T) {
	w := newTokenWorld(t)
	calls := w.stamped(contracttest.CallTokens)
	// Another test's generation notice, on the database every test shares,
	// cuts a pause as this installation's own would.
	gens := w.generations(t)
	w.fake.RefuseAlways(contracttest.CallTokens, kc.CodeUnavailable)
	key := lockKey(t)
	l := w.leader(w.members, &membershiptest.Logs{}, key)
	l.Retry = 0
	stopA := run(t, l)
	// Four failures in a row reach the cap (1, 2, 4, 5 s), and the next
	// waits it too; the client asks once more after an unavailable.
	eventuallySteps(t, 15*time.Second, "token feed calls", 10, func() int { return len(calls()) })
	at := calls()
	var worst time.Duration
	for i := 1; i < len(at); i++ {
		worst = max(worst, at[i].Sub(at[i-1]))
	}
	if worst > 6*time.Second {
		t.Fatalf("the longest wait between token feed calls was %v, over the 5-second cap", worst)
	}
	switch n := gens(); {
	case n > 0:
		t.Logf("%d generation notices cut the pauses; the longest was %v", n, worst)
	case worst < 3*time.Second:
		t.Fatalf("the longest wait between token feed calls was %v: the backoff never reached its cap", worst)
	}
	w.fake.RefuseAlways(contracttest.CallTokens, "")

	// A second process, at the default retry; the leader's lock goes with
	// its connection.
	second := NewClient(&http.Client{}, w.fake.URL, nil)
	if err := second.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	m := &Members{Client: second, Contract: w.contract, Tokens: w.tokens, Log: w.logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
	other := w.leader(m, &membershiptest.Logs{}, key)
	other.Retry = 0
	run(t, other)
	eventually(t, 10*time.Second, "a token page", func() bool { return w.feed(t).readAt != nil })
	holder := w.lockHolder(t, key)
	stopA()
	if _, err := w.pool.Exec(context.Background(), `SELECT pg_terminate_backend($1)`, holder); err != nil {
		t.Fatal(err)
	}
	lost := time.Now()
	asked := func() time.Time {
		for _, at := range calls() {
			if at.After(lost) {
				return at
			}
		}
		return time.Time{}
	}
	eventually(t, 10*time.Second, "the other process's token feed call", func() bool { return !asked().IsZero() })
	// Within its 5-second retry, and the lock's taking.
	if took := asked().Sub(lost); took > 6500*time.Millisecond {
		t.Fatalf("the token feed was asked %v after the leader's death", took)
	}
	eventually(t, 10*time.Second, "the other process's token page", func() bool {
		f := w.feed(t)
		return f.readAt != nil && f.readAt.After(lost)
	})
}

// Token auth holds after tokens on until the leader commits a token page
// with more false; and after a stale start (a leader's first token page
// after a stored read over an hour old, as after a restore of Wappie's
// database) it holds again until one does. A fresh start holds nothing.
func TestTokenAuthHoldsAfterTokensOnAndAStaleStart(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	w.exec(ctx, t, `UPDATE contract_token_state SET mode = 'off'`)
	if _, err := w.tokens.SetMode(ctx, store.TokensOn, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f := w.feed(t); f.caughtUp != nil {
		t.Fatalf("tokens on left caught_up_at %v", f.caughtUp)
	}
	stop := run(t, w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t)))
	eventually(t, 10*time.Second, "caught up", func() bool { return w.feed(t).caughtUp != nil })
	stop()

	gen := w.generation(t)
	for _, c := range []struct {
		name  string
		read  string
		holds bool
	}{
		{"a stale start", "2 hours", true},
		{"a fresh start", "10 minutes", false},
	} {
		w.exec(ctx, t, `UPDATE contract_token_state SET read_at = clock_timestamp() - $1::interval, caught_up_at = clock_timestamp()`, c.read)
		cursor := w.feed(t).cursor
		var released atomic.Bool
		page := func(after int64) kc.TokenFeed {
			p := kc.TokenFeed{Generation: gen, Head: cursor + 1, PublishedThrough: kc.T(time.Now()), Items: []kc.TokenFeedItem{}, NextAfter: cursor + 1}
			if after == cursor {
				p.Items = append(p.Items, tokenItem(t, cursor+1, w.tokenRecord(gen, uuid.Must(uuid.NewV7()), 1)))
				p.More = true
				return p
			}
			for deadline := time.Now().Add(5 * time.Second); !released.Load() && time.Now().Before(deadline); {
				time.Sleep(10 * time.Millisecond)
			}
			return p
		}
		logs := &membershiptest.Logs{}
		stop := run(t, w.tokenLeader(w.membersOn(w.signedTokens(t, &signedTokens{}, page), logs), logs, lockKey(t)))
		eventually(t, 5*time.Second, c.name+": the page with more", func() bool { return w.feed(t).cursor == cursor+1 })
		if held := w.feed(t).caughtUp == nil; held != c.holds {
			t.Fatalf("%s: token auth holds %t after a first page with more", c.name, held)
		}
		released.Store(true)
		eventually(t, 5*time.Second, c.name+": caught up", func() bool { return w.feed(t).caughtUp != nil })
		stop()
		if warned := len(logs.Lines("contract: the token feed was last read over an hour before this leader")) == 1; warned != c.holds {
			t.Fatalf("%s: the WARN %t:\n%s", c.name, warned, logs.String())
		}
	}
}

// Of two processes only the leader long-polls the token feed: one call at
// a time, and a few at most while a lost leader's call is still in flight.
func TestTokenFeedOneLongPoll(t *testing.T) {
	w := newTokenWorld(t)
	key := lockKey(t)
	second := NewClient(&http.Client{}, w.fake.URL, nil)
	if err := second.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	other := &Members{Client: second, Contract: w.contract, Tokens: w.tokens, Log: w.logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
	run(t, w.tokenLeader(w.members, &membershiptest.Logs{}, key))
	run(t, w.tokenLeader(other, &membershiptest.Logs{}, key))
	eventually(t, 10*time.Second, "token pages", func() bool { return w.fake.Count(contracttest.CallTokens) > 3 })
	time.Sleep(2 * time.Second)
	if n := w.fake.Most(contracttest.CallTokens); n != 1 {
		t.Fatalf("%d token long-polls at once from one leader", n)
	}
	if _, err := w.pool.Exec(context.Background(), `SELECT pg_terminate_backend($1)`, w.lockHolder(t, key)); err != nil {
		t.Fatal(err)
	}
	lost := time.Now()
	eventually(t, 10*time.Second, "a token page after the takeover", func() bool {
		f := w.feed(t)
		return f.readAt != nil && f.readAt.After(lost)
	})
	time.Sleep(2 * time.Second)
	if n := w.fake.Most(contracttest.CallTokens); n > 4 {
		t.Fatalf("%d token long-polls at once across a takeover", n)
	}
}

// team is a platform team of the person's (its owner on the platform, an
// owner here beside another, so the person's role here can change), named
// to Wappie, with a number of it they read.
func (w *tokenWorld) team(t *testing.T) (team, number uuid.UUID) {
	t.Helper()
	id, err := w.fake.AddTeam("Equipe", w.sub.String())
	if err != nil {
		t.Fatal(err)
	}
	team = uuid.MustParse(id)
	w.localTeam(t, team, "Equipe", member{w.user, "owner", "active"}, member{w.localPerson(t), "owner", "active"})
	return team, w.world.number(t, team, "Equipe", 3, w.user)
}

// selector is a token's selector, from its text.
func selector(t *testing.T, text string) string {
	t.Helper()
	p, err := kc.ParseToken(text)
	if err != nil {
		t.Fatal(err)
	}
	return p.Selector
}

// lastAck is the latest acknowledgement the fake accepted that carries the
// set the pick takes from it (waiting or suspended), after n of them.
func (w *tokenWorld) lastSet(n int, pick func(kc.TokenApplied) bool) (kc.TokenApplied, bool) {
	acks := w.acks()
	for i := len(acks) - 1; i >= n; i-- {
		if pick(acks[i]) {
			return acks[i], true
		}
	}
	return kc.TokenApplied{}, false
}

// A narrowing is acknowledged at once, and so is the end of a reset's
// pass, whatever the acknowledgements' spacing; a widening waits for it.
// The spacing here is a minute: an acknowledgement well within it is one
// sent at once.
func TestANarrowingIsAcknowledgedAtOnce(t *testing.T) {
	w := newTokenWorld(t)
	id, _ := w.token(t, kc.CanRead, kc.CanSend)
	l := w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t))
	const spacing = time.Minute
	l.AckSpacing, l.AckEvery = spacing, 2*spacing
	run(t, l)
	seq := w.latestSeq(t, id)
	eventually(t, 10*time.Second, "the token acknowledged", func() bool { return w.acked(seq) })
	w.settled(t)
	n := len(w.acks())

	w.grant(t, id, kc.CanManage)
	eventually(t, 5*time.Second, "manage applied", func() bool { return w.perms(t, id)[kc.CanManage] == "applied" })
	time.Sleep(500 * time.Millisecond)
	if m := len(w.acks()); m != n {
		t.Fatalf("a widening was acknowledged within the spacing (%d acknowledgements, were %d)", m, n)
	}
	if err := w.fake.UngrantToken(id, "wappie", w.number.String(), kc.CanSend); err != nil {
		t.Fatal(err)
	}
	seq = w.latestSeq(t, id)
	eventually(t, spacing/3, "the narrowing acknowledged within a third of the spacing", func() bool { return w.acked(seq) })

	// A reset: the new generation's first acknowledgement is its pass's,
	// at once.
	gen := w.fake.NewGeneration()
	eventually(t, spacing/3, "an acknowledgement in the new generation within a third of the spacing", func() bool {
		for _, a := range w.acks() {
			if a.Generation == gen {
				return true
			}
		}
		return false
	})
	if f := w.feed(t); f.generation == nil || f.generation.String() != gen || !f.passDone {
		t.Fatalf("the new generation's first acknowledgement went before its pass was done: %+v", f)
	}
}

// Acknowledgements go at most once per AckSpacing while pages widen, and
// at least once per AckEvery while nothing changes. Each is timed as it
// leaves Wappie, which a loaded machine's latency does not move.
func TestAcksAtMostOncePerSecondAndAtLeastOncePerMinute(t *testing.T) {
	w := newTokenWorld(t)
	numbers := []uuid.UUID{w.number}
	for i := range 4 {
		numbers = append(numbers, w.world.number(t, w.home, "Mais", 10+i, w.user))
	}
	id, _ := w.token(t, kc.CanRead)
	var mu sync.Mutex
	var sent []time.Time
	client := NewClient(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/contract/v1/tokens/applied" {
			mu.Lock()
			sent = append(sent, time.Now())
			mu.Unlock()
		}
		return http.DefaultTransport.RoundTrip(r)
	})}, w.fake.URL, nil)
	if err := client.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	stamps := func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), sent...)
	}
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.membersOn(client, logs), logs, lockKey(t))
	const spacing, every = 500 * time.Millisecond, 1200 * time.Millisecond
	l.AckSpacing, l.AckEvery = spacing, every
	run(t, l)
	seq := w.latestSeq(t, id)
	eventually(t, 10*time.Second, "the token acknowledged", func() bool { return w.acked(seq) })
	w.settled(t)
	burst := time.Now()
	for i := range 10 {
		n := numbers[i%len(numbers)]
		perm := []string{kc.CanRead, kc.CanSend}[i/len(numbers)]
		if err := w.fake.GrantToken(id, "wappie", n.String(), kc.ItemNumber, perm, w.sub.String()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	idle := time.Now()
	time.Sleep(2500 * time.Millisecond)
	var in []time.Time
	for _, at := range stamps() {
		if at.After(burst) {
			in = append(in, at)
		}
	}
	if len(in) < 3 {
		t.Fatalf("%d acknowledgements in the burst and the idle seconds after it", len(in))
	}
	for i := 1; i < len(in); i++ {
		gap := in[i].Sub(in[i-1])
		if gap < spacing-10*time.Millisecond {
			t.Fatalf("two acknowledgements %v apart, under the spacing of %v", gap, spacing)
		}
		if in[i].After(idle) && gap > every+spacing {
			t.Fatalf("two acknowledgements %v apart while idle, over %v", gap, every)
		}
	}
	if last := in[len(in)-1]; time.Since(last) > every+spacing {
		t.Fatalf("no acknowledgement for %v while idle", time.Since(last))
	}
}

// An acknowledgement answered with a signed gone (another generation, or
// a through past the platform's head) resets both feeds, once.
func TestAnAckOfAnotherGenerationIsGoneAndResets(t *testing.T) {
	w := newTokenWorld(t)
	gen := w.generation(t)
	var gone atomic.Bool
	s := &signedTokens{}
	s.ack = func(r *http.Request, a kc.TokenApplied) *http.Response {
		if !gone.Swap(true) {
			return w.refused(r, http.StatusGone, kc.CodeGone)
		}
		s.acks = append(s.acks, a)
		return signedAnswer(r, w.secret, http.StatusOK, []byte(`{"accepted":true}`), time.Now())
	}
	page := func(after int64) kc.TokenFeed {
		return kc.TokenFeed{Generation: gen, Head: after, PublishedThrough: kc.T(time.Now()), Items: []kc.TokenFeedItem{}, NextAfter: after}
	}
	puts := w.fake.Count(contracttest.CallSubscribe)
	logs := &membershiptest.Logs{}
	run(t, w.tokenLeader(w.membersOn(w.signedTokens(t, s, page), logs), logs, lockKey(t)))
	eventually(t, 10*time.Second, "an acknowledgement accepted after the reset", func() bool { return len(s.taken()) > 0 })
	if n := len(logs.Lines("contract: the token feed says the platform's generation changed", "why=acknowledgement_gone")); n != 1 {
		t.Fatalf("%d resets for one gone:\n%s", n, logs.String())
	}
	// The reset forgot every sub's version: the round PUT them again, and
	// the account feed adopted the generation again.
	eventually(t, 5*time.Second, "the round again", func() bool { return w.fake.Count(contracttest.CallSubscribe) > puts })
	if f := w.feed(t); f.generation == nil || f.generation.String() != gen {
		t.Fatalf("after the reset Wappie holds generation %v", f.generation)
	}
	for _, a := range s.taken() {
		if a.Generation != gen {
			t.Fatalf("an acknowledgement of generation %s", a.Generation)
		}
	}
}

// A refusal names the version of the record that carried its grant: the
// fake applies it only while that grant is the one it holds, so a grant
// given again meanwhile stays until Wappie refuses it too, by its own
// version.
func TestARefusalNamesTheVersionThatCarriedItsGrant(t *testing.T) {
	w := newTokenWorld(t)
	// A number the person does not read: their grant of Read on it is
	// refused giver_not_reader.
	other := w.world.number(t, w.home, "Suporte", 2)
	id, _ := w.token(t)
	grant := func() error {
		return w.fake.GrantToken(id, "wappie", other.String(), kc.ItemNumber, kc.CanRead, w.sub.String())
	}
	if err := grant(); err != nil {
		t.Fatal(err)
	}
	first := w.version(t, id)
	var again atomic.Int64
	w.fake.Before(contracttest.CallTokensApplied, func(string) {
		// The first acknowledgement after the refusal was queued: the grant
		// is given again before the fake judges it.
		if again.Load() != 0 {
			return
		}
		var queued bool
		if err := w.pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM contract_token_refusals_out WHERE token_id = $1)`, id).
			Scan(&queued); err != nil || !queued {
			return
		}
		if err := w.fake.UngrantToken(id, "wappie", other.String(), kc.CanRead); err != nil {
			t.Error(err)
		}
		if err := grant(); err != nil {
			t.Error(err)
		}
		rec, _ := w.fake.TokenRecord("wappie", id)
		again.Store(rec.Version)
	})
	run(t, w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t)))
	eventually(t, 15*time.Second, "the grant given again refused by its own version", func() bool {
		v := again.Load()
		if v == 0 {
			return false
		}
		for _, a := range w.acks() {
			for _, r := range a.Refused {
				if r.Token == id && r.Version == v {
					return true
				}
			}
		}
		return false
	})
	var versions []int64
	for _, a := range w.acks() {
		for _, r := range a.Refused {
			if r.Token != id {
				continue
			}
			if r.Item != other.String() || r.Perm != kc.CanRead || r.Code != kc.RefusedGiverNotReader {
				t.Fatalf("a refusal %+v", r)
			}
			if len(versions) == 0 || versions[len(versions)-1] != r.Version {
				versions = append(versions, r.Version)
			}
		}
	}
	if len(versions) != 2 || versions[0] != first || versions[1] != again.Load() {
		t.Fatalf("the refusals name versions %v, want %d (the first grant's) then %d (the second's)", versions, first, again.Load())
	}
	eventually(t, 5*time.Second, "the fake took the second grant off", func() bool {
		rec, _ := w.fake.TokenRecord("wappie", id)
		for _, it := range rec.Items {
			if it.ID == other.String() {
				return false
			}
		}
		return rec.Version > again.Load()
	})
}

// A grant a bad record brings that the acknowledgement could not carry (an
// item that is no item id) is refused and only logged, so it never makes
// the whole acknowledgement invalid; the bad record's other grants are told
// as invalid_record.
func TestARefusalThatDidNotDecodeIsOnlyLogged(t *testing.T) {
	w := newTokenWorld(t)
	gen := w.generation(t)
	cursor := w.feed(t).cursor
	id := uuid.Must(uuid.NewV7())
	good := w.tokenRecord(gen, id, 1)
	bad := w.tokenRecord(gen, id, 2)
	at := kc.T(time.Now().Add(-time.Minute))
	bad.Items = []kc.TokenItem{
		{ID: w.number.String(), Kind: kc.ItemNumber, Perms: []kc.TokenPerm{{Perm: kc.CanSend, GrantedBy: w.sub.String(), GrantedAt: at}}},
		{ID: "not an item", Kind: kc.ItemNumber, Perms: []kc.TokenPerm{{Perm: kc.CanRead, GrantedBy: w.sub.String(), GrantedAt: at}}},
	}
	page := func(after int64) kc.TokenFeed {
		p := kc.TokenFeed{Generation: gen, Head: cursor + 2, PublishedThrough: kc.T(time.Now()), Items: []kc.TokenFeedItem{}, NextAfter: cursor + 2}
		switch after {
		case cursor:
			p.Items = append(p.Items, tokenItem(t, cursor+1, good))
			p.NextAfter, p.More = cursor+1, true
		case cursor + 1:
			p.Items = append(p.Items, tokenItem(t, cursor+2, bad))
		}
		return p
	}
	s := &signedTokens{}
	logs := &membershiptest.Logs{}
	run(t, w.tokenLeader(w.membersOn(w.signedTokens(t, s, page), logs), logs, lockKey(t)))
	var told kc.TokenRefusal
	eventually(t, 10*time.Second, "the bad record's grant refused", func() bool {
		for _, a := range s.taken() {
			for _, r := range a.Refused {
				if r.Token == id.String() {
					told = r
					return true
				}
			}
		}
		return false
	})
	if told != (kc.TokenRefusal{Token: id.String(), Version: 2, Item: w.number.String(), Perm: kc.CanSend, Code: kc.RefusedInvalidRecord}) {
		t.Fatalf("the refusal told: %+v", told)
	}
	for _, a := range s.taken() {
		if err := a.Validate(); err != nil {
			t.Fatalf("an acknowledgement is not valid: %v", err)
		}
		for _, r := range a.Refused {
			if r.Item == "not an item" {
				t.Fatalf("the refusal that cannot be told was sent: %+v", r)
			}
		}
	}
	if len(logs.Lines("contract: a bad token record's grant is refused, but cannot be told", "token="+id.String())) == 0 {
		t.Fatalf("the refusal that cannot be told was not logged:\n%s", logs.String())
	}
}

// What is due beyond one acknowledgement's budget of 1000 entries across
// its four lists goes in further acknowledgements at the same through, at
// once, whatever the spacing.
func TestOverflowGoesInFurtherAcksAtTheSameThrough(t *testing.T) {
	w := newTokenWorld(t)
	const queued = 2100
	w.exec(context.Background(), t, `INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code)
		SELECT gen_random_uuid(), 1, gen_random_uuid()::text, 'read', 'giver_not_reader' FROM generate_series(1, $1)`, queued)
	l := w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t))
	l.AckSpacing, l.AckEvery = 5*time.Second, time.Minute
	run(t, l)
	refused := func() int {
		n := 0
		for _, a := range w.acks() {
			n += len(a.Refused)
		}
		return n
	}
	eventually(t, 10*time.Second, "every refusal acknowledged", func() bool { return refused() >= queued })
	var carrying []kc.TokenApplied
	for _, a := range w.acks() {
		if err := a.Validate(); err != nil {
			t.Fatalf("an acknowledgement is not valid: %v", err)
		}
		if n := len(a.Refused) + len(a.Waiting) + len(a.Suspended) + len(a.Held); n > kc.MaxAppliedEntries {
			t.Fatalf("an acknowledgement of %d entries", n)
		}
		if len(a.Refused) > 0 {
			carrying = append(carrying, a)
		}
	}
	if len(carrying) != 3 || len(carrying[0].Refused) != 1000 || len(carrying[1].Refused) != 1000 || len(carrying[2].Refused) != 100 {
		t.Fatalf("the refusals went in %d acknowledgements", len(carrying))
	}
	for _, a := range carrying[1:] {
		if a.Through != carrying[0].Through {
			t.Fatalf("the overflow at through %d, the first at %d", a.Through, carrying[0].Through)
		}
	}
	// The sender marks a batch sent once the platform has accepted it, so
	// the last mark may commit just after the fake recorded its
	// acknowledgement.
	eventually(t, 10*time.Second, "every refusal marked sent", func() bool {
		var sent int
		if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM contract_token_refusals_out WHERE sent_at IS NOT NULL`).Scan(&sent); err != nil {
			t.Fatal(err)
		}
		return sent == queued
	})
}

// The waiting set and the suspended set go whole, only when they change
// (absent means unchanged), the suspended one computed workspace by
// workspace.
func TestWaitingAndSuspendedAreWholeSets(t *testing.T) {
	w := newTokenWorld(t)
	team, teamNumber := w.team(t)
	// A giver with an account here but no document yet: the grant waits.
	waiter := uuid.New()
	w.exec(context.Background(), t, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'legacy')`,
		waiter, w.localPerson(t), waiter.String()[:8]+"@id.test")
	l := w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t))
	l.AckSpacing, l.AckEvery = 50*time.Millisecond, 300*time.Millisecond
	run(t, l)
	a, textA := w.token(t, kc.CanRead)
	if err := w.fake.GrantToken(a, "wappie", w.number.String(), kc.ItemNumber, kc.CanSend, waiter.String()); err != nil {
		t.Fatal(err)
	}
	b, textB, err := w.fake.AddToken(team.String(), w.sub.String(), "Equipe", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.fake.GrantToken(b, "wappie", teamNumber.String(), kc.ItemNumber, kc.CanSend, w.sub.String()); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "both tokens applied", func() bool {
		va, sa := w.held(t, a)
		vb, sb := w.held(t, b)
		return va == w.version(t, a) && vb == w.version(t, b) && w.acked(max(sa, sb))
	})
	ctx := context.Background()
	for _, text := range []string{textA, textB} {
		if _, err := w.tokens.StopToken(ctx, selector(t, text), "test", "", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	both := kc.Suspensions{{Token: a, Cause: kc.SuspendedOperator}, {Token: b, Cause: kc.SuspendedOperator}}
	if b < a {
		both[0], both[1] = both[1], both[0]
	}
	var withBoth int
	eventually(t, 10*time.Second, "both stops told whole", func() bool {
		for i, ack := range w.acks() {
			if len(ack.Suspended) == 2 && ack.Suspended[0] == both[0] && ack.Suspended[1] == both[1] {
				withBoth = i
				return true
			}
		}
		return false
	})
	waiting, ok := w.lastSet(0, func(a kc.TokenApplied) bool { return a.Waiting != nil })
	if !ok || len(waiting.Waiting) != 1 || waiting.Waiting[0].Token != a || waiting.Waiting[0].Perm != kc.CanSend ||
		waiting.Waiting[0].GrantedBy != waiter.String() || waiting.Waiting[0].Item != w.number.String() {
		t.Fatalf("the waiting set: %+v (%t)", waiting.Waiting, ok)
	}
	// Unchanged: the next ones (each minute's, here 300 ms) carry neither.
	n := len(w.acks())
	eventually(t, 5*time.Second, "two more acknowledgements", func() bool { return len(w.acks()) >= n+2 })
	for _, ack := range w.acks()[withBoth+1:] {
		if ack.Suspended != nil || ack.Waiting != nil {
			t.Fatalf("an unchanged set was sent again: %+v %+v", ack.Suspended, ack.Waiting)
		}
	}
	if _, _, err := w.tokens.LiftToken(ctx, selector(t, textA), time.Now()); err != nil {
		t.Fatal(err)
	}
	n = len(w.acks())
	eventually(t, 5*time.Second, "the changed set told whole", func() bool {
		ack, ok := w.lastSet(n, func(a kc.TokenApplied) bool { return a.Suspended != nil })
		return ok && len(ack.Suspended) == 1 && ack.Suspended[0] == kc.Suspension{Token: b, Cause: kc.SuspendedOperator}
	})
}

// Fail-static: with the platform answering nothing, the tokens Wappie
// holds stay as they were (token auth stays caught up, every perm applied),
// the follower and the acknowledgement record their failure; once it
// answers again, what changed meanwhile applies and is acknowledged.
func TestTokenFailStatic(t *testing.T) {
	w := newTokenWorld(t)
	logs := &membershiptest.Logs{}
	run(t, w.tokenLeader(w.members, logs, lockKey(t)))
	id, _ := w.token(t, kc.CanRead, kc.CanSend)
	seq := w.latestSeq(t, id)
	eventually(t, 10*time.Second, "the token acknowledged", func() bool { return w.acked(seq) })
	w.fake.SetDown(true)
	// The long-poll in flight when it went down may still answer: the
	// change is made once the calls fail.
	eventually(t, 10*time.Second, "the failures recorded", func() bool {
		f := w.feed(t)
		return f.failing != "" && f.ackError != ""
	})
	if err := w.fake.RevokeToken(id, kc.RevokedInConsole); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	f := w.feed(t)
	p := w.perms(t, id)
	if _, revoked, _ := w.stored(t, id); revoked || f.caughtUp == nil || p[kc.CanRead] != "applied" || p[kc.CanSend] != "applied" {
		t.Fatalf("with the platform down: revoked %t, caught up %v, perms %v", revoked, f.caughtUp, p)
	}
	w.fake.SetDown(false)
	seq = w.latestSeq(t, id)
	eventually(t, 10*time.Second, "the revocation applied and acknowledged", func() bool {
		_, revoked, _ := w.stored(t, id)
		return revoked && w.acked(seq)
	})
	eventually(t, 5*time.Second, "the failures cleared", func() bool {
		f := w.feed(t)
		return f.failing == "" && f.ackError == ""
	})
	if len(logs.Lines("contract: the token feed answers again")) == 0 {
		t.Fatalf("no line for the feed's return:\n%s", logs.String())
	}
}

// The usage report carries each key's absolute count from its one row, to
// which every process adds its own counts; a day of use is reported once;
// reports go at most once per UsageEvery.
func TestUsageIsAbsoluteAndSentAtMostOncePerMinute(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	stamps := w.stamped(contracttest.CallTokenUsage)
	one, two := store.NewTokens(w.pool), store.NewTokens(w.pool)
	a, b := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	day := time.Now().UTC()
	send := kc.CanSend
	refusal := func(n int64) store.TokenUseRefusal {
		return store.TokenUseRefusal{Token: a, Day: day, Device: &w.number, Perm: &send, Code: kc.UseNoPermission, Count: n}
	}
	if err := one.AddTokenUse(ctx, store.TokenUse{Used: []store.TokenDay{{Token: a, Day: day}}, Refusals: []store.TokenUseRefusal{refusal(2)}}); err != nil {
		t.Fatal(err)
	}
	if err := two.AddTokenUse(ctx, store.TokenUse{Used: []store.TokenDay{{Token: a, Day: day}},
		Refusals: []store.TokenUseRefusal{refusal(3), {Token: b, Day: day, Code: kc.UseRevoked, Count: 1}}}); err != nil {
		t.Fatal(err)
	}
	l := w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t))
	const every = 400 * time.Millisecond
	l.UsageEvery = every
	run(t, l)
	count := func(u kc.TokenUsage, token uuid.UUID, code string) int64 {
		for _, r := range u.Refusals {
			if r.Token == token.String() && r.Code == code {
				return r.Count
			}
		}
		return -1
	}
	eventually(t, 5*time.Second, "the first report", func() bool { return len(w.fake.TokenUsage("wappie")) > 0 })
	first := w.fake.TokenUsage("wappie")[0]
	if count(first, a, kc.UseNoPermission) != 5 || count(first, b, kc.UseRevoked) != 1 || len(first.Used) != 1 ||
		first.Used[0] != (kc.TokenUsed{Token: a.String(), Day: day.Format(time.DateOnly)}) {
		t.Fatalf("the first report: %+v", first)
	}
	for _, r := range first.Refusals {
		if (r.Code == kc.UseRevoked) != (r.Item == nil && r.Perm == nil) {
			t.Fatalf("a refusal's item and perm: %+v", r)
		}
	}
	if err := one.AddTokenUse(ctx, store.TokenUse{Used: []store.TokenDay{{Token: a, Day: day}}, Refusals: []store.TokenUseRefusal{refusal(1)}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the next report", func() bool { return len(w.fake.TokenUsage("wappie")) > 1 })
	next := w.fake.TokenUsage("wappie")[1]
	if count(next, a, kc.UseNoPermission) != 6 || count(next, b, kc.UseRevoked) != -1 || len(next.Used) != 0 {
		t.Fatalf("the next report: %+v", next)
	}
	// Once more, to time three reports.
	if err := two.AddTokenUse(ctx, store.TokenUse{Refusals: []store.TokenUseRefusal{refusal(1)}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "a third report", func() bool { return len(w.fake.TokenUsage("wappie")) > 2 })
	at := stamps()
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < every-50*time.Millisecond {
			t.Fatalf("two usage reports %v apart, under %v", gap, every)
		}
	}
}

// The operator's stop, by selector, stands over the token feed: recorded
// with the platform down, it bumps the token's access_version and wakes
// every process; neither a later record nor a reset lifts it; it is told
// as suspended {operator}; and a stop of a selector Wappie holds no record
// of yet applies once the token arrives.
func TestTheOperatorsStopStandsOverTheFeed(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	l := w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t))
	l.AckEvery = 300 * time.Millisecond
	run(t, l)
	id, text := w.token(t, kc.CanRead)
	seq := w.latestSeq(t, id)
	eventually(t, 10*time.Second, "the token acknowledged", func() bool { return w.acked(seq) })
	access := func() int64 {
		var v int64
		if err := pg.InTenantTx(ctx, w.pool, w.home.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT access_version FROM contract_tokens WHERE id = $1`, id).Scan(&v)
		}); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := access()
	listen, err := w.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Release()
	if _, err := listen.Exec(ctx, `LISTEN wappie_contract_tokens`); err != nil {
		t.Fatal(err)
	}
	w.fake.SetDown(true)
	if _, err := w.tokens.StopToken(ctx, selector(t, text), "operator", "leaked", time.Now()); err != nil {
		t.Fatal(err)
	}
	if access() != before+1 {
		t.Fatalf("the stop left access_version at %d (was %d)", access(), before)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		n, err := listen.Conn().WaitForNotification(wait)
		if err != nil {
			t.Fatalf("no notice of the stop: %v", err)
		}
		if n.Payload == id {
			break
		}
	}
	open := func() bool {
		stops, err := w.tokens.TokenStops(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range stops {
			if s.Selector == selector(t, text) && s.Cause == "operator" && s.LiftedAt == nil {
				return true
			}
		}
		return false
	}
	w.fake.SetDown(false)
	stopped := kc.Suspension{Token: id, Cause: kc.SuspendedOperator}
	told := func(s kc.Suspension) func() bool {
		return func() bool {
			ack, ok := w.lastSet(0, func(a kc.TokenApplied) bool { return a.Suspended != nil })
			for _, x := range ack.Suspended {
				if ok && x == s {
					return true
				}
			}
			return false
		}
	}
	eventually(t, 10*time.Second, "the stop told", told(stopped))

	// A later record, then a reset, leave it.
	if err := w.fake.ShortenToken(id, time.Now().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the later record applied", func() bool { v, _, _ := w.stored(t, id); return v == w.version(t, id) })
	gen := w.fake.NewGeneration()
	eventually(t, 15*time.Second, "the new generation's pass done", func() bool {
		f := w.feed(t)
		return f.generation != nil && f.generation.String() == gen && f.passDone
	})
	if !open() {
		t.Fatal("the feed or the reset lifted the operator's stop")
	}
	// The reset forgot the sets told: the new generation is told them
	// whole.
	eventually(t, 10*time.Second, "the stop told in the new generation", func() bool {
		ack, ok := w.lastSet(0, func(a kc.TokenApplied) bool { return a.Suspended != nil && a.Generation == gen })
		return ok && slicesContains(ack.Suspended, stopped)
	})

	// A selector stopped before its token reaches Wappie.
	later, laterText, err := w.fake.AddToken(w.home.String(), w.sub.String(), "Later", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.tokens.StopToken(ctx, selector(t, laterText), "operator", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	w.grant(t, later, kc.CanRead)
	eventually(t, 10*time.Second, "the early stop told once the token arrived", told(kc.Suspension{Token: later, Cause: kc.SuspendedOperator}))
}

func slicesContains[S ~[]E, E comparable](s S, v E) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Wappie's own stops are told and lifted with their rules: the creator
// disabled here (creator_disabled_here), the creator's local role not an
// owner's or admin's (local_rule), and a record Wappie could not apply
// (apply_failed, told as local_rule), which a later version that applies
// cleanly lifts.
func TestCreatorDisabledHereAndLocalRuleAreReportedAndLifted(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	team, teamNumber := w.team(t)
	l := w.tokenLeader(w.members, &membershiptest.Logs{}, lockKey(t))
	l.AckEvery = 300 * time.Millisecond
	run(t, l)
	id, _, err := w.fake.AddToken(team.String(), w.sub.String(), "Equipe", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.fake.GrantToken(id, "wappie", teamNumber.String(), kc.ItemNumber, kc.CanSend, w.sub.String()); err != nil {
		t.Fatal(err)
	}
	seq := w.latestSeq(t, id)
	eventually(t, 10*time.Second, "the token acknowledged", func() bool { return w.acked(seq) })
	set := func(want ...kc.Suspension) func() bool {
		n := len(w.acks())
		return func() bool {
			ack, ok := w.lastSet(n, func(a kc.TokenApplied) bool { return a.Suspended != nil })
			if !ok || len(ack.Suspended) != len(want) {
				return false
			}
			for i := range want {
				if ack.Suspended[i] != want[i] {
					return false
				}
			}
			return true
		}
	}
	in := func(ws uuid.UUID, sql string, args ...any) {
		t.Helper()
		if err := pg.InTenantTx(ctx, w.pool, ws.String(), func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, sql, args...)
			if err == nil && tag.RowsAffected() != 1 {
				err = errors.New("no row changed")
			}
			return err
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	member := func(role string) {
		t.Helper()
		in(team, `UPDATE workspace_memberships SET role = $3 WHERE tenant_id = $1 AND user_id = $2`, team, w.user, role)
	}
	status := func(st string) {
		t.Helper()
		in(w.home, `UPDATE users SET status = $2 WHERE id = $1`, w.user, st)
	}
	for _, c := range []struct {
		name        string
		stop, lift  func()
		cause       string
		suspendedBy string
	}{
		{"creator_disabled_here", func() { status("disabled") }, func() { status("active") }, kc.SuspendedCreatorDisabledHere, ""},
		{"local_rule", func() { member("member") }, func() { member("owner") }, kc.SuspendedLocalRule, ""},
		{"apply_failed",
			func() {
				w.exec(ctx, t, `INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'apply_failed', clock_timestamp(), 'wappie')`,
					w.fakeSelector(t, id))
			},
			func() {
				if err := w.fake.ShortenToken(id, time.Now().Add(72*time.Hour)); err != nil {
					t.Fatal(err)
				}
			},
			kc.SuspendedLocalRule, ""},
	} {
		told := set(kc.Suspension{Token: id, Cause: c.cause})
		c.stop()
		eventually(t, 10*time.Second, c.name+": told", told)
		lifted := set()
		c.lift()
		eventually(t, 10*time.Second, c.name+": lifted", lifted)
	}
}

// fakeSelector is the selector of the fake's record of the token.
func (w *tokenWorld) fakeSelector(t *testing.T, id string) string {
	t.Helper()
	rec, ok := w.fake.TokenRecord("wappie", id)
	if !ok {
		t.Fatalf("the fake holds no record of %s", id)
	}
	return rec.Selector
}
