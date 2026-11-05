package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// contract tokens on, off and status, contract mode off's token line, the
// token part's status lines and findings, and tokens suspend, lift and list
// (step 7's plan, section 8 and 10.6).

// tokenMode is the token mode and whether caught_up_at is set.
func tokenMode(ctx context.Context, t *testing.T, c *store.Contract) (string, bool) {
	t.Helper()
	ts, err := c.Tokens().TokenStatus(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ts.Mode, ts.CaughtUpAt != nil
}

// contract tokens on asks, with nothing changed and exit 3 when one
// refuses: the contract on, a generation stored, the server ready, and a
// signed answer of the token feed with the stored generation, which proves
// the platform's token routes are live. On clears caught_up_at and makes
// the snapshots due; on again and off ask nothing.
func TestContractTokensOnNeedsT1(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	secret := membershiptest.Secret(t)
	fake := membershiptest.StartFake(t, secret)
	client := membership.NewClient(&http.Client{}, fake.URL, nil)
	if err := client.Use(secret, ""); err != nil {
		t.Fatal(err)
	}
	probed := 0
	probe := func(ctx context.Context) (kc.TokenFeed, error) {
		probed++
		return client.Tokens(ctx, 0, 0)
	}
	ready := func() error { return nil }
	refused := func(name, want string, ready func() error) {
		t.Helper()
		var out bytes.Buffer
		err := contractTokens(ctx, c, store.TokensOn, ready, probe, &out)
		var exit exitError
		if !errors.As(err, &exit) || exit.code != exitNotReady || !strings.Contains(err.Error(), want) || out.Len() != 0 {
			t.Fatalf("%s: %v %q, want exit %d with %q", name, err, out.String(), exitNotReady, want)
		}
		if mode, _ := tokenMode(ctx, t, c); mode != store.TokensOff {
			t.Fatalf("%s: the token mode is %s", name, mode)
		}
	}
	refused("the contract off", "contract tokens on: not ready: the contract is off", ready)
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	refused("no generation", "Wappie holds no generation", ready)
	gen, _ := fake.Generation()
	execSQL(t, pool, `UPDATE contract_state SET generation = $1`, uuid.MustParse(gen))
	refused("the server not ready", "contract tokens on: not ready: the test's", func() error {
		return errors.New("contract tokens on: not ready: the test's; nothing changed")
	})
	fake.RefuseAlways(contracttest.CallTokens, kc.CodeNotFound)
	refused("no token routes", "the platform's token feed did not answer (refused:not_found)", ready)
	fake.RefuseAlways(contracttest.CallTokens, "")
	execSQL(t, pool, `UPDATE contract_state SET generation = gen_random_uuid()`)
	refused("another generation", "the token feed answers generation "+gen, ready)
	execSQL(t, pool, `UPDATE contract_state SET generation = $1`, uuid.MustParse(gen))
	if probed != 2 {
		t.Fatalf("the token feed was asked %d times, want 2 (once each refusal got that far)", probed)
	}

	execSQL(t, pool, `UPDATE contract_token_state SET caught_up_at = clock_timestamp()`)
	ws := uuid.New()
	execSQL(t, pool, `INSERT INTO contract_workspaces (workspace_id, kind, named_at, snapshot_due_at, snapshot_ok_at)
		VALUES ($1, 'team', clock_timestamp(), clock_timestamp() + interval '1 hour', clock_timestamp())`, ws)
	var out bytes.Buffer
	if err := contractTokens(ctx, c, store.TokensOn, ready, probe, &out); err != nil || !strings.HasPrefix(out.String(), "contract tokens: off -> on\n") {
		t.Fatalf("tokens on: %v %q", err, out.String())
	}
	if mode, caught := tokenMode(ctx, t, c); mode != store.TokensOn || caught {
		t.Fatalf("after tokens on: mode %s, caught up %t", mode, caught)
	}
	var due bool
	if err := pool.QueryRow(ctx, `SELECT snapshot_due_at <= clock_timestamp() FROM contract_workspaces WHERE workspace_id = $1`, ws).Scan(&due); err != nil || !due {
		t.Fatalf("the snapshot is not due after the switch: %v", err)
	}
	out.Reset()
	if err := contractTokens(ctx, c, store.TokensOn, func() error { return errors.New("never asked") }, probe, &out); err != nil ||
		out.String() != "contract tokens: already on; nothing changed\n" || probed != 3 {
		t.Fatalf("tokens on again: %v %q (asked %d)", err, out.String(), probed)
	}
	// Off makes the snapshots due as well, which then go without the
	// token part's members.
	execSQL(t, pool, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '1 hour' WHERE workspace_id = $1`, ws)
	out.Reset()
	if err := contractTokens(ctx, c, store.TokensOff, nil, nil, &out); err != nil || !strings.HasPrefix(out.String(), "contract tokens: on -> off\n") {
		t.Fatalf("tokens off: %v %q", err, out.String())
	}
	if err := pool.QueryRow(ctx, `SELECT snapshot_due_at <= clock_timestamp() FROM contract_workspaces WHERE workspace_id = $1`, ws).Scan(&due); err != nil || !due {
		t.Fatalf("the snapshot is not due after tokens off: %v", err)
	}
	if err := contractTokensCommand([]string{"sideways"}, &out); !errors.As(err, new(usageError)) {
		t.Fatalf("contract tokens sideways: %v", err)
	}
	if err := contractTokensCommand([]string{"on", "now"}, &out); !errors.As(err, new(usageError)) {
		t.Fatalf("contract tokens on now: %v", err)
	}
}

// The probe tokens on sends: the contract's secret loaded from its sealed
// file with Wappie's key, as contract check loads it, publishing nothing,
// and one signed GET of the token feed from 0 with no wait, which the
// platform answers at once; a refusal and a failed load each have their
// class.
func TestTokensOnProbesTheTokenFeedOnce(t *testing.T) {
	w := newSecretWorld(t)
	secret := membershiptest.Secret(t)
	w.seal(t, "current", secret)
	fake := membershiptest.StartFake(t, secret)
	platform, err := url.Parse(fake.URL)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var asked []string
	proxy := httputil.NewSingleHostReverseProxy(platform)
	front := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		proxy.ServeHTTP(rw, r)
	}))
	t.Cleanup(front.Close)
	loaded := filepath.Join(t.TempDir(), "contract-secrets.loaded")
	cfg := config.Contract{Addr: strings.TrimPrefix(front.URL, "http://"), SecretFile: w.dir.Path(membership.SecretFileName),
		SecretOtherFile: w.dir.Path(membership.SecretOtherFileName), KMSKeyARN: testKeyARN, KMSRegion: testRegion, LoadedFile: loaded}
	ctx := context.Background()

	start := time.Now()
	feed, err := probeTokens(ctx, cfg, w.key.Open)
	gen, _ := fake.Generation()
	if err != nil || feed.Generation != gen {
		t.Fatalf("the probe: %+v %v, want generation %s", feed, err, gen)
	}
	// An empty token feed: a wait would have held the answer.
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the probe took %v", took)
	}
	mu.Lock()
	if len(asked) != 1 || asked[0] != "GET /contract/v1/tokens?after=0&wait=0" {
		t.Fatalf("the probe asked %q", asked)
	}
	mu.Unlock()
	if _, err := os.Stat(loaded); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the probe published a load: %v", err)
	}

	fake.RefuseAlways(contracttest.CallTokens, kc.CodeNotFound)
	_, err = probeTokens(ctx, cfg, w.key.Open)
	if err == nil || tokenProbeClass(err) != "refused:not_found" {
		t.Fatalf("a refused probe: %v (class %q)", err, tokenProbeClass(err))
	}
	fake.RefuseAlways(contracttest.CallTokens, "")
	before := fake.Count(contracttest.CallTokens)
	w.key.SetFail(errors.New("kms: the key is disabled"))
	_, err = probeTokens(ctx, cfg, w.key.Open)
	if err == nil || !strings.HasPrefix(tokenProbeClass(err), "the secrets did not load (step ") {
		t.Fatalf("a probe whose secrets did not load: %v (class %q)", err, tokenProbeClass(err))
	}
	if n := fake.Count(contracttest.CallTokens); n != before {
		t.Fatalf("a probe whose secrets did not load asked the token feed (%d calls, were %d)", n, before)
	}
}

// contract mode off always succeeds and turns the token mode off with it,
// saying so on its second line (B2b's undo reads the first, and treats a
// non-zero exit as UNDO FAILED); the contract back on leaves tokens off.
func TestContractModeOffAlsoTurnsTokensOff(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Tokens().SetMode(ctx, store.TokensOn, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, tokens := range []string{store.TokensOn, store.TokensOff} {
		execSQL(t, pool, `UPDATE contract_token_state SET mode = $1`, tokens)
		var out bytes.Buffer
		if err := contractMode(ctx, c, store.ContractOff, nil, &out); err != nil {
			t.Fatalf("contract mode off with tokens %s: %v", tokens, err)
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) != 2 || lines[0] != "contract mode: observe -> off" || lines[1] != "tokens mode: off (with the contract)" {
			t.Fatalf("contract mode off with tokens %s said %q", tokens, out.String())
		}
		if mode, _ := tokenMode(ctx, t, c); mode != store.TokensOff {
			t.Fatalf("contract mode off left tokens %s", mode)
		}
		if err := contractMode(ctx, c, store.ContractObserve, func() error { return nil }, &out); err != nil {
			t.Fatal(err)
		}
		if mode, _ := tokenMode(ctx, t, c); mode != store.TokensOff {
			t.Fatalf("the contract back on turned tokens %s", mode)
		}
	}
	// Tokens on refuses while the contract is off, in the store too.
	if _, err := c.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Tokens().SetMode(ctx, store.TokensOn, time.Now()); !errors.Is(err, store.ErrTokensNeedTheContract) {
		t.Fatalf("tokens on with the contract off: %v", err)
	}
}

// The lines the kits read by their prefixes (mode:, transport:, feed:,
// generation:, published_through:, subs:, the workspaces' and finding:)
// are what they were before the token part, byte for byte, with tokens off
// and on; every line the token part adds starts with "tokens ", which none
// of those prefixes or the kits' workspace pattern matches.
func TestStatusLinesKeepTheirPrefixes(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	gen := uuid.MustParse("0199b1e0-0000-7000-8000-000000000001")
	ws := uuid.MustParse("0199b1e0-0000-7000-8000-0000000000aa")
	st := store.ContractStatus{Now: now, Held: 1, Followed: 1, Accounts: 1,
		State: store.ContractState{Mode: store.ContractObserve, ModeChangedAt: now.Add(-24 * time.Hour), Generation: &gen,
			GenerationConfirmed: true, FeedCursor: 42, PublishedThrough: at(3 * time.Second), RoundGeneration: &gen,
			FeedReadAt: at(2 * time.Second), EventsFrom: at(48 * time.Hour)},
		Workspaces: []store.ContractWorkspaceStatus{{ID: ws, Kind: "personal", Status: "open", NamedAt: now.Add(-time.Hour),
			SnapshotOKAt: at(time.Minute), SnapshotDueAt: now.Add(time.Hour), Local: true}}}
	cfg := config.Contract{Socket: "/run/platform/contract.sock"}
	loaded := membership.Loaded{PID: 7, LoadedAt: now.Add(-time.Hour), Reloads: 1, Current: "0123456789ab", Other: "none", Error: "none"}
	files := sealed{present: true, state: "steady", current: "0123456789ab", other: "none"}
	want := []string{
		"mode: observe (since 2026-10-26T12:00:00Z)",
		"transport: socket",
		"secrets (server): pid=7 loaded_at=2026-10-27T11:00:00Z reloads=1 current=0123456789ab other=none error=none",
		"secrets (files): state=steady current=0123456789ab other=none",
		"generation: 0199b1e0-0000-7000-8000-000000000001 confirmed=true",
		"cursor: 42",
		"published_through: 3s ago (2026-10-27T11:59:57Z)",
		"feed: last page 2s ago (2026-10-27T11:59:58Z)",
		"subs: held 1, followed 1, subscriptions 1, round done",
		"last error: none",
		"platform workspaces: 1",
		"  0199b1e0-0000-7000-8000-0000000000aa personal open named 1h0m0s ago (2026-10-27T11:00:00Z), snapshot 1m0s ago (2026-10-27T11:59:00Z), events pending 0 parked 0 coalesced 0",
		"person invitations pending: 0 in 0 local teams",
	}
	workspace := regexp.MustCompile(`\s+([0-9a-f-]{36}) (personal|team) (\S+) named (.+?), snapshot (.+?), events pending (\d+) parked (\d+) coalesced (\d+)(.*)$`)
	prefixes := []string{"mode:", "transport:", "secrets (server):", "secrets (files):", "generation:", "published_through:", "feed:", "subs:",
		"last error:", "platform workspaces:", "person invitations pending:", "finding:"}
	for _, mode := range []string{store.TokensOff, store.TokensOn} {
		ts := store.TokenStatus{Mode: mode, ModeChangedAt: now.Add(-time.Hour), Cursor: 9, PublishedThrough: at(time.Second),
			CaughtUpAt: at(time.Second), ReadAt: at(time.Second), AckThrough: 9, AckSentAt: at(time.Second), UsageSentAt: at(30 * time.Second),
			PassGeneration: &gen, PassDoneAt: at(time.Hour), Live: 2}
		var out bytes.Buffer
		if err := statusReport(&out, st, ts, cfg, loaded, true, nil, files, true); err != nil {
			t.Fatalf("tokens %s: %v\n%s", mode, err, out.String())
		}
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		var kept, added []string
		for _, l := range lines {
			if strings.HasPrefix(l, "tokens ") {
				added = append(added, l)
				continue
			}
			kept = append(kept, l)
		}
		if strings.Join(kept, "\n") != strings.Join(want, "\n") {
			t.Fatalf("tokens %s: the lines before the token part changed:\n%s\nwant:\n%s", mode, strings.Join(kept, "\n"), strings.Join(want, "\n"))
		}
		if len(added) < 5 || added[0] != "tokens mode: "+mode+" (since 2026-10-27T11:00:00Z)" {
			t.Fatalf("tokens %s: the token lines %q", mode, added)
		}
		for _, l := range added {
			for _, p := range prefixes {
				if strings.HasPrefix(l, p) {
					t.Fatalf("the token line %q starts with the kits' %q", l, p)
				}
			}
			if workspace.MatchString(l) {
				t.Fatalf("the token line %q is a workspace's to the kits", l)
			}
		}
	}
}

// The token part's findings, each at both sides of its bound, only while
// the contract and the token mode are both on, each bound counted from the
// later of its own time and the token mode's switch.
func TestTokenFindingsOnlyWhileTokensAreOn(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	clean := func() store.TokenStatus {
		return store.TokenStatus{Mode: store.TokensOn, ModeChangedAt: now.Add(-24 * time.Hour), PublishedThrough: at(time.Second),
			CaughtUpAt: at(time.Second), ReadAt: at(time.Second)}
	}
	if f := tokenFindings(now, true, clean()); len(f) != 0 {
		t.Fatalf("a clean token part: %v", f)
	}
	for _, c := range []struct {
		name        string
		under, over func(*store.TokenStatus)
		finding     string
	}{
		{"the token feed's last read",
			func(s *store.TokenStatus) { s.ReadAt = at(4 * time.Minute) }, func(s *store.TokenStatus) { s.ReadAt = at(6 * time.Minute) },
			"the token feed was last read 6m0s ago (2026-10-27T11:54:00Z)"},
		{"the token feed's published_through",
			func(s *store.TokenStatus) { s.PublishedThrough = at(59 * time.Minute) }, func(s *store.TokenStatus) { s.PublishedThrough = at(61 * time.Minute) },
			"the token feed's published_through is 1h1m0s ago (2026-10-27T10:59:00Z): tokens' send and manage are refused"},
		{"token auth held",
			func(s *store.TokenStatus) { s.CaughtUpAt, s.ModeChangedAt = nil, now.Add(-4*time.Minute) },
			func(s *store.TokenStatus) { s.CaughtUpAt, s.ModeChangedAt = nil, now.Add(-6*time.Minute) },
			"token auth holds: no token page with more false has committed since the token mode's switch at 2026-10-27T11:54:00Z"},
		{"the acknowledgement failing",
			func(s *store.TokenStatus) { s.AckError, s.AckErrorAt = "unavailable", at(4*time.Minute) },
			func(s *store.TokenStatus) { s.AckError, s.AckErrorAt = "unavailable", at(6*time.Minute) },
			"the token acknowledgement has failed since 2026-10-27T11:54:00Z (unavailable)"},
		{"the usage report failing",
			func(s *store.TokenStatus) { s.UsageError, s.UsageErrorAt = "unavailable", at(14*time.Minute) },
			func(s *store.TokenStatus) { s.UsageError, s.UsageErrorAt = "unavailable", at(16*time.Minute) },
			"the token usage report has failed since 2026-10-27T11:44:00Z (unavailable)"},
		{"unlisted tokens", func(s *store.TokenStatus) {}, func(s *store.TokenStatus) { s.Unlisted = 2 },
			"2 tokens unlisted by a reset's pass in the last day: refused here for good"},
		{"a reading key changed", func(s *store.TokenStatus) {}, func(s *store.TokenStatus) { s.KeyChanged = 1 },
			"1 tokens' reading key changed: their new grants are refused"},
		{"apply_failed", func(s *store.TokenStatus) { s.Stopped = 3 }, func(s *store.TokenStatus) { s.ApplyFailed = 1 },
			"1 tokens stopped here: a record of theirs could not be applied (apply_failed)"},
		{"a slow commit",
			func(s *store.TokenStatus) { s.SlowCommitAt, s.SlowCommit = at(61*time.Minute), 1500*time.Millisecond },
			func(s *store.TokenStatus) { s.SlowCommitAt, s.SlowCommit = at(59*time.Minute), 1500*time.Millisecond },
			"a token page took 1500 ms to commit at 2026-10-27T11:01:00Z (over a second)"},
	} {
		under, over := clean(), clean()
		c.under(&under)
		c.over(&over)
		if f := tokenFindings(now, true, under); len(f) != 0 {
			t.Errorf("%s, within its bound: %v", c.name, f)
		}
		f := tokenFindings(now, true, over)
		if len(f) != 1 || f[0] != c.finding {
			t.Errorf("%s, past its bound: %q, want %q", c.name, f, c.finding)
		}
		off := over
		off.Mode = store.TokensOff
		if f := tokenFindings(now, true, off); len(f) != 0 {
			t.Errorf("%s with tokens off: %v", c.name, f)
		}
		if f := tokenFindings(now, false, over); len(f) != 0 {
			t.Errorf("%s with the contract off: %v", c.name, f)
		}
	}
	// A switch a minute ago: the feed never read is not late yet.
	s := clean()
	s.ModeChangedAt, s.ReadAt, s.PublishedThrough = now.Add(-time.Minute), nil, nil
	if f := tokenFindings(now, true, s); len(f) != 0 {
		t.Fatalf("a switch a minute ago: %v", f)
	}

	// Through contract status --check on the database.
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	ctx := context.Background()
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 day', feed_read_at = clock_timestamp(),
		published_through = clock_timestamp(), generation = gen_random_uuid(), round_generation = NULL`)
	execSQL(t, pool, `UPDATE contract_token_state SET mode_changed_at = clock_timestamp() - interval '1 day',
		read_at = clock_timestamp() - interval '10 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); has(findings, "token") {
		t.Fatalf("token findings with tokens off: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_token_state SET mode = 'on'`)
	if _, findings, code := statusRun(t, c, config.Contract{}); code != 1 || !has(findings, "the token feed was last read 10m") {
		t.Fatalf("with tokens on: %v", findings)
	}
}

// tokens suspend and lift: a selector, or a whole token of which only the
// selector is kept, or either from stdin; the same words whether or not
// Wappie holds a token of the selector; the record, and its replay after
// a restore; list.
func TestTokensSuspendCommand(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tokens := store.NewTokens(pool)
	const known, unknown = "0123456789abcdef", "fedcba9876543210"
	var knownID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO contract_token_selectors (selector, token_id, tenant_id, hash, until)
		VALUES ($1, gen_random_uuid(), gen_random_uuid(), decode(repeat('ab', 32), 'hex'), clock_timestamp() + interval '1 day')
		RETURNING token_id`, known).Scan(&knownID); err != nil {
		t.Fatal(err)
	}

	// A whole token: only its selector is kept.
	whole := kc.TokenPrefix + known + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := kc.ParseToken(whole); err != nil {
		t.Fatalf("the test's token does not parse: %v", err)
	}
	for _, in := range []struct{ arg, stdin string }{{known, ""}, {whole, ""}, {"-", whole + "\n"}, {"-", known}} {
		if sel, err := tokenSelector(in.arg, strings.NewReader(in.stdin)); err != nil || sel != known {
			t.Fatalf("the selector of %q (stdin %q): %q, %v", in.arg, in.stdin, sel, err)
		}
	}
	for _, bad := range []string{"", "0123456789ABCDEF", whole + " ", "thc_" + known} {
		if _, err := tokenSelector(bad, strings.NewReader("")); err == nil || (bad != "" && strings.Contains(err.Error(), bad)) {
			t.Fatalf("the selector of %q: %v", bad, err)
		}
	}

	record := filepath.Join(t.TempDir(), "token-stops.jsonl")
	said := func(r tokenStopRecord, note string) string {
		t.Helper()
		var out bytes.Buffer
		if err := changeTokenStop(ctx, tokens, r, note, record, &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	at := time.Now().UTC().Truncate(time.Second)
	a := said(tokenStopRecord{Selector: known, At: at}, "leaked in a log")
	b := said(tokenStopRecord{Selector: unknown, At: at.Add(time.Second)}, "")
	if strings.ReplaceAll(a, known, "S") != strings.ReplaceAll(b, unknown, "S") {
		t.Fatalf("the words differ for a selector Wappie holds and one it does not:\n%s\n%s", a, b)
	}
	lifted := said(tokenStopRecord{Selector: known, At: at.Add(2 * time.Second), Lift: true}, "")
	if !strings.Contains(lifted, "the operator's stop is lifted") {
		t.Fatalf("tokens lift: %q", lifted)
	}
	var secretKept bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM contract_token_stops x WHERE x::text LIKE '%AAAAAAAA%')`).Scan(&secretKept); err != nil || secretKept {
		t.Fatalf("a stop keeps more than the selector: %t %v", secretKept, err)
	}
	state := func() map[string]string {
		stops, err := tokens.TokenStops(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, s := range stops {
			v := "open " + stamp(s.StoppedAt)
			if s.LiftedAt != nil {
				v = "lifted " + stamp(*s.LiftedAt)
			}
			out[s.Selector+" "+s.Cause] = v
		}
		return out
	}
	before := state()
	if before[known+" operator"] != "lifted "+stamp(at.Add(2*time.Second)) || before[unknown+" operator"] != "open "+stamp(at.Add(time.Second)) {
		t.Fatalf("the stops: %v", before)
	}

	// A restore of Wappie's database from before both: the record brings
	// them back as they stood.
	execSQL(t, pool, `DELETE FROM contract_token_stops`)
	var out bytes.Buffer
	if err := replayTokenStops(ctx, tokens, record, &out); err != nil || !strings.Contains(out.String(), "2 stops and 1 lifts applied") {
		t.Fatalf("the replay: %v %q", err, out.String())
	}
	if after := state(); len(after) != 2 || after[known+" operator"] != before[known+" operator"] || after[unknown+" operator"] != before[unknown+" operator"] {
		t.Fatalf("after the replay %v, before the restore %v", after, before)
	}
	// What the database holds that is later than the record (a stop, and
	// a lift, made with no record) stands over its older lines: the stop is
	// neither rewound nor lifted by the record's older lift, and the lift is
	// not undone by the record's older stop.
	for _, r := range []tokenStopRecord{{Selector: known, At: at.Add(3 * time.Second)}, {Selector: unknown, At: at.Add(4 * time.Second), Lift: true}} {
		if err := changeTokenStop(ctx, tokens, r, "", "", &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	later := state()
	out.Reset()
	if err := replayTokenStops(ctx, tokens, record, &out); err != nil || !strings.Contains(out.String(), "0 stops and 0 lifts applied") ||
		!strings.Contains(out.String(), "3 lines left") {
		t.Fatalf("the replay over later changes: %v %q", err, out.String())
	}
	if after := state(); after[known+" operator"] != "open "+stamp(at.Add(3*time.Second)) || after[known+" operator"] != later[known+" operator"] ||
		after[unknown+" operator"] != "lifted "+stamp(at.Add(4*time.Second)) {
		t.Fatalf("after the replay over later changes %v, before it %v", after, later)
	}
	// A line that is no record refuses the replay before it changes
	// anything.
	if err := os.WriteFile(record, []byte(`{"selector":"`+known+`","at":"`+at.Format(time.RFC3339)+`"}`+"\nnot a record\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	execSQL(t, pool, `DELETE FROM contract_token_stops`)
	if err := replayTokenStops(ctx, tokens, record, &out); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("a bad record: %v", err)
	}
	if len(state()) != 0 {
		t.Fatalf("a refused replay changed the stops: %v", state())
	}

	out.Reset()
	if err := changeTokenStop(ctx, tokens, tokenStopRecord{Selector: known, At: at}, "", "", &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := listTokenStops(ctx, tokens, &out); err != nil || !strings.Contains(out.String(), known+" operator stopped ") ||
		!strings.HasSuffix(out.String(), "1 stops\n") {
		t.Fatalf("tokens list: %v %q", err, out.String())
	}
	// Never the token a selector maps to, in either spelling.
	if list := out.String(); strings.Contains(list, knownID.String()) || strings.Contains(list, strings.ReplaceAll(knownID.String(), "-", "")) {
		t.Fatalf("tokens list names the token behind a selector: %q", list)
	}
	if err := tokensCommand([]string{"suspend", "-replay", record, known}, strings.NewReader(""), &out); err == nil {
		t.Fatal("tokens suspend -replay with a selector ran")
	}
	if err := tokensCommand([]string{"suspend"}, strings.NewReader(""), &out); err == nil || !strings.Contains(err.Error(), "give one token's selector") {
		t.Fatalf("tokens suspend with nothing: %v", err)
	}
}

// The stop record keeps a line 365 days, as retention keeps a stop of a
// selector Wappie never held: each append drops the older lines, keeping
// the others in their order, a line that is no record as it is, and the
// file's mode, the file replaced whole; two appends at once lose no line.
// A replay leaves a line over 365 days old, whose stop retention let go.
func TestTokenStopRecordKeepsAYear(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	record := filepath.Join(dir, "token-stops.jsonl")
	const a, b = "0123456789abcdef", "fedcba9876543210"
	line := func(sel string, at time.Time, lift bool) string {
		js, err := json.Marshal(tokenStopRecord{Selector: sel, At: at, Lift: lift})
		if err != nil {
			t.Fatal(err)
		}
		return string(js)
	}
	lines := []string{
		line(a, now.Add(-400*24*time.Hour), false),
		"not a record",
		line(b, now.Add(-364*24*time.Hour), false),
		line(a, now.Add(-366*24*time.Hour), true),
		line(b, now.Add(-time.Hour), true),
	}
	if err := os.WriteFile(record, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(record, 0o640); err != nil {
		t.Fatal(err)
	}
	added := tokenStopRecord{Selector: a, At: now}
	if err := appendTokenStop(context.Background(), record, added, now); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(added)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join([]string{lines[1], lines[2], lines[4], string(js)}, "\n") + "\n"; string(got) != want {
		t.Fatalf("the record after an append:\n%s\nwant:\n%s", got, want)
	}
	if fi, err := os.Stat(record); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("the record's mode after an append: %v %v, want 0640", fi.Mode().Perm(), err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("the record's directory after an append: %v %v", entries, err)
	}

	// Two appends at once, 20 each: none lost.
	var wg sync.WaitGroup
	for _, sel := range []string{a, b} {
		wg.Go(func() {
			for i := range 20 {
				if err := appendTokenStop(context.Background(), record, tokenStopRecord{Selector: sel, At: now.Add(time.Duration(i) * time.Second)}, now); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	got, err = os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(got), "\n"); n != 4+40 {
		t.Fatalf("after 40 appends at once the record has %d lines, want %d", n, 4+40)
	}

	// A replay leaves the line over 365 days old. A line an older binary
	// wrote with its note applies, with no note.
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	old := filepath.Join(dir, "old.jsonl")
	older := `{"selector":"` + b + `","at":"` + now.Add(-364*24*time.Hour).Format(time.RFC3339Nano) + `","note":"from an older binary"}`
	if err := os.WriteFile(old, []byte(line(a, now.Add(-366*24*time.Hour), false)+"\n"+older+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := replayTokenStops(ctx, store.NewTokens(pool), old, &out); err != nil ||
		!strings.Contains(out.String(), "1 stops and 0 lifts applied") || !strings.Contains(out.String(), "1 lines over 365 days old left") {
		t.Fatalf("the replay: %v %q", err, out.String())
	}
	var stops []string
	rows, err := pool.Query(ctx, `SELECT selector FROM contract_token_stops`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		stops = append(stops, s)
	}
	if rows.Err() != nil || len(stops) != 1 || stops[0] != b {
		t.Fatalf("the stops after the replay: %v %v, want only %s", stops, rows.Err(), b)
	}
	var note string
	if err := pool.QueryRow(ctx, `SELECT note FROM contract_token_stops WHERE selector = $1`, b).Scan(&note); err != nil || note != "" {
		t.Fatalf("the replayed stop's note: %q %v", note, err)
	}
}

// A temporary copy of the record that an append killed before its rename
// left (its lines past the year the record keeps them) goes with the next
// append; another record's stays.
func TestTokenStopRecordLeavesNoTemporaryCopy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	record := filepath.Join(dir, "token-stops.jsonl")
	left, other := filepath.Join(dir, ".token-stops.jsonl.tmp-123456"), filepath.Join(dir, ".other.jsonl.tmp-1")
	for _, p := range []string{left, other} {
		if err := os.WriteFile(p, []byte(`{"selector":"0123456789abcdef","at":"2020-01-01T00:00:00Z"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := appendTokenStop(context.Background(), record, tokenStopRecord{Selector: "fedcba9876543210", At: now}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the temporary copy a killed append left: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("another record's temporary copy: %v", err)
	}
	if b, err := os.ReadFile(record); err != nil || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("the record: %q %v", b, err)
	}
}

// tokens suspend and lift append to the stop record WS_TOKEN_STOP_RECORD
// names, the only record they write: -record is no flag of theirs, and is
// refused before anything changes. A line holds the selector, its time and
// whether it was a lift, never the note, which the database alone keeps.
// With the setting blank, the stop is made all the same, no file is
// written, and the command says a restore would lose it.
func TestTokensSuspendWritesTheConfiguredRecord(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	dir := t.TempDir()
	configured, other := filepath.Join(dir, "token-stops.jsonl"), filepath.Join(dir, "other.jsonl")
	commandEnv(t, pool, filepath.Join(dir, "deletion-ledger.jsonl"))
	t.Setenv("WS_TOKEN_STOP_RECORD", configured)
	var usage bytes.Buffer
	flagOutput := tokensFlagOutput
	tokensFlagOutput = &usage
	t.Cleanup(func() { tokensFlagOutput = flagOutput })
	const sel, unrecorded = "0123456789abcdef", "fedcba9876543210"
	run := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := tokensCommand(args, strings.NewReader(""), &out); err != nil {
			t.Fatalf("tokens %s: %v", strings.Join(args, " "), err)
		}
		return out.String()
	}
	read := func(path string) []string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}
	if out := run("suspend", "-note", "leaked in a log", sel); !strings.Contains(out, "recorded in "+configured) {
		t.Fatalf("tokens suspend: %q", out)
	}
	var note string
	if err := pool.QueryRow(ctx, `SELECT note FROM contract_token_stops WHERE selector = $1`, sel).Scan(&note); err != nil || note != "leaked in a log" {
		t.Fatalf("the stop's note in the database: %q %v", note, err)
	}
	open := func(sel string) bool {
		t.Helper()
		var open bool
		if err := pool.QueryRow(ctx, `SELECT lifted_at IS NULL FROM contract_token_stops WHERE selector = $1`, sel).Scan(&open); err != nil {
			t.Fatal(err)
		}
		return open
	}
	for _, args := range [][]string{{"lift", "-record", other, sel}, {"lift", "-record", configured, sel}, {"suspend", "-record", configured, sel}} {
		var out bytes.Buffer
		if err := tokensCommand(args, strings.NewReader(""), &out); err == nil || !strings.Contains(err.Error(), "flag provided but not defined: -record") ||
			out.Len() != 0 || !open(sel) || len(read(configured)) != 1 {
			t.Fatalf("tokens %s: %v %q, the stop open %v, the record %q", strings.Join(args, " "), err, out.String(), open(sel), read(configured))
		}
	}
	if _, err := os.Stat(other); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused -record wrote its file: %v", err)
	}
	if out := run("suspend", sel); !strings.Contains(out, "recorded in "+configured) {
		t.Fatalf("tokens suspend again: %q", out)
	}
	if out := run("lift", sel); !strings.Contains(out, "recorded in "+configured) {
		t.Fatalf("tokens lift: %q", out)
	}
	written := read(configured)
	if len(written) != 3 || strings.Contains(written[1], "lift") || !strings.Contains(written[2], `"lift":true`) {
		t.Fatalf("the configured record %q: want two stops and a lift", written)
	}
	for _, l := range written {
		var keys map[string]any
		if err := json.Unmarshal([]byte(l), &keys); err != nil {
			t.Fatal(err)
		}
		delete(keys, "lift")
		if len(keys) != 2 || keys["selector"] != sel || keys["at"] == nil {
			t.Fatalf("a line holds more than the selector, its time and whether it was a lift: %s", l)
		}
	}

	names := func() []string {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}
	before := names()
	t.Setenv("WS_TOKEN_STOP_RECORD", " ")
	said := run("suspend", unrecorded)
	if !strings.Contains(said, "selector "+unrecorded+" is stopped here") ||
		!strings.Contains(said, "no stop record (WS_TOKEN_STOP_RECORD is empty), so a restore of Wappie's database would lose it") {
		t.Fatalf("tokens suspend with no record: %q", said)
	}
	if !open(unrecorded) {
		t.Fatal("the stop made with no record is not open")
	}
	if after := names(); !slices.Equal(after, before) {
		t.Fatalf("a stop with no record wrote a file: %v, before %v", after, before)
	}
}

// The command takes a stop's time to the microsecond, Postgres' own, so a
// line's time is its stop's stopped_at, or its lift's lifted_at, exactly.
func TestTokenStopLineIsTheDatabasesTime(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tokens := store.NewTokens(pool)
	record := filepath.Join(t.TempDir(), "token-stops.jsonl")
	const sel = "0123456789abcdef"
	at := time.Now().Truncate(time.Second).Add(-time.Minute + 123456789*time.Nanosecond)
	for _, r := range []tokenStopRecord{{Selector: sel, At: at}, {Selector: sel, At: at.Add(time.Second), Lift: true}} {
		if err := changeTokenStop(ctx, tokens, r, "", record, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	var stopped, lifted time.Time
	if err := pool.QueryRow(ctx, `SELECT stopped_at, lifted_at FROM contract_token_stops WHERE selector = $1`, sel).Scan(&stopped, &lifted); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("the record: %q", lines)
	}
	for i, want := range []time.Time{stopped, lifted} {
		var r tokenStopRecord
		if err := json.Unmarshal([]byte(lines[i]), &r); err != nil {
			t.Fatal(err)
		}
		if !r.At.Equal(want) || r.At.Nanosecond()%1000 != 0 {
			t.Errorf("line %d's time %s, the database's %s", i+1, r.At.Format(time.RFC3339Nano), want.UTC().Format(time.RFC3339Nano))
		}
	}
}

// stopLine is a stop record's line.
func stopLine(t *testing.T, sel string, at time.Time, lift bool) string {
	t.Helper()
	js, err := json.Marshal(tokenStopRecord{Selector: sel, At: at, Lift: lift})
	if err != nil {
		t.Fatal(err)
	}
	return string(js)
}

// The hourly trim drops the lines 365 days old, by the comparison a replay
// uses to leave one (store.TokenStopLapsed), and nothing else: a line
// younger by a microsecond stays, whatever became of its stop. It keeps a
// line that is no stop's record, counted, in their order, each record
// written again with nothing a line must not hold. It keeps the file's
// mode and owner, removes a temporary copy a killed rewrite left, never
// makes a missing record, and leaves alone one it would not change.
func TestTokenStopRecordTrim(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	const day = 24 * time.Hour
	const year = 365 * day
	if !store.TokenStopLapsed(now.Add(-year), now) || store.TokenStopLapsed(now.Add(-year+time.Microsecond), now) {
		t.Fatal("a replay leaves a line other than those 365 days old")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "token-stops.jsonl")
	const a, b, c = "0000000000000001", "0000000000000002", "0000000000000003"
	lines := []string{
		stopLine(t, a, now.Add(-366*day), false),
		"not a record",
		"",
		stopLine(t, a, now.Add(-year), false),
		stopLine(t, a, now.Add(-year+time.Microsecond), true),
		stopLine(t, b, now.Add(-10*day), false),
		stopLine(t, b, now.Add(-9*day), true),
		stopLine(t, c, now.Add(-364*day), false),
		`{"selector":"` + c + `","at":"` + now.Add(-time.Minute).Format(time.RFC3339Nano) + `","note":"from an older binary"}`,
	}
	if err := os.WriteFile(record, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(record, 0o640); err != nil {
		t.Fatal(err)
	}
	stale, others := filepath.Join(dir, ".token-stops.jsonl.tmp-123456"), filepath.Join(dir, ".other.jsonl.tmp-1")
	for _, p := range []string{stale, others} {
		if err := os.WriteFile(p, []byte(lines[0]+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	owner := func() [2]uint32 {
		t.Helper()
		fi, err := os.Stat(record)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		return [2]uint32{st.Uid, st.Gid}
	}
	was := owner()
	if did, err := trimTokenStops(ctx, record, now); err != nil || did.dropped != 2 || did.unreadable != 1 {
		t.Fatalf("the trim: %+v, %v; want 2 lines dropped and 1 kept unread", did, err)
	}
	got, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{lines[1], lines[2], lines[4], lines[5], lines[6], lines[7], stopLine(t, c, now.Add(-time.Minute), false)}, "\n") + "\n"
	if string(got) != want {
		t.Fatalf("the record after the trim:\n%s\nwant:\n%s", got, want)
	}
	if fi, err := os.Stat(record); err != nil || fi.Mode().Perm() != 0o640 || owner() != was {
		t.Fatalf("the record's mode after the trim: %v %v, owner %v; want 0640 and %v", fi.Mode().Perm(), err, owner(), was)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the temporary copy a killed rewrite left: %v", err)
	}
	if _, err := os.Stat(others); err != nil {
		t.Fatalf("another record's temporary copy: %v", err)
	}

	// Nothing more to drop: the file is not written.
	held, err := os.Stat(record)
	if err != nil {
		t.Fatal(err)
	}
	if did, err := trimTokenStops(ctx, record, now); err != nil || did.dropped != 0 || did.unreadable != 1 {
		t.Fatalf("a second trim: %+v, %v", did, err)
	}
	if fi, err := os.Stat(record); err != nil || !os.SameFile(held, fi) {
		t.Fatalf("a trim with nothing to drop replaced the record: %v", err)
	}
	// A missing record stays missing.
	missing := filepath.Join(dir, "missing.jsonl")
	if did, err := trimTokenStops(ctx, missing, now); err != nil || did != (stopRecordRewrite{}) {
		t.Fatalf("the trim of a missing record: %+v, %v", did, err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the trim made a missing record: %v", err)
	}
}

// Appends and trims at once lose no line: each rewrite holds the record's
// lock, and one that waited locks the file another renamed in. Every
// rewrite here replaces the file: one append adds lines 365 days old,
// which the trims drop, beside another's lines, which stay.
func TestTokenStopRecordAppendBesideTrim(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	record := filepath.Join(t.TempDir(), "token-stops.jsonl")
	const lapsed, kept = "0000000000000001", "0000000000000002"
	const year = 365 * 24 * time.Hour
	var initial []string
	for i := range 20 {
		initial = append(initial, stopLine(t, lapsed, now.Add(-year-time.Duration(i+1)*time.Hour), false))
	}
	if err := os.WriteFile(record, []byte(strings.Join(initial, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var want []string
	for i := range 20 {
		want = append(want, stopLine(t, kept, now.Add(time.Duration(i)*time.Second), false))
	}
	var wg sync.WaitGroup
	for sel, at := range map[string]func(int) time.Time{
		kept:   func(i int) time.Time { return now.Add(time.Duration(i) * time.Second) },
		lapsed: func(i int) time.Time { return now.Add(-year - time.Duration(i)*time.Second) },
	} {
		wg.Go(func() {
			for i := range 20 {
				if err := appendTokenStop(ctx, record, tokenStopRecord{Selector: sel, At: at(i)}, now); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Go(func() {
		for range 20 {
			if _, err := trimTokenStops(ctx, record, now); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	if _, err := trimTokenStops(ctx, record, now); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != strings.Join(want, "\n")+"\n" {
		t.Fatalf("after 40 appends beside 20 trims the record is:\n%s\nwant every line under 365 days old, in order", got)
	}
}

// The hourly pass trims the configured stop record after retention, by
// age only: a line 365 days old goes, and the lines of a stop retention
// just deleted, its lift's too, stay to their 365 days, as a standing
// stop's do. Its INFO line counts, and no line names a selector. The trim
// runs when retention fails, and retention when the trim fails. A line
// that is no stop's record stays, an ERROR that counts it and never says
// it; a record the pass cannot rewrite is an ERROR.
func TestRetentionTrimsTheStopRecord(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tokens := store.NewTokens(pool)
	dir := t.TempDir()
	record := filepath.Join(dir, "token-stops.jsonl")
	log := &recorder{}
	a := &app{log: slog.New(log), pools: &pg.Pools{API: pool}, cfg: config.Config{TokenStopRecord: record}}
	const gone, live, old, due = "0123456789abcdef", "fedcba9876543210", "00000000000000aa", "00000000000000bb"
	now := time.Now().UTC()
	const day = 24 * time.Hour
	for _, r := range []tokenStopRecord{{Selector: gone, At: now.Add(-10 * day)}, {Selector: gone, At: now.Add(-9 * day), Lift: true},
		{Selector: live, At: now.Add(-10 * day)}} {
		if err := changeTokenStop(ctx, tokens, r, "", record, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() []string {
		t.Helper()
		b, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}
	written := read()
	appendLine := func(line string) {
		t.Helper()
		f, err := os.OpenFile(record, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	appendLine(stopLine(t, old, now.Add(-366*day), false))
	// A valid record of gone's selector came, created 365 days ago: its
	// stop is due.
	execSQL(t, pool, `UPDATE contract_token_stops SET record_until = clock_timestamp() - interval '1 minute' WHERE selector = $1`, gone)
	stopped := func(sel string) bool {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_token_stops WHERE selector = $1`, sel).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}

	// Retention fails (the pass's context is gone): the trim runs all the
	// same, and the old line goes.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	a.retainTokens(cancelled, now)
	if len(log.find(slog.LevelWarn, "token retention failed")) != 1 || !stopped(gone) {
		t.Fatalf("a failed retention: its stop there %v, the logs %+v", stopped(gone), log.lines)
	}
	if got := read(); !slices.Equal(got, written) {
		t.Fatalf("the record after a failed retention: %q, want %q", got, written)
	}
	trimmed := log.find(slog.LevelInfo, "token stop record trimmed")
	if len(trimmed) != 1 || trimmed[0].attrs["lines"] != "1" || trimmed[0].attrs["path"] != record {
		t.Fatalf("the trim beside a failed retention: %+v", trimmed)
	}

	// Retention deletes gone's stop; its lines stay to their 365 days.
	a.retainTokens(ctx, now)
	if stopped(gone) || !stopped(live) {
		t.Fatalf("retention: gone's stop there %v, live's %v", stopped(gone), stopped(live))
	}
	if got := read(); !slices.Equal(got, written) {
		t.Fatalf("the record after retention deleted a stop: %q, want every line still, %q", got, written)
	}
	if trimmed := log.find(slog.LevelInfo, "token stop record trimmed"); len(trimmed) != 1 {
		t.Fatalf("a trim with nothing to drop: %+v", trimmed)
	}

	// A line that is no stop's record, which -replay would refuse.
	const unread = `{"selector":"` + live + `","note":"a secret"}`
	appendLine(unread)
	a.retainTokens(ctx, now)
	if bad := log.find(slog.LevelError, "token stop record has unreadable lines"); len(bad) != 1 || bad[0].attrs["lines"] != "1" || bad[0].attrs["path"] != record {
		t.Fatalf("a line that is no stop's record: %+v", log.lines)
	}
	if got := read(); !slices.Equal(got, append(slices.Clone(written), unread)) {
		t.Fatalf("the record with a line that is no stop's record: %q", got)
	}

	// A record the pass cannot rewrite (a directory): an ERROR, and a stop
	// due goes all the same.
	if _, err := tokens.StopToken(ctx, due, "root", "", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	execSQL(t, pool, `UPDATE contract_token_stops SET record_until = clock_timestamp() - interval '1 minute' WHERE selector = $1`, due)
	a.cfg.TokenStopRecord = dir
	a.retainTokens(ctx, now)
	if bad := log.find(slog.LevelError, "token stop record trim failed"); len(bad) != 1 || bad[0].attrs["path"] != dir || bad[0].attrs["error"] == "" {
		t.Fatalf("a record the pass cannot rewrite: %+v", bad)
	}
	if stopped(due) || !stopped(live) {
		t.Fatalf("beside a failed trim: the due stop there %v, the standing one %v", stopped(due), stopped(live))
	}
	for _, l := range log.lines {
		for _, v := range append([]string{l.msg}, slices.Collect(maps.Values(l.attrs))...) {
			for _, sel := range []string{gone, live, old, due, "a secret"} {
				if strings.Contains(v, sel) {
					t.Errorf("a log line names a selector: %+v", l)
				}
			}
		}
	}
}

// The record holds what the commands did, at the times the database
// holds, so a replay after a restore brings the stops back as they stood,
// whatever was run. A lift of a stop lifted already appends that lift
// again at its own time (so a lift whose append failed can be recorded by
// running it again); a lift with nothing to lift (no stop, or only
// Wappie's own) appends nothing, as no lift happened. Commands that
// reached the database out of their times' order (two at once, or a clock
// stepped back) never move a stop's times back: a suspend timed before the
// stop or its lift, a lift timed before its stop.
func TestTheRecordReplaysWhatTheCommandsDid(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tokens := store.NewTokens(pool)
	record := filepath.Join(t.TempDir(), "token-stops.jsonl")
	const twice, never, failing, raced, reopened, early = "0000000000000001", "0000000000000002", "0000000000000003", "0000000000000004",
		"0000000000000005", "0000000000000006"
	const day, ms = 24 * time.Hour, time.Millisecond
	base := time.Now().UTC().Truncate(time.Microsecond).Add(-10 * day)
	change := func(r tokenStopRecord) string {
		t.Helper()
		var out bytes.Buffer
		if err := changeTokenStop(ctx, tokens, r, "", record, &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	read := func() []tokenStopRecord {
		t.Helper()
		b, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		var lines []tokenStopRecord
		for l := range strings.Lines(string(b)) {
			var r tokenStopRecord
			if err := json.Unmarshal([]byte(l), &r); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, r)
		}
		return lines
	}

	change(tokenStopRecord{Selector: twice, At: base})
	change(tokenStopRecord{Selector: twice, At: base.Add(day), Lift: true})
	if out := change(tokenStopRecord{Selector: twice, At: base.Add(2 * day), Lift: true}); !strings.Contains(out, "lifted already; nothing changed") ||
		!strings.Contains(out, "recorded in") {
		t.Fatalf("a second lift: %q", out)
	}
	if lines := read(); len(lines) != 3 || lines[2].Selector != twice || !lines[2].At.Equal(base.Add(day)) || !lines[2].Lift {
		t.Fatalf("a second lift's line: %+v, want the first lift's again", lines)
	}
	execSQL(t, pool, `INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'apply_failed', $2, 'wappie')`, failing, base)
	for _, sel := range []string{never, failing} {
		if out := change(tokenStopRecord{Selector: sel, At: base.Add(2 * day), Lift: true}); !strings.Contains(out, "nothing changed or recorded") ||
			strings.Contains(out, "recorded in") {
			t.Fatalf("a lift with nothing to lift: %q", out)
		}
	}
	if lines := read(); len(lines) != 3 {
		t.Fatalf("a lift with nothing to lift wrote a line: %+v", lines)
	}
	// Two suspends, the later timed first; a suspend timed before the lift
	// it follows; a lift timed before its stop.
	change(tokenStopRecord{Selector: raced, At: base.Add(ms)})
	change(tokenStopRecord{Selector: raced, At: base})
	change(tokenStopRecord{Selector: reopened, At: base.Add(-time.Hour)})
	change(tokenStopRecord{Selector: reopened, At: base.Add(ms), Lift: true})
	change(tokenStopRecord{Selector: reopened, At: base})
	change(tokenStopRecord{Selector: early, At: base.Add(ms)})
	change(tokenStopRecord{Selector: early, At: base, Lift: true})
	if lines := read(); len(lines) != 10 || !lines[4].At.Equal(base.Add(ms)) || !lines[7].At.Equal(base.Add(ms)) || !lines[9].At.Equal(base.Add(ms)) {
		t.Fatalf("the lines of commands out of their times' order: %+v", lines)
	}

	// A restore of a snapshot taken before them all: the replay brings
	// every operator's stop back as it stood.
	stops := func() map[string]string {
		t.Helper()
		list, err := tokens.TokenStops(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, s := range list {
			v := "stopped " + s.StoppedAt.UTC().Format(time.RFC3339Nano)
			if s.LiftedAt != nil {
				v += " lifted " + s.LiftedAt.UTC().Format(time.RFC3339Nano)
			}
			out[s.Selector+" "+s.Cause] = v
		}
		return out
	}
	before := stops()
	execSQL(t, pool, `DELETE FROM contract_token_stops WHERE cause = 'operator'`)
	var out bytes.Buffer
	if err := replayTokenStops(ctx, tokens, record, &out); err != nil {
		t.Fatalf("the replay: %v", err)
	}
	if after := stops(); len(after) != 5 || !maps.Equal(after, before) {
		t.Fatalf("after the replay %v, before the restore %v", after, before)
	}
}

// The hourly pass, maintainOnce, trims the stop record after the token
// part's retention, by age only: a line 365 days old goes, and the lines
// of a stop retention deleted stay, as a standing stop's do.
func TestMaintainOnceTrimsTheStopRecord(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tokens := store.NewTokens(pool)
	record := filepath.Join(t.TempDir(), "token-stops.jsonl")
	const gone, live, old = "0123456789abcdef", "fedcba9876543210", "00000000000000aa"
	const day = 24 * time.Hour
	now := time.Now().UTC()
	for _, r := range []tokenStopRecord{{Selector: gone, At: now.Add(-10 * day)}, {Selector: gone, At: now.Add(-9 * day), Lift: true},
		{Selector: live, At: now.Add(-10 * day)}} {
		if err := changeTokenStop(ctx, tokens, r, "", record, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	written, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte(stopLine(t, old, now.Add(-366*day), false)+"\n"+string(written)), 0o600); err != nil {
		t.Fatal(err)
	}
	execSQL(t, pool, `UPDATE contract_token_stops SET record_until = $2 WHERE selector = $1`, gone, now.Add(-time.Hour))

	logged := &warnings{}
	a := &app{cfg: config.Config{TokenStopRecord: record}, log: slog.New(logged),
		pools: &pg.Pools{Live: pool, History: pool, API: pool}, storage: store.NewStorage(pool)}
	a.maintainOnce(ctx, 30*24*time.Hour, &fakeObjects{})
	if len(logged.lines) != 0 {
		t.Fatalf("the pass warned: %q", logged.lines)
	}
	var stops []string
	rows, err := pool.Query(ctx, `SELECT selector FROM contract_token_stops`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		stops = append(stops, s)
	}
	if rows.Err() != nil || !slices.Equal(stops, []string{live}) {
		t.Fatalf("the stops after the pass: %v %v, want %s's alone", stops, rows.Err(), live)
	}
	if b, err := os.ReadFile(record); err != nil || string(b) != string(written) {
		t.Fatalf("the record after the pass: %q %v, want every line but the old one, %q", b, err, written)
	}
}

// A rewrite of the record waits for its lock only until its context ends,
// so the hourly pass never hangs on a command stopped while it holds it.
func TestTokenStopRecordWaitsForItsLockNoLonger(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	record := filepath.Join(t.TempDir(), "token-stops.jsonl")
	if err := os.WriteFile(record, []byte(stopLine(t, "0123456789abcdef", now.Add(-366*24*time.Hour), false)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(record)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close() //nolint:errcheck // only locked
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	for name, rewrite := range map[string]func(context.Context) error{
		"an append": func(ctx context.Context) error {
			return appendTokenStop(ctx, record, tokenStopRecord{Selector: "fedcba9876543210", At: now}, now)
		},
		"a trim": func(ctx context.Context) error { _, err := trimTokenStops(ctx, record, now); return err },
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		done := make(chan error, 1)
		go func() { done <- rewrite(ctx) }()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("%s with the record locked: %v", name, err)
			}
		case <-time.After(10 * time.Second):
			_ = held.Close() //nolint:errcheck // releases the lock, so the rewrite ends
			<-done
			t.Fatalf("%s waited for the record's lock past its context", name)
		}
		cancel()
	}
	if b, err := os.ReadFile(record); err != nil || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("the record after rewrites that could not lock it: %q %v", b, err)
	}
}

// A trim whose lock is held past its bound (tokenStopTrimWait), by a
// command stopped while it held it, holds up the pass no longer than that
// and changes nothing; retention ran all the same, and the next pass
// trims.
func TestATrimThatFailedIsTriedAgain(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tokens := store.NewTokens(pool)
	record := filepath.Join(t.TempDir(), "token-stops.jsonl")
	log := &recorder{}
	a := &app{log: slog.New(log), pools: &pg.Pools{API: pool}, cfg: config.Config{TokenStopRecord: record}}
	const gone, live, old = "0123456789abcdef", "fedcba9876543210", "00000000000000aa"
	now := time.Now().UTC()
	for _, r := range []tokenStopRecord{{Selector: gone, At: now.Add(-10 * 24 * time.Hour)}, {Selector: live, At: now.Add(-time.Hour)}} {
		if err := changeTokenStop(ctx, tokens, r, "", record, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	execSQL(t, pool, `UPDATE contract_token_stops SET record_until = $2 WHERE selector = $1`, gone, now.Add(-time.Hour))
	read := func() string {
		t.Helper()
		b, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	kept := read()
	written := stopLine(t, old, now.Add(-366*24*time.Hour), false) + "\n" + kept
	if err := os.WriteFile(record, []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}

	held, err := os.Open(record)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close() //nolint:errcheck // only locked
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	wait := tokenStopTrimWait
	tokenStopTrimWait = 200 * time.Millisecond
	t.Cleanup(func() { tokenStopTrimWait = wait })
	done := make(chan struct{})
	go func() { a.retainTokens(ctx, now); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = held.Close() //nolint:errcheck // releases the lock, so the pass ends
		<-done
		t.Fatal("the pass waited for the record's lock past the trim's bound")
	}
	if bad := log.find(slog.LevelError, "token stop record trim failed"); len(bad) != 1 || !strings.Contains(bad[0].attrs["error"], "deadline exceeded") {
		t.Fatalf("a trim that could not lock the record: %+v", log.lines)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_token_stops WHERE selector = $1`, gone).Scan(&left); err != nil || left != 0 {
		t.Fatalf("retention left %d stops of %s, %v", left, gone, err)
	}
	if got := read(); got != written {
		t.Fatalf("a failed trim changed the record: %q", got)
	}

	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	a.retainTokens(ctx, now)
	if got := read(); got != kept {
		t.Fatalf("the next pass's trim: %q, want every line but the old one, %q", got, kept)
	}
	if trimmed := log.find(slog.LevelInfo, "token stop record trimmed"); len(trimmed) != 1 || trimmed[0].attrs["lines"] != "1" {
		t.Fatalf("the next pass's trim: %+v", trimmed)
	}
}

// In prod, serve says once, right after the deletion ledger's line and
// before "starting", whether it can write the stop record, creating it
// 0600 when it is missing, and starts either way: none configured, a file
// it cannot make, and one in a directory where no rewrite can make its
// temporary file are ERRORs. A dev server says nothing.
func TestServeChecksTokenStopRecordBeforeStarting(t *testing.T) {
	dir := t.TempDir()
	prod := func(path string) config.Config { return config.Config{Env: config.EnvProd, TokenStopRecord: path} }
	log := &recorder{}
	lg := slog.New(log)
	checkTokenStopRecord(prod(filepath.Join(dir, "missing", "token-stops.jsonl")), lg)
	checkTokenStopRecord(prod(""), lg)
	if bad := log.find(slog.LevelError, "token stop record not writable"); len(bad) != 2 || !strings.Contains(bad[0].attrs["path"], "missing") ||
		bad[1].attrs["error"] != "WS_TOKEN_STOP_RECORD is empty" {
		t.Fatalf("an unwritable record, and none: %+v", log.lines)
	}
	path := filepath.Join(dir, "token-stops.jsonl")
	checkTokenStopRecord(prod(path), lg)
	if ok := log.find(slog.LevelInfo, "token stop record writable"); len(ok) != 1 || ok[0].attrs["path"] != path {
		t.Fatalf("a writable record: %+v", log.lines)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the created record: %v %v", info, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("the check left more than the record: %v %v", entries, err)
	}
	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked")
		if err := os.Mkdir(locked, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(locked, "token-stops.jsonl"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) //nolint:errcheck // the temporary directory's removal says
		checkTokenStopRecord(prod(filepath.Join(locked, "token-stops.jsonl")), lg)
		if bad := log.find(slog.LevelError, "token stop record not writable"); len(bad) != 3 || !strings.Contains(bad[2].attrs["path"], "locked") {
			t.Fatalf("a record in a directory the server cannot write: %+v", log.lines)
		}
	}
	quiet := &recorder{}
	checkTokenStopRecord(config.Config{Env: config.EnvDev, TokenStopRecord: filepath.Join(dir, "missing", "x")}, slog.New(quiet))
	if len(quiet.lines) != 0 {
		t.Fatalf("a dev server checked its stop record: %+v", quiet.lines)
	}

	// In serve, right after the ledger's check, before "starting".
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "serve" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := call.Fun.(type) {
			case *ast.Ident:
				if f.Name == "setup" || f.Name == "checkDeletionLedger" || f.Name == "checkTokenStopRecord" {
					order = append(order, f.Name)
				}
			case *ast.SelectorExpr:
				if f.Sel.Name != "Info" || len(call.Args) == 0 {
					return true
				}
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Value == strconv.Quote("starting") {
					order = append(order, "starting")
				}
			}
			return true
		})
	}
	if !slices.Equal(order, []string{"setup", "checkDeletionLedger", "checkTokenStopRecord", "starting"}) {
		t.Fatalf("serve's order: %v", order)
	}
}
