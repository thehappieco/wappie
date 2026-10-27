package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/migrate"
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
	out.Reset()
	if err := contractTokens(ctx, c, store.TokensOff, nil, nil, &out); err != nil || !strings.HasPrefix(out.String(), "contract tokens: on -> off\n") {
		t.Fatalf("tokens off: %v %q", err, out.String())
	}
	if err := contractTokensCommand([]string{"sideways"}, &out); !errors.As(err, new(usageError)) {
		t.Fatalf("contract tokens sideways: %v", err)
	}
	if err := contractTokensCommand([]string{"on", "now"}, &out); !errors.As(err, new(usageError)) {
		t.Fatalf("contract tokens on now: %v", err)
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
	execSQL(t, pool, `INSERT INTO contract_token_selectors (selector, token_id, tenant_id, hash, until)
		VALUES ($1, gen_random_uuid(), gen_random_uuid(), decode(repeat('ab', 32), 'hex'), clock_timestamp() + interval '1 day')`, known)

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
	said := func(r tokenStopRecord) string {
		t.Helper()
		var out bytes.Buffer
		if err := changeTokenStop(ctx, tokens, r, record, &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	at := time.Now().UTC().Truncate(time.Second)
	a := said(tokenStopRecord{Selector: known, At: at, Note: "leaked in a log"})
	b := said(tokenStopRecord{Selector: unknown, At: at.Add(time.Second)})
	if strings.ReplaceAll(a, known, "S") != strings.ReplaceAll(b, unknown, "S") {
		t.Fatalf("the words differ for a selector Wappie holds and one it does not:\n%s\n%s", a, b)
	}
	lifted := said(tokenStopRecord{Selector: known, At: at.Add(2 * time.Second), Lift: true})
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
	if err := changeTokenStop(ctx, tokens, tokenStopRecord{Selector: known, At: at}, "", &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := listTokenStops(ctx, tokens, &out); err != nil || !strings.Contains(out.String(), known+" operator stopped ") ||
		!strings.HasSuffix(out.String(), "1 stops\n") {
		t.Fatalf("tokens list: %v %q", err, out.String())
	}
	if err := tokensCommand([]string{"suspend", "-replay", record, known}, strings.NewReader(""), &out); err == nil {
		t.Fatal("tokens suspend -replay with a selector ran")
	}
	if err := tokensCommand([]string{"suspend"}, strings.NewReader(""), &out); err == nil || !strings.Contains(err.Error(), "give one token's selector") {
		t.Fatalf("tokens suspend with nothing: %v", err)
	}
}
