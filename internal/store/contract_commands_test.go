package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thehappieco/kit/vectors"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The command ledger (0052's contract_commands; the plan's 2.3 and 3.1 to
// 3.3): what a take stores of each item, the executor's order and its
// retries, a reset, a result's compare-and-set and delivery, and the 30
// days.

// ledgerWorld is a contract holding a generation, a recorded workspace and
// an actor, with the command feed's cursor.
type ledgerWorld struct {
	pool  *pgxpool.Pool
	c     *store.Contract
	gen   uuid.UUID
	ws    uuid.UUID
	actor uuid.UUID
	cseq  int64
}

func newLedgerWorld(t *testing.T) *ledgerWorld {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	l := &ledgerWorld{pool: pool, c: store.NewContract(pool), gen: uuid.New(), actor: uuid.New()}
	if _, err := pool.Exec(context.Background(), `UPDATE contract_state SET generation = $1, generation_confirmed = true`, l.gen); err != nil {
		t.Fatal(err)
	}
	l.ws = recordWorkspace(t, pool, "team")
	return l
}

// command is a rename of the workspace l.ws at wseq, decoded, with a body
// of its own.
func (l *ledgerWorld) command(ws uuid.UUID, wseq int64) store.ContractCommandTake {
	l.cseq++
	id := uuid.Must(uuid.NewV7())
	body := fmt.Sprintf(`{"v":1,"type":"command","app":"wappie","id":%q,"workspace_id":%q,"wseq":%d,"kind":"item.rename","mac":"v1=00"}`, id, ws, wseq)
	now := time.Now()
	w := ws
	return store.ContractCommandTake{ID: id, Cseq: l.cseq, Body: []byte(body), BodyKey: bodyKey(body),
		Decoded: &store.ContractCommandFields{Producer: store.ProducerWappie, Workspace: &w, WSeq: &wseq, Kind: "item.rename",
			Section: "numbers", Actor: l.actor, ActorRole: "owner", Target: json.RawMessage(`{"item":"` + uuid.NewString() + `"}`),
			Params: []byte(`{"before":{"label":"A"},"after":{"label":"B"}}`), BasedOnDocs: json.RawMessage(`{}`),
			IssuedAt: now, FirstIssuedAt: now}}
}

func bodyKey(body string) []byte {
	sum := sha256.Sum256([]byte(body))
	return sum[:]
}

// take commits a page of items from the cursor, as the follower does.
func (l *ledgerWorld) take(t *testing.T, items ...store.ContractCommandTake) store.ContractTakeResult {
	t.Helper()
	return l.takePage(t, store.ContractCommandPage{Items: items})
}

func (l *ledgerWorld) takePage(t *testing.T, p store.ContractCommandPage) store.ContractTakeResult {
	t.Helper()
	st, err := l.c.SettingsState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.SeenGeneration, p.After = l.gen, st.FeedCursor
	p.NextAfter = st.FeedCursor + int64(len(p.Items)+len(p.Unreadable))
	if p.SignedAt.IsZero() {
		p.SignedAt = time.Now()
	}
	res, err := l.c.TakeCommands(context.Background(), p)
	if err != nil {
		t.Fatalf("the take: %v", err)
	}
	if !res.Committed {
		t.Fatal("the take did not commit")
	}
	return res
}

// ledgerRow is a ledger row as a test reads it.
type ledgerRow struct {
	Exists                                    bool
	Outcome, Code, Delivery, RejectCode, Kind string
	StateSeq                                  *int64
	RetryAfter                                *int
	Generation                                uuid.UUID
	Again                                     bool
	RunTries                                  int
}

func (l *ledgerWorld) row(t *testing.T, id uuid.UUID) ledgerRow {
	t.Helper()
	var r ledgerRow
	err := l.pool.QueryRow(context.Background(), `SELECT coalesce(outcome, ''), coalesce(code, ''), coalesce(delivery, ''),
		coalesce(reject_code, ''), coalesce(kind, ''), state_seq, retry_after, generation, again, run_tries
		FROM contract_commands WHERE id = $1`, id).Scan(&r.Outcome, &r.Code, &r.Delivery, &r.RejectCode, &r.Kind, &r.StateSeq,
		&r.RetryAfter, &r.Generation, &r.Again, &r.RunTries)
	if err == nil {
		r.Exists = true
	}
	return r
}

// securityEvents counts the invalid-command security events, and fails if
// one names a person or holds a body.
func (l *ledgerWorld) securityEvents(t *testing.T) int {
	t.Helper()
	rows, err := l.pool.Query(context.Background(), `SELECT user_id IS NULL AND sub IS NULL, detail::text FROM security_events
		WHERE kind = 'contract_command_invalid'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var nobody bool
		var detail string
		if err := rows.Scan(&nobody, &detail); err != nil {
			t.Fatal(err)
		}
		if !nobody || strings.Contains(detail, "mac") && strings.Contains(detail, "v1=") || strings.Contains(detail, "item.rename") {
			t.Errorf("a security event names a person or holds a body: %v %s", nobody, detail)
		}
		n++
	}
	return n
}

func (l *ledgerWorld) finish(t *testing.T, id uuid.UUID, r store.CommandResult) {
	t.Helper()
	if err := l.c.RefuseCommand(context.Background(), id, r); err != nil {
		t.Fatal(err)
	}
}

func TestTakeCommands(t *testing.T) {
	ctx := context.Background()
	l := newLedgerWorld(t)

	// New rows to run, and each verdict decided before the take.
	run := l.command(l.ws, 1)
	expired := l.command(l.ws, 2)
	expired.Verdict, expired.Why = store.CommandExpired, "expired"
	forged := l.command(l.ws, 3)
	forged.Verdict, forged.Why, forged.Forged, forged.Decoded = store.CommandInvalid, "mac", true, nil
	res := l.take(t, run, expired, forged)
	if res.New != 1 || res.Refused != 2 || res.Invalid != 1 || res.Security != 1 {
		t.Fatalf("the first page: %+v", res)
	}
	if r := l.row(t, run.ID); r.Outcome != "" || r.Kind != "item.rename" || r.Generation != l.gen {
		t.Fatalf("a row to run: %+v", r)
	}
	if r := l.row(t, expired.ID); r.Outcome != store.CommandRefused || r.Code != store.CommandExpired || r.StateSeq != nil || r.Kind == "" {
		t.Fatalf("an expired row: %+v", r)
	}
	if r := l.row(t, forged.ID); r.Code != store.CommandInvalid || r.Kind != "" {
		t.Fatalf("a forged row keeps no decoded column: %+v", r)
	}
	st, err := l.c.SettingsState(ctx)
	if err != nil || st.FeedCursor != 3 || st.FirstReadAt == nil || st.ReadAt == nil || st.InvalidAt == nil {
		t.Fatalf("the settings after a page: %+v %v", st, err)
	}
	first := *st.FirstReadAt
	if err := l.c.CommandFeedFailed(ctx, "transport"); err != nil {
		t.Fatal(err)
	}

	// Replays: a row with no result stays open; one with a result is posted
	// again; a forged copy of an open row only logs; a copy whose MAC holds
	// with another body finishes an open row, and leaves a finished one's
	// result.
	if err := l.c.ResultsPosted(ctx, []store.ContractResultOutcome{{ID: expired.ID, Answer: store.DeliveryAccepted}}); err != nil {
		t.Fatal(err)
	}
	if r := l.row(t, expired.ID); r.Delivery != store.DeliveryAccepted {
		t.Fatalf("delivered: %+v", r)
	}
	forgedCopy := run
	forgedCopy.Body, forgedCopy.BodyKey, forgedCopy.Forged, forgedCopy.Verdict, forgedCopy.Why, forgedCopy.Decoded =
		[]byte(`{"x":1}`), bodyKey(`{"x":1}`), true, store.CommandInvalid, "other_app", nil
	other := l.command(l.ws, 9)
	other.ID = expired.ID
	res = l.take(t, run, expired, forgedCopy)
	if res.Replayed != 2 || res.OtherBody != 1 || res.Invalid != 0 {
		t.Fatalf("replays and a forged copy: %+v", res)
	}
	if r := l.row(t, run.ID); r.Outcome != "" {
		t.Fatalf("a forged copy finished an open row: %+v", r)
	}
	if r := l.row(t, expired.ID); r.Delivery != "" || r.Code != store.CommandExpired {
		t.Fatalf("a replay of a delivered result is not posted again: %+v", r)
	}
	otherOpen := run
	otherOpen.Body, otherOpen.BodyKey = []byte(`{"other":true}`), bodyKey(`{"other":true}`)
	res = l.take(t, otherOpen, other)
	if res.OtherBody != 2 || res.Invalid != 1 {
		t.Fatalf("copies with another body: %+v", res)
	}
	if r := l.row(t, run.ID); r.Outcome != store.CommandRefused || r.Code != store.CommandInvalid || r.StateSeq != nil {
		t.Fatalf("an open row with another body: %+v", r)
	}
	if r := l.row(t, expired.ID); r.Code != store.CommandExpired || r.Delivery != "" {
		t.Fatalf("a finished row with another body: %+v", r)
	}
	// A forged copy with the very body of a row taken touches nothing,
	// not even its delivery.
	if err := l.c.ResultsPosted(ctx, []store.ContractResultOutcome{{ID: expired.ID, Answer: store.DeliveryAccepted}}); err != nil {
		t.Fatal(err)
	}
	sameBody := expired
	sameBody.Forged, sameBody.Verdict, sameBody.Why, sameBody.Decoded = true, store.CommandInvalid, "mac", nil
	if res := l.take(t, sameBody); res.OtherBody != 1 || res.Replayed != 0 {
		t.Fatalf("a forged copy with the same body: %+v", res)
	}
	if r := l.row(t, expired.ID); r.Delivery != store.DeliveryAccepted {
		t.Fatalf("a forged copy posted a result again: %+v", r)
	}
	if n := l.securityEvents(t); n != 5 {
		t.Fatalf("%d security events, want 5", n)
	}

	// Step 7: a wseq the memory has passed, with another id, is refused; the
	// same id is a replay; again, it runs.
	a := l.command(l.ws, 20)
	l.take(t, a)
	l.finish(t, a.ID, store.CommandResult{Code: store.CommandKindNotAccepted})
	if r := l.row(t, a.ID); r.StateSeq == nil || *r.StateSeq != 1 {
		t.Fatalf("a refusal's judged seq: %+v", r)
	}
	lower, same := l.command(l.ws, 19), l.command(l.ws, 20)
	againLower := l.command(l.ws, 18)
	againLower.Again = true
	otherWS := recordWorkspace(t, l.pool, "team")
	elsewhere := l.command(otherWS, 1)
	res = l.take(t, lower, same, againLower, elsewhere, a)
	if res.New != 2 || res.Refused != 2 || res.Replayed != 1 {
		t.Fatalf("step 7: %+v", res)
	}
	for id, want := range map[uuid.UUID]string{lower.ID: store.CommandInvalid, same.ID: store.CommandInvalid, againLower.ID: "", elsewhere.ID: ""} {
		if r := l.row(t, id); r.Code != want {
			t.Errorf("step 7, %s: %+v, want %q", id, r, want)
		}
	}
	if r := l.row(t, againLower.ID); !r.Again {
		t.Fatal("a command delivered again is not marked so")
	}

	// The compare-and-set: a moved cursor or generation commits nothing.
	st, _ = l.c.SettingsState(ctx)
	if st.FirstReadAt == nil || !st.FirstReadAt.Equal(first) || st.FeedError != "" {
		t.Fatalf("first_read_at moved or the feed error stayed: %+v", st)
	}
	stale := l.command(l.ws, 30)
	for name, p := range map[string]store.ContractCommandPage{
		"a moved cursor":   {SeenGeneration: l.gen, After: st.FeedCursor - 1, NextAfter: st.FeedCursor, Items: []store.ContractCommandTake{stale}},
		"a moved gen":      {SeenGeneration: uuid.New(), After: st.FeedCursor, NextAfter: st.FeedCursor + 1, Items: []store.ContractCommandTake{stale}},
		"no page at all":   {SeenGeneration: l.gen, After: st.FeedCursor, NextAfter: st.FeedCursor - 1},
		"a page behind it": {SeenGeneration: l.gen, After: st.FeedCursor + 5, NextAfter: st.FeedCursor + 6},
	} {
		res, err := l.c.TakeCommands(ctx, p)
		if res.Committed || (err != nil && !errors.Is(err, store.ErrPageBehind)) {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	if r := l.row(t, stale.ID); r.Exists {
		t.Fatal("a refused page wrote a row")
	}

	// A command whose generation is not its page's: invalid_command, never
	// a reset.
	wrong := l.command(l.ws, 40)
	wrong.Verdict, wrong.Why, wrong.Decoded = store.CommandInvalid, "generation", nil
	l.take(t, wrong)
	if r := l.row(t, wrong.ID); r.Code != store.CommandInvalid {
		t.Fatalf("another generation's command: %+v", r)
	}
	var gen uuid.UUID
	if err := l.pool.QueryRow(ctx, `SELECT generation FROM contract_state`).Scan(&gen); err != nil || gen != l.gen {
		t.Fatalf("the generation after: %v %v", gen, err)
	}
}

// TestTakeNeverFailsAPage: no body breaks a take. Every command the kit's
// vectors hold as not valid, a body with a NUL member at the top and in
// params, and one that is not UTF-8 are each taken as a refused row with
// no decoded column (or, with no UUID id, as no row at all), and each page
// commits and moves the cursor.
func TestTakeNeverFailsAPage(t *testing.T) {
	ctx := context.Background()
	l := newLedgerWorld(t)
	raw, err := fs.ReadFile(vectors.FS, "platform/contract-v1/wire-commands.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Commands []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	type body struct {
		name string
		raw  []byte
	}
	var bodies []body
	for _, c := range file.Commands {
		if !c.Valid {
			bodies = append(bodies, body{c.Name, c.Value})
		}
	}
	if len(bodies) < 50 {
		t.Fatalf("only %d invalid commands in the kit's vectors", len(bodies))
	}
	nulID, utfID, paramsID := uuid.New(), uuid.New(), uuid.New()
	bodies = append(bodies,
		body{"a NUL member", []byte(`{"id":"` + nulID.String() + `","x":"a\u0000b"}`)},
		body{"a NUL in params", []byte(`{"id":"` + paramsID.String() + `","params":{"after":{"label":"\u0000"}}}`)},
		body{"not UTF-8", append([]byte(`{"id":"`+utfID.String()+`","label":"`), 0xff, 0xfe, '"', '}')},
		body{"no id at all", []byte(`{"kind":"item.rename"}`)},
		body{"an id that is no UUID", []byte(`{"id":"dev_123"}`)},
		body{"no object", []byte(`[1,2]`)},
	)
	rows, unread := 0, 0
	for _, b := range bodies {
		var generic struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(b.raw, &generic)
		l.cseq++
		p := store.ContractCommandPage{}
		_, err := uuid.Parse(generic.ID)
		// The kit's vectors share a few ids: each body here gets an id of
		// its own, so each is stored, not met as another body of one row.
		id := uuid.New()
		if b.name == "a NUL member" || b.name == "a NUL in params" || b.name == "not UTF-8" {
			id = uuid.MustParse(generic.ID)
		}
		if err != nil || len(generic.ID) != 36 {
			p.Unreadable = []store.ContractUnreadable{{Cseq: l.cseq, Why: "no_id", Forged: true}}
			unread++
		} else {
			p.Items = []store.ContractCommandTake{{ID: id, Cseq: l.cseq, Body: b.raw, BodyKey: bodyKey(string(b.raw)),
				Verdict: store.CommandInvalid, Why: "invalid", Forged: true}}
			rows++
		}
		before, _ := l.c.SettingsState(ctx)
		l.takePage(t, p)
		after, _ := l.c.SettingsState(ctx)
		if after.FeedCursor != before.FeedCursor+1 {
			t.Fatalf("%s: the cursor did not move", b.name)
		}
	}
	var n, decoded int
	if err := l.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE kind IS NOT NULL OR workspace_id IS NOT NULL
		OR actor IS NOT NULL OR target IS NOT NULL OR params IS NOT NULL OR issued_at IS NOT NULL)
		FROM contract_commands`).Scan(&n, &decoded); err != nil {
		t.Fatal(err)
	}
	if n != rows || decoded != 0 {
		t.Fatalf("%d rows for %d bodies with an id, %d with a decoded column", n, rows, decoded)
	}
	var stored []byte
	if err := l.pool.QueryRow(ctx, `SELECT body FROM contract_commands WHERE id = $1`, utfID).Scan(&stored); err != nil ||
		!strings.Contains(string(stored), "\xff\xfe") {
		t.Fatalf("the body that is not UTF-8, as stored: %q %v", stored, err)
	}
	if got := l.securityEvents(t); got != len(bodies) {
		t.Fatalf("%d security events for %d bodies (%d without an id)", got, len(bodies), unread)
	}
}

// The executor's order: take order across generations, one open row at a
// time per workspace and producer, a row retrying holds back only those;
// after CommandRunTries it is answered rate_limited.
func TestCommandOrder(t *testing.T) {
	ctx := context.Background()
	l := newLedgerWorld(t)
	l.cseq = 899
	old := l.command(l.ws, 7)
	l.take(t, old)
	newGen := uuid.New()
	st, _ := l.c.State(ctx)
	if ok, err := l.c.Restart(ctx, st.Generation, st.FeedCursor, &newGen, true); err != nil || !ok {
		t.Fatalf("the restart: %v %v", ok, err)
	}
	l.gen, l.cseq = newGen, 0
	first, second := l.command(l.ws, 1), l.command(l.ws, 2)
	otherWS := recordWorkspace(t, l.pool, "team")
	elsewhere := l.command(otherWS, 1)
	l.take(t, first, second, elsewhere)

	next := func(want uuid.UUID) {
		t.Helper()
		got, ok, err := l.c.NextCommand(ctx)
		if err != nil || !ok || got.ID != want {
			t.Fatalf("next: %v %v %v, want %v", got.ID, ok, err, want)
		}
	}
	next(old.ID)
	if got, _, _ := l.c.NextCommand(ctx); got.Cseq != 900 || got.Generation == newGen || got.Workspace == nil || *got.Workspace != l.ws ||
		string(got.Params) != `{"before":{"label":"A"},"after":{"label":"B"}}` {
		t.Fatalf("the old generation's row as read: %+v", got)
	}
	// It retries: the rows of its workspace wait, another's runs.
	for i := 1; i < store.CommandRunTries; i++ {
		tries, err := l.c.CommandRunFailed(ctx, old.ID, "store")
		if err != nil || tries != i {
			t.Fatalf("try %d: %d %v", i, tries, err)
		}
		next(elsewhere.ID)
		if _, err := l.pool.Exec(ctx, `UPDATE contract_commands SET run_after = clock_timestamp() WHERE id = $1`, old.ID); err != nil {
			t.Fatal(err)
		}
		next(old.ID)
	}
	tries, err := l.c.CommandRunFailed(ctx, old.ID, "store")
	if err != nil || tries != store.CommandRunTries {
		t.Fatalf("the last try: %d %v", tries, err)
	}
	if at, now, ok, err := l.c.NextCommandAt(ctx); err != nil || !ok || !at.After(now) || at.Sub(now) > store.CommandRunBackoffMax {
		t.Fatalf("the waiting row: %v %v %v %v", at, now, ok, err)
	}
	if st, err := l.c.SettingsStatus(ctx); err != nil || st.Retrying != 1 || st.RetryError != "store" || st.OldestRetrying == nil ||
		st.Open != 4 || st.OldestOpen == nil || st.StuckAt != nil {
		t.Fatalf("the status of a row retrying: %+v %v", st, err)
	}
	l.finish(t, old.ID, store.CommandResult{Code: store.CommandRateLimited, RetryAfter: store.CommandStuckRetryAfter})
	r := l.row(t, old.ID)
	if r.Code != store.CommandRateLimited || r.RetryAfter == nil || *r.RetryAfter != 60 || r.StateSeq == nil || r.RunTries != 5 ||
		r.Delivery != store.DeliveryDropped {
		t.Fatalf("a stuck row's answer: %+v", r)
	}
	if st, err := l.c.SettingsStatus(ctx); err != nil || st.StuckAt == nil || st.Retrying != 0 || len(st.Sections) != 2 ||
		!slices.ContainsFunc(st.Results, func(r store.ContractResultCount) bool { return r.Code == store.CommandRateLimited && r.N == 1 }) {
		t.Fatalf("the status of a stuck row: %+v %v", st, err)
	}
	if _, err := l.c.CommandRunFailed(ctx, old.ID, "store"); !errors.Is(err, store.ErrCommandFinished) {
		t.Fatalf("a try on a finished row: %v", err)
	}
	next(first.ID)
	l.finish(t, first.ID, store.CommandResult{Code: store.CommandKindNotAccepted})
	next(second.ID)
	if err := l.c.RefuseCommand(ctx, first.ID, store.CommandResult{Code: store.CommandKindNotAccepted}); !errors.Is(err, store.ErrCommandFinished) {
		t.Fatalf("a second result: %v", err)
	}
}

// A reset (a new generation, from either feed) clears the command feed in
// Restart's transaction: the cursor to 0, the wseq memory gone, the old
// generation's results not delivered dropped, every document due afresh.
// A result of the old generation that lands after it is dropped by the
// poster.
func TestCommandReset(t *testing.T) {
	ctx := context.Background()
	l := newLedgerWorld(t)
	sub := uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO contract_accounts (sub) VALUES ($1)`, sub); err != nil {
		t.Fatal(err)
	}
	done, undelivered, open := l.command(l.ws, 1), l.command(l.ws, 2), l.command(l.ws, 3)
	l.take(t, done, undelivered, open)
	l.finish(t, done.ID, store.CommandResult{Code: store.CommandKindNotAccepted})
	if err := l.c.ResultsPosted(ctx, []store.ContractResultOutcome{{ID: done.ID, Answer: store.DeliveryAccepted}}); err != nil {
		t.Fatal(err)
	}
	l.finish(t, undelivered.ID, store.CommandResult{Code: store.CommandKindNotAccepted})
	if _, err := l.pool.Exec(ctx, `UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour', tries = 3, parked_at = clock_timestamp();
		UPDATE contract_persons SET due_at = clock_timestamp() + interval '1 hour', tries = 2`); err != nil {
		t.Fatal(err)
	}
	newGen := uuid.New()
	if ok, err := l.c.RestartFromCommands(ctx, uuid.New(), &newGen); err != nil || ok {
		t.Fatalf("a reset from a generation not held: %v %v", ok, err)
	}
	if ok, err := l.c.RestartFromCommands(ctx, l.gen, &newGen); err != nil || !ok {
		t.Fatalf("the reset: %v %v", ok, err)
	}
	st, _ := l.c.SettingsState(ctx)
	var memory, due, persons int
	if err := l.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM contract_command_wseq),
		(SELECT count(*) FROM contract_sections WHERE due_at <= clock_timestamp() AND tries = 0 AND parked_at IS NULL),
		(SELECT count(*) FROM contract_persons WHERE due_at <= clock_timestamp() AND tries = 0)`).Scan(&memory, &due, &persons); err != nil {
		t.Fatal(err)
	}
	if st.FeedCursor != 0 || memory != 0 || due != 1 || persons != 1 {
		t.Fatalf("after the reset: cursor %d, %d memory rows, %d sections and %d persons due afresh", st.FeedCursor, memory, due, persons)
	}
	if r := l.row(t, done.ID); r.Delivery != store.DeliveryAccepted {
		t.Fatalf("a delivered result: %+v", r)
	}
	if r := l.row(t, undelivered.ID); r.Delivery != store.DeliveryDropped {
		t.Fatalf("an undelivered result of the old generation: %+v", r)
	}
	if r := l.row(t, open.ID); r.Outcome != "" || r.Delivery != "" {
		t.Fatalf("an open row: %+v", r)
	}
	// An act that read the old generation and committed after the reset.
	l.finish(t, open.ID, store.CommandResult{Code: store.CommandKindNotAccepted})
	if r := l.row(t, open.ID); r.Delivery != store.DeliveryDropped {
		t.Fatalf("a result of the old generation after the reset: %+v", r)
	}
	if _, err := l.pool.Exec(ctx, `UPDATE contract_commands SET delivery = NULL, delivered_at = NULL WHERE id = $1`, open.ID); err != nil {
		t.Fatal(err)
	}
	results, err := l.c.UndeliveredResults(ctx, 10)
	if err != nil || len(results) != 0 {
		t.Fatalf("the poster found %+v %v", results, err)
	}
	if r := l.row(t, open.ID); r.Delivery != store.DeliveryDropped {
		t.Fatalf("the poster left an old generation's result: %+v", r)
	}

	// A restart from the account side resets the command feed too.
	l.gen = newGen
	l.take(t, l.command(l.ws, 1))
	st2, _ := l.c.State(ctx)
	third := uuid.New()
	if ok, err := l.c.Restart(ctx, st2.Generation, st2.FeedCursor, &third, true); err != nil || !ok {
		t.Fatal(err)
	}
	if st, _ := l.c.SettingsState(ctx); st.FeedCursor != 0 {
		t.Fatalf("the account side's restart left the command cursor at %d", st.FeedCursor)
	}
}

// The results: read oldest first, settled by the platform's answers,
// parked by a rejection or by Wappie's own check, a failed post counted.
func TestCommandResults(t *testing.T) {
	ctx := context.Background()
	l := newLedgerWorld(t)
	var ids []uuid.UUID
	for i := range 6 {
		c := l.command(l.ws, int64(i+1))
		l.take(t, c)
		l.finish(t, c.ID, store.CommandResult{Code: store.CommandKindNotAccepted})
		ids = append(ids, c.ID)
	}
	results, err := l.c.UndeliveredResults(ctx, 10)
	if err != nil || len(results) != 6 || results[0].ID != ids[0] || results[0].Kind != "item.rename" || results[0].StateSeq == nil {
		t.Fatalf("the results: %+v %v", results, err)
	}
	if err := l.c.ResultsFailed(ctx, "transport"); err != nil {
		t.Fatal(err)
	}
	if err := l.c.ResultsPosted(ctx, []store.ContractResultOutcome{
		{ID: ids[0], Answer: store.DeliveryAccepted},
		{ID: ids[1], Answer: store.DeliveryDuplicate},
		{ID: ids[2], Answer: store.DeliveryRejected, Code: "invalid_request"},
		{ID: ids[3], Answer: store.DeliveryRejected, Code: "conflict"},
		{ID: ids[4], Failed: "transport"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.c.ResultsParked(ctx, []uuid.UUID{ids[5]}, "detail"); err != nil {
		t.Fatal(err)
	}
	for i, want := range []struct{ delivery, code string }{
		{store.DeliveryAccepted, ""}, {store.DeliveryDuplicate, ""}, {store.DeliveryRejected, "invalid_request"},
		{store.DeliveryRejected, "conflict"}, {"", ""}, {store.DeliveryRejected, store.RejectLocalInvalid},
	} {
		if r := l.row(t, ids[i]); r.Delivery != want.delivery || r.RejectCode != want.code {
			t.Errorf("result %d: %+v, want %+v", i, r, want)
		}
	}
	results, err = l.c.UndeliveredResults(ctx, 10)
	if err != nil || len(results) != 1 || results[0].ID != ids[4] || results[0].PostTries != 1 {
		t.Fatalf("left to post: %+v %v", results, err)
	}
	if err := l.c.ResultsPosted(ctx, []store.ContractResultOutcome{{ID: ids[4], Answer: "maybe"}}); err == nil {
		t.Fatal("an unknown answer was taken")
	}
	status, err := l.c.SettingsStatus(ctx)
	if err != nil || status.State.ResultsError != "" || status.Parked != 2 || status.Undelivered != 1 || status.UndeliveredError != "transport" {
		t.Fatalf("the status: %+v %v", status, err)
	}
}

// Exactly 30 days: a row is used up to then, invisible after it to the
// executor and to a take (a delivery of its id is a new row), and the trim
// deletes it; and a person no longer followed goes with the trim.
func TestCommandsThirtyDays(t *testing.T) {
	ctx := context.Background()
	l := newLedgerWorld(t)
	young, old, open := l.command(l.ws, 1), l.command(l.ws, 2), l.command(l.ws, 3)
	l.take(t, young, old, open)
	for id, age := range map[uuid.UUID]string{young.ID: "29 days 23 hours", old.ID: "30 days", open.ID: "30 days 1 second"} {
		if _, err := l.pool.Exec(ctx, `UPDATE contract_commands SET taken_at = clock_timestamp() - $2::interval WHERE id = $1`, id, age); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok, err := l.c.NextCommand(ctx); err != nil || !ok || got.ID != young.ID {
		t.Fatalf("the executor took %v %v %v", got.ID, ok, err)
	}
	// The open row past its days is a new row when delivered again.
	again := open
	again.Again = true
	if res := l.take(t, again); res.New != 1 || res.Replayed != 0 {
		t.Fatalf("a delivery of a row past its days: %+v", res)
	}
	gone := uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO contract_persons (sub) VALUES ($1)`, gone); err != nil {
		t.Fatal(err)
	}
	n, err := l.c.TrimCommands(ctx)
	if err != nil || n != 1 {
		t.Fatalf("the trim: %d %v", n, err)
	}
	if !l.row(t, young.ID).Exists || l.row(t, old.ID).Exists || !l.row(t, open.ID).Exists {
		t.Fatal("the trim kept or deleted the wrong rows")
	}
	var left int
	if err := l.pool.QueryRow(ctx, `SELECT count(*) FROM contract_persons WHERE sub = $1`, gone).Scan(&left); err != nil || left != 0 {
		t.Fatalf("a person no longer followed: %d %v", left, err)
	}
}
