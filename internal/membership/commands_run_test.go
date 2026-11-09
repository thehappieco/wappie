package membership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The executor in the commands release (the plan's 3.2, 6.4 and 6.8): its
// order of checks, a row that keeps failing, a row left open at a stop,
// a tightening delivered again, and that nothing the take refused (a
// forged or an expired command) ever runs.

// executorOf is w's settings part in mode, with no loop running: rows are
// judged one by one.
func (w *snapshotWorld) executorOf(t *testing.T, mode string, logs *membershiptest.Logs) *settingsWork {
	t.Helper()
	l := w.settingsLeader(w.members, logs, settingsTimes())
	sw := newSettingsWork(l, &follower{l: l, round: make(chan struct{}, 1)})
	sw.current.Store(&mode)
	return sw
}

// generation is the stored generation.
func (w *world) generation(t *testing.T) uuid.UUID {
	t.Helper()
	g := w.state(t).Generation
	if g == nil {
		t.Fatal("no generation stored")
	}
	return *g
}

// row is a ledger row to take as decoded: kind in ws (nil for a person's)
// by actor, its target and params, drawn from docs; again for one
// delivered again.
type row struct {
	kind           string
	ws             *uuid.UUID
	actor          uuid.UUID
	target, params string
	docs           map[uuid.UUID]int64
	gen            uuid.UUID
	issued         time.Time
	again          bool
}

var rowSeq int64

// take writes r to the ledger with no result, as a take leaves a command to
// run.
func (w *world) take(t *testing.T, r row) uuid.UUID {
	t.Helper()
	rowSeq++
	id := uuid.New()
	section := kc.SectionNumbers
	var wseq *int64
	if r.ws == nil {
		section = kc.SectionPerson
	} else {
		wseq = &rowSeq
	}
	if r.gen == uuid.Nil {
		r.gen = w.generation(t)
	}
	if r.issued.IsZero() {
		r.issued = time.Now()
	}
	docs := map[string]int64{}
	for sub, v := range r.docs {
		docs[sub.String()] = v
	}
	rawDocs, err := json.Marshal(docs)
	if err != nil {
		t.Fatal(err)
	}
	if r.target == "" {
		r.target = "{}"
	}
	if r.params == "" {
		r.params = "{}"
	}
	if _, err := w.pool.Exec(context.Background(), `INSERT INTO contract_commands (id, generation, cseq, workspace_id, wseq, kind, section, actor,
		target, params, based_on_seq, based_on_docs, issued_at, body, body_key, signed_at, again)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1, $11, $12, '{}', $13, clock_timestamp(), $14)`,
		id, r.gen, rowSeq, r.ws, wseq, r.kind, section, r.actor, r.target, []byte(r.params), rawDocs, r.issued, make([]byte, 32),
		r.again); err != nil {
		t.Fatal(err)
	}
	return id
}

// runNext judges the first open row with sw.
func (w *world) runNext(t *testing.T, sw *settingsWork) {
	t.Helper()
	cmd, ok, err := w.contract.NextCommand(context.Background())
	if err != nil || !ok {
		t.Fatalf("no row to run: %v %v", ok, err)
	}
	if !sw.runCommand(context.Background(), cmd) {
		t.Fatal("the run recorded nothing")
	}
}

func item(id uuid.UUID) string { return fmt.Sprintf(`{"item":%q}`, id) }

const renameParams = `{"before":{"label":"Vendas"},"after":{"label":"Vendas SP"}}`

// TestRunChecksOrder: R0 to R5 in their order, each answered with its code
// and the seq it was judged on (none for a person's not_held): a kind the
// mode does not run (read: all; on: item.flags_raise), an actor Wappie does
// not hold, a document not yet applied (memberships_behind, retry_after
// 5), a workspace not recorded, a closed team, a deleted number and
// another workspace's (not_found, before any role); then a rename runs.
func TestRunChecksOrder(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	read, on := w.executorOf(t, store.SettingsRead, logs), w.executorOf(t, store.SettingsOn, logs)
	docs := map[uuid.UUID]int64{w.sub: w.version(t, w.sub)}
	check := func(what string, sw *settingsWork, r row, code string, judged bool) ledgerRow {
		t.Helper()
		id := w.take(t, r)
		w.runNext(t, sw)
		got, _ := w.ledgerRow(t, id.String())
		if got.code != code || (got.stateSeq != nil) != judged || (code == "" && got.outcome != store.CommandRan) {
			t.Fatalf("%s: %+v, want %q (judged on a seq: %v)", what, got, code, judged)
		}
		return got
	}
	rename := row{kind: kc.OpItemRename, ws: &w.team, actor: w.sub, target: item(w.device), params: renameParams, docs: docs}

	check("read", read, rename, kc.CodeKindNotAccepted, true)
	raise := rename
	raise.kind, raise.params = kc.OpItemFlagsRaise, `{"before":{"can":["read"]},"after":{"can":["read","send"]}}`
	check("a kind this binary does not run, in on", on, raise, kc.CodeKindNotAccepted, true)

	stranger := uuid.New()
	unheld := rename
	unheld.actor, unheld.docs = stranger, map[uuid.UUID]int64{stranger: 1}
	check("an actor Wappie does not hold", on, unheld, kc.CodeNotHeld, true)
	signOut := row{kind: kc.OpPersonSignOutEverywhere, actor: stranger, docs: map[uuid.UUID]int64{stranger: 1}}
	check("a person's kind by an actor Wappie does not hold", on, signOut, kc.CodeNotHeld, false)
	// Linked to an account here, but not followed: no document.
	local, err := w.users.Create(ctx, store.NewUser{TenantID: w.team, Email: "unfollowed@example.com", Role: "admin", AuthKey: "x",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("w")})
	if err != nil {
		t.Fatal(err)
	}
	unfollowed := uuid.New()
	w.exec(ctx, t, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, 'u@id.test', 'new')`, unfollowed, local.ID)
	linked := rename
	linked.actor, linked.docs = unfollowed, map[uuid.UUID]int64{unfollowed: 1}
	check("a linked actor Wappie does not follow", on, linked, kc.CodeNotHeld, true)

	behind := rename
	behind.docs = map[uuid.UUID]int64{w.sub: w.version(t, w.sub) + 1}
	id := w.take(t, behind)
	w.runNext(t, on)
	var retry *int
	if err := w.pool.QueryRow(ctx, `SELECT retry_after FROM contract_commands WHERE id = $1 AND code = 'memberships_behind'`, id).
		Scan(&retry); err != nil || retry == nil || *retry != 5 {
		t.Fatalf("memberships_behind: retry_after %v, %v", retry, err)
	}

	elsewhere := uuid.New()
	unrecorded := rename
	unrecorded.ws = &elsewhere
	check("a workspace not recorded", on, unrecorded, kc.CodeNotFound, true)
	w.exec(ctx, t, `UPDATE contract_workspaces SET status = 'closed' WHERE workspace_id = $1`, w.team)
	check("a closed team", on, rename, kc.CodeTeamClosed, true)
	w.exec(ctx, t, `UPDATE contract_workspaces SET status = 'open' WHERE workspace_id = $1`, w.team)

	// The target before any role: the home's number, named in the team,
	// is not found there, nor is a deleted number.
	home := w.number(t, w.home, "Casa", 77, w.owner)
	theirs := rename
	theirs.target = item(home)
	check("another workspace's number", on, theirs, kc.CodeNotFound, true)
	notOurs := rename
	notOurs.target = `{"item":"not-a-uuid"}`
	check("an id that is none of Wappie's", on, notOurs, kc.CodeNotFound, true)
	// The number's own id, written otherwise than Wappie writes it.
	upper := rename
	upper.target = fmt.Sprintf(`{"item":%q}`, strings.ToUpper(w.device.String()))
	check("the number's id in capitals", on, upper, kc.CodeNotFound, true)

	got := check("a rename", on, rename, "", true)
	if d, err := store.NewDevices(w.pool).Get(ctx, w.team.String(), w.device.String()); err != nil || d.Label != "Vendas SP" {
		t.Fatalf("the label after the rename: %+v %v", d, err)
	}
	var sections int64
	if err := w.pool.QueryRow(ctx, `SELECT sections_seq FROM contract_workspaces WHERE workspace_id = $1`, w.team).Scan(&sections); err != nil ||
		*got.stateSeq != sections {
		t.Fatalf("ran at %v, the clock at %d", got.stateSeq, sections)
	}
	if len(logs.Lines("contract: a command was run", "outcome=ran")) != 1 {
		t.Fatalf("the log:\n%s", logs.String())
	}
}

// TestExecutorRowStuck: a command whose act fails with a store error (a
// constraint a trigger of the test raises) backs off; another workspace's
// command runs meanwhile, a later command of its own workspace waits
// behind it; after 5 tries it is answered rate_limited (retry_after 60)
// with an ERROR, and the one behind it runs then.
func TestExecutorRowStuck(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsOn)
	w.exec(ctx, t, `CREATE FUNCTION test_refuse_stuck() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.label = 'Stuck' THEN
				RAISE EXCEPTION 'the test refuses it' USING ERRCODE = '23514';
			END IF;
			RETURN NEW;
		END $$`)
	w.exec(ctx, t, `CREATE TRIGGER test_refuse_stuck BEFORE UPDATE OF label ON devices FOR EACH ROW EXECUTE FUNCTION test_refuse_stuck()`)
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	home := w.number(t, w.home, "Casa", 77, w.owner)
	for _, ws := range []uuid.UUID{w.team, w.home} {
		eventually(t, soon, "the sections listing the kinds", func() bool {
			doc, ok := w.fake.Settings("wappie", ws.String(), kc.SectionNumbers)
			return ok && len(doc.Accepts) == 5
		})
	}
	issue := func(ws, device uuid.UUID, before, after string) string {
		t.Helper()
		id, err := w.fake.IssueCommand("wappie", contracttest.CommandSpec{Kind: kc.OpItemRename, Workspace: ws.String(), Actor: w.sub.String(),
			Target: kc.CommandTarget{Item: device.String()}, Params: json.RawMessage(fmt.Sprintf(`{"before":{"label":%q},"after":{"label":%q}}`, before, after))})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	stuck := issue(w.team, w.device, "Vendas", "Stuck")
	behind := issue(w.team, w.device, "Vendas", "Vendas SP")
	other := issue(w.home, home, "Casa", "Casa SP")
	eventually(t, soon, "the other workspace's command ran", func() bool {
		r, ok := w.ledgerRow(t, other)
		return ok && r.outcome == store.CommandRan
	})
	if r, ok := w.ledgerRow(t, behind); !ok || r.outcome != "" {
		t.Fatalf("the command behind the stuck one: %+v", r)
	}
	eventually(t, soon, "five tries, then rate_limited", func() bool {
		var code string
		if err := w.pool.QueryRow(ctx, `UPDATE contract_commands SET run_after = CASE WHEN run_after > clock_timestamp()
			THEN clock_timestamp() ELSE run_after END WHERE id = $1 RETURNING coalesce(code, '')`, stuck).Scan(&code); err != nil {
			t.Fatal(err)
		}
		return code == kc.CodeRateLimited
	})
	var tries, retry int
	if err := w.pool.QueryRow(ctx, `SELECT run_tries, retry_after FROM contract_commands WHERE id = $1`, stuck).Scan(&tries, &retry); err != nil ||
		tries != store.CommandRunTries || retry != 60 {
		t.Fatalf("tries %d, retry_after %d: %v", tries, retry, err)
	}
	eventually(t, soon, "the command behind it ran", func() bool {
		r, _ := w.ledgerRow(t, behind)
		return r.outcome == store.CommandRan
	})
	eventually(t, soon, "the ERROR recorded", func() bool { return w.state(t).ErrorClass == store.ContractErrorCommandStuck })
	if len(logs.Lines("level=ERROR", "contract: a command was answered rate_limited after its runs kept failing")) != 1 {
		t.Fatalf("the log:\n%s", logs.String())
	}
}

// TestExecutorResumesAtStart: a command taken whose run did not finish
// runs at the next leader's start; an old generation's open row runs too,
// its result dropped, never posted.
func TestExecutorResumesAtStart(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsOn)
	w.exec(ctx, t, `CREATE FUNCTION test_refuse_all() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'the test refuses it' USING ERRCODE = '23514'; END $$`)
	w.exec(ctx, t, `CREATE TRIGGER test_refuse_all BEFORE UPDATE OF label ON devices FOR EACH ROW EXECUTE FUNCTION test_refuse_all()`)
	logs := &membershiptest.Logs{}
	stop := run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the section listing the kinds", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		return ok && len(doc.Accepts) == 5
	})
	id := w.rename(t, w.team, w.device, w.sub)
	eventually(t, soon, "a failed run", func() bool {
		var tries int
		_ = w.pool.QueryRow(ctx, `SELECT run_tries FROM contract_commands WHERE id = $1`, id).Scan(&tries) //nolint:errcheck // not taken yet
		return tries > 0
	})
	stop()
	if r, _ := w.ledgerRow(t, id); r.outcome != "" {
		t.Fatalf("the row has a result already: %+v", r)
	}
	w.exec(ctx, t, `DROP TRIGGER test_refuse_all ON devices`)
	w.exec(ctx, t, `UPDATE contract_commands SET run_after = clock_timestamp() WHERE id = $1`, id)
	old := w.take(t, row{kind: kc.OpItemRename, ws: &w.team, actor: w.sub, gen: uuid.New(), target: item(w.device),
		params: `{"before":{"label":"Vendas SP"},"after":{"label":"Vendas RJ"}}`, docs: map[uuid.UUID]int64{w.sub: w.version(t, w.sub)}})
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the open row ran at the start", func() bool {
		r, _ := w.ledgerRow(t, id)
		return r.outcome == store.CommandRan && r.delivery == store.DeliveryAccepted
	})
	eventually(t, soon, "the old generation's row ran, its result dropped", func() bool {
		r, _ := w.ledgerRow(t, old.String())
		return r.outcome == store.CommandRan && r.delivery == store.DeliveryDropped
	})
	if d, err := store.NewDevices(w.pool).Get(ctx, w.team.String(), w.device.String()); err != nil || d.Label != "Vendas RJ" {
		t.Fatalf("the label: %+v %v", d, err)
	}
}

// TestTighteningAgain: a person.sign_out_everywhere delivered again whose
// row the ledger holds is answered from it, never run again (a session
// begun since stays); one delivered again with no row (past 30 days, or
// after Wappie's restore) runs, whatever its age, and counts what it ends.
func TestTighteningAgain(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	sw := w.executorOf(t, store.SettingsOn, &membershiptest.Logs{})
	gen := w.generation(t)
	u, err := w.users.Get(ctx, w.home, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := w.users.StartSession(ctx, u, "before")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	issued := time.Now()
	docs := json.RawMessage(fmt.Sprintf(`{%q:%d}`, w.sub, w.version(t, w.sub)))
	take := func(id uuid.UUID, again bool, at time.Time) store.ContractTakeResult {
		t.Helper()
		st, err := w.contract.SettingsState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		body := []byte(fmt.Sprintf(`{"id":%q,"issued":%q}`, id, at))
		res, err := w.contract.TakeCommands(ctx, store.ContractCommandPage{SeenGeneration: gen, After: st.FeedCursor, NextAfter: st.FeedCursor + 1,
			SignedAt: time.Now(), Items: []store.ContractCommandTake{{ID: id, Cseq: st.FeedCursor + 1, Body: body, BodyKey: bodyKey(body), Again: again,
				Decoded: &store.ContractCommandFields{Producer: store.ProducerWappie, Kind: kc.OpPersonSignOutEverywhere, Section: kc.SectionPerson,
					Actor: w.sub, Target: json.RawMessage(`{}`), Params: []byte(`{}`), BasedOnDocs: docs, IssuedAt: at, FirstIssuedAt: at}}}})
		if err != nil || !res.Committed {
			t.Fatalf("the take: %+v %v", res, err)
		}
		return res
	}
	first := uuid.New()
	take(first, false, issued)
	w.runNext(t, sw)
	if r, _ := w.ledgerRow(t, first.String()); r.outcome != store.CommandRan {
		t.Fatalf("the first run: %+v", r)
	}
	if _, _, err := w.users.ActiveSession(ctx, token); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("the session begun before: %v", err)
	}
	later, _, err := w.users.StartSession(ctx, u, "later")
	if err != nil {
		t.Fatal(err)
	}
	if res := take(first, true, issued); res.Replayed != 1 || res.New != 0 {
		t.Fatalf("delivered again with its row: %+v", res)
	}
	if _, ok, err := w.contract.NextCommand(ctx); err != nil || ok {
		t.Fatalf("a replay left a row to run: %v %v", ok, err)
	}
	// With no row, delivered again 40 days on: it runs, and the session
	// begun after it stays.
	gone := uuid.New()
	if res := take(gone, true, issued.Add(-40*24*time.Hour)); res.New != 1 {
		t.Fatalf("delivered again with no row: %+v", res)
	}
	w.runNext(t, sw)
	var detail string
	if err := w.pool.QueryRow(ctx, `SELECT detail::text FROM contract_commands WHERE id = $1 AND outcome = 'ran'`, gone).Scan(&detail); err != nil ||
		detail != `{"sessions_ended": 0}` {
		t.Fatalf("the rerun's detail %q: %v", detail, err)
	}
	if _, _, err := w.users.ActiveSession(ctx, later); err != nil {
		t.Fatalf("the session begun after: %v", err)
	}
}

// pageOf is a command feed page of the stored generation from the cursor,
// with raw at the next cseq, signed at signedAt, verified with secret.
func (w *world) pageOf(t *testing.T, raw []byte, signedAt time.Time, secret string) (uuid.UUID, int64, CommandPage) {
	t.Helper()
	st, err := w.contract.SettingsState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gen := w.generation(t)
	cseq := st.FeedCursor + 1
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["cseq"], m["generation"] = cseq, gen.String()
	delete(m, "mac")
	unsigned, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := kc.SignCommand(unsigned, App, secret)
	if err != nil {
		t.Fatal(err)
	}
	return gen, st.FeedCursor, CommandPage{Feed: kc.CommandFeed{Generation: gen.String(), Head: cseq, NextAfter: cseq,
		Items: []kc.CommandFeedItem{{CSeq: cseq, Command: signed}}}, SignedAt: signedAt, kit: &kc.Client{App: App, Accept: []string{w.secret}}}
}

// TestTakeRefusalsNeverRun: in the mode on, a command the take refused
// never runs: one carried by an answer signed after its expires_at
// (expired), one whose MAC holds under none of Wappie's secrets
// (invalid_command), and one delivered again after it ran (a replay,
// answered from its row). The number keeps its label each time.
func TestTakeRefusalsNeverRun(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	stop := run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
	w.settleSection(t, w.team)
	w.offer(t, w.team, kc.OpItemRename)
	id := w.rename(t, w.team, w.device, w.sub)
	eventually(t, soon, "the read release's answer", func() bool {
		r, _ := w.ledgerRow(t, id)
		return r.code == kc.CodeKindNotAccepted
	})
	stop()
	issued, _ := w.fake.Command("wappie", id)
	raw, err := json.Marshal(issued)
	if err != nil {
		t.Fatal(err)
	}
	label := func() string {
		d, err := store.NewDevices(w.pool).Get(ctx, w.team.String(), w.device.String())
		if err != nil {
			t.Fatal(err)
		}
		return d.Label
	}
	sw := w.executorOf(t, store.SettingsOn, logs)
	fresh := func(raw []byte) []byte {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		next, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		m["id"] = next.String()
		m["wseq"] = 1000 + rowSeq
		rowSeq++
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, c := range []struct {
		what     string
		signedAt time.Time
		secret   string
		code     string
	}{
		{"carried after its expires_at", issued.ExpiresAt.Add(time.Second), w.secret, kc.CodeExpired},
		{"signed with another secret", time.Now(), membershiptest.Secret(t), kc.CodeInvalidCommand},
	} {
		gen, after, page := w.pageOf(t, fresh(raw), c.signedAt, c.secret)
		if err := sw.take(ctx, gen, after, page); err != nil {
			t.Fatal(err)
		}
		if cmd, ok, err := w.contract.NextCommand(ctx); err != nil || ok {
			t.Fatalf("%s: a row to run: %+v %v", c.what, cmd, err)
		}
		var code string
		if err := w.pool.QueryRow(ctx, `SELECT coalesce(code, '') FROM contract_commands ORDER BY take_seq DESC LIMIT 1`).Scan(&code); err != nil ||
			code != c.code {
			t.Fatalf("%s: %q, want %q (%v)", c.what, code, c.code, err)
		}
		if got := label(); got != "Vendas" {
			t.Fatalf("%s: the label became %q", c.what, got)
		}
	}
	// One that runs, then the same delivered again: answered from its row.
	body := fresh(raw)
	gen, after, page := w.pageOf(t, body, time.Now(), w.secret)
	if err := sw.take(ctx, gen, after, page); err != nil {
		t.Fatal(err)
	}
	w.runNext(t, sw)
	if got := label(); got != "Vendas SP" {
		t.Fatalf("the command that runs left %q", got)
	}
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET label = 'Vendas' WHERE id = $1`, w.device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	gen, after, page = w.pageOf(t, body, time.Now(), w.secret)
	page.Feed.Items[0].Again = true
	if err := sw.take(ctx, gen, after, page); err != nil {
		t.Fatal(err)
	}
	if cmd, ok, err := w.contract.NextCommand(ctx); err != nil || ok {
		t.Fatalf("a replay: a row to run: %+v %v", cmd, err)
	}
	if got := label(); got != "Vendas" {
		t.Fatalf("a replay ran the rename again: %q", got)
	}
}

// TestSettingsOnEndToEnd: in the mode on, each listed kind the console
// issues runs, its result kept by the platform, and what the console waits
// for holds: the numbers section (and for a rename the snapshot, with the
// new label) at or above the result's seq, a person's document at or above
// theirs; item.sync_now is offered and judged.
func TestSettingsOnEndToEnd(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsOn)
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the section listing the kinds", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		return ok && len(doc.Accepts) == 5
	})
	eventually(t, soon, "the person's document listing the kinds", func() bool {
		doc, ok := w.fake.PersonSettings("wappie", w.sub.String())
		return ok && len(doc.Accepts) == 2
	})
	result := func(id string) kc.CommandResult {
		t.Helper()
		var res kc.CommandResult
		eventually(t, soon, "the result kept", func() bool {
			var ok bool
			res, ok = w.fake.CommandResult("wappie", id)
			return ok
		})
		if res.Outcome != kc.OutcomeRan || res.StateSeq == nil {
			t.Fatalf("the result: %+v", res)
		}
		return res
	}
	shown := func(seq int64, snapshot bool) {
		t.Helper()
		eventually(t, soon, "the numbers section shown", func() bool {
			doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
			return ok && doc.StateSeq >= seq
		})
		if snapshot {
			eventually(t, soon, "the snapshot shown", func() bool {
				s, ok := w.fake.Snapshot("wappie", w.team.String())
				if !ok || s.SnapshotSeq < seq {
					return false
				}
				for _, it := range s.Items {
					if it.ID == w.device.String() {
						return it.Label != nil && *it.Label == "Vendas SP"
					}
				}
				return false
			})
		}
	}
	issue := func(spec contracttest.CommandSpec) string {
		t.Helper()
		spec.Actor = w.sub.String()
		id, err := w.fake.IssueCommand("wappie", spec)
		if err != nil {
			t.Fatalf("%s: %v", spec.Kind, err)
		}
		return id
	}
	target := kc.CommandTarget{Item: w.device.String()}
	res := result(w.rename(t, w.team, w.device, w.sub))
	shown(*res.StateSeq, true)
	res = result(issue(contracttest.CommandSpec{Kind: kc.OpItemSyncStop, Workspace: w.team.String(), Target: target,
		Params: json.RawMessage(`{"before":{"capture":"on"},"after":{"capture":"paused"}}`)}))
	shown(*res.StateSeq, false)
	res = result(issue(contracttest.CommandSpec{Kind: kc.OpItemSyncResume, Workspace: w.team.String(), Target: target,
		Params: json.RawMessage(`{"before":{"capture":"paused"},"after":{"capture":"on"}}`)}))
	shown(*res.StateSeq, false)
	pending, err := store.NewDevices(w.pool).Create(ctx, w.team.String(), "device", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "the registration listed", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		return ok && strings.Contains(string(doc.Data), pending.ID)
	})
	res = result(issue(contracttest.CommandSpec{Kind: kc.OpItemRegistrationDelete, Workspace: w.team.String(),
		Target: kc.CommandTarget{Row: pending.ID}, Confirm: &pending.ID}))
	shown(*res.StateSeq, false)
	if _, err := store.NewDevices(w.pool).Get(ctx, w.team.String(), pending.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the registration: %v", err)
	}
	for _, spec := range []contracttest.CommandSpec{
		{Kind: kc.OpPersonNoticesDismiss, Params: json.RawMessage(`{"notices":[{"id":"424242","version":1}]}`)},
		{Kind: kc.OpPersonSignOutEverywhere},
	} {
		res = result(issue(spec))
		eventually(t, soon, "the person's document shown", func() bool {
			doc, ok := w.fake.PersonSettings("wappie", w.sub.String())
			return ok && doc.StateSeq >= *res.StateSeq
		})
	}
	if res.Detail == nil || res.Detail.SessionsEnded == nil {
		t.Fatalf("the sign-out's detail: %+v", res.Detail)
	}
	doc, _ := w.fake.PersonSettings("wappie", w.sub.String())
	var data kc.WappiePersonSettings
	if err := json.Unmarshal(doc.Data, &data); err != nil || data.SignedOutEverywhereAt == nil {
		t.Fatalf("signed_out_everywhere_at: %s %v", doc.Data, err)
	}
	// Sync now is offered (DS13): the owner who reads the number syncs it
	// now; with no WhatsApp connection in this process it is
	// connect_failed, at a seq.
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET current_epoch = 1 WHERE id = $1`, w.device); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_permissions (tenant_id, device_id, user_id, can_read) VALUES ($1, $2, $3, true)
			ON CONFLICT (tenant_id, device_id, user_id) DO UPDATE SET can_read = true`, w.team, w.device, w.owner)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	id := issue(contracttest.CommandSpec{Kind: kc.OpItemSyncNow, Workspace: w.team.String(), Target: target})
	var got kc.CommandResult
	eventually(t, soon, "the sync now's result kept", func() bool {
		var ok bool
		got, ok = w.fake.CommandResult("wappie", id)
		return ok
	})
	if got.Outcome != kc.OutcomeRefused || got.Code == nil || *got.Code != kc.CodeConnectFailed || got.StateSeq == nil {
		t.Fatalf("the sync now: %+v", got)
	}
}
