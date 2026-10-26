package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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
	"whatserver2/internal/wa"
)

// The events (README 9; the plan's 4.11, TB4, TB31 to TB35, and TB2's and
// TB23's event parts) on a real database and the fake platform.

// eventWorld is a team of the platform's that Wappie holds and records,
// with its owner and a member, both held, and a number they both read.
type eventWorld struct {
	*world
	owner, sub, home  uuid.UUID
	second, secondSub uuid.UUID
	team, device      uuid.UUID
}

func newEventWorld(t *testing.T) *eventWorld {
	t.Helper()
	ctx := context.Background()
	w := &eventWorld{world: newWorld(t)}
	w.owner, w.sub, w.home = w.heldAtHome(t)
	w.second, w.secondSub, _ = w.heldAtHome(t)
	team, err := w.fake.AddTeam("Equipe", w.sub.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.fake.SetRole(team, w.secondSub.String(), kc.RoleMember); err != nil {
		t.Fatal(err)
	}
	w.team = uuid.MustParse(team)
	w.localTeam(t, w.team, "Equipe", member{w.owner, "owner", "active"}, member{w.second, "member", "active"})
	w.device = w.number(t, w.team, "Vendas", 1, w.owner, w.second)
	w.members.SignIn(ctx, w.sub)
	w.members.SignIn(ctx, w.secondSub)
	if _, ok, err := w.contract.Workspace(ctx, w.team); err != nil || !ok {
		t.Fatalf("the team is not recorded: %v %v", ok, err)
	}
	return w
}

// number makes a number of ws named name, its phone number ending in n,
// that each of readers reads: Read and a key at its epoch.
func (w *world) number(t *testing.T, ws uuid.UUID, name string, n int, readers ...uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	d, err := store.NewDevices(w.pool).Create(ctx, ws.String(), name, wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(d.ID)
	if err := pg.InTenantTx(ctx, w.pool, ws.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET pn = $2, current_epoch = 1 WHERE id = $1`, device,
			fmt.Sprintf("551191234%04d@s.whatsapp.net", n)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key)
			VALUES ($1, $2, 1, decode(repeat('ab', 32), 'hex'))`, ws, device); err != nil {
			return err
		}
		for _, r := range readers {
			if err := readsTx(ctx, tx, ws, device, r); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return device
}

// readsTx gives user the number's key and Read.
func readsTx(ctx context.Context, tx pgx.Tx, ws, device, user uuid.UUID) error {
	if _, err := tx.Exec(ctx, `INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk, granted_by)
		VALUES ($1, $2, $3, 1, '\x01', $3)`, ws, device, user); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO device_permissions (tenant_id, device_id, user_id, can_read) VALUES ($1, $2, $3, true)
		ON CONFLICT (tenant_id, device_id, user_id) DO UPDATE SET can_read = true`, ws, device, user)
	return err
}

// eventRow is an item_events row a test writes in SQL with its type's
// columns, as release A's writers write one; its times are intervals
// before the database's clock (created, and occurred unless at says it).
type eventRow struct {
	id, item          uuid.UUID
	kind, actorKind   string
	actor, user       *uuid.UUID
	readers           []uuid.UUID
	label, hint       *string
	purgeAfter        *time.Time
	to, person        *uuid.UUID
	cause             *string
	created, occurred string
	at                *time.Time
	replayed          bool
}

func (w *world) event(t *testing.T, ws uuid.UUID, r eventRow) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	if r.id == uuid.Nil {
		r.id = uuid.Must(uuid.NewV7())
	}
	if r.item == uuid.Nil {
		r.item = uuid.New()
	}
	if r.actorKind == "" {
		r.actorKind = "person"
	}
	if r.created == "" {
		r.created = "0"
	}
	if r.occurred == "" {
		r.occurred = r.created
	}
	if r.readers == nil {
		r.readers = []uuid.UUID{}
	}
	if r.kind == "moved_out" && r.to == nil {
		to := uuid.New()
		r.to = &to
	}
	if err := pg.InTenantTx(ctx, w.pool, ws.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind,
				actor_sub, actor_user_id, reader_subs, label, hint, deleted_at, purge_after, to_tenant_id, ledgered_at, replayed_at,
				person_sub, cause, created_at)
			VALUES ($1, $2, $3, $4, $5, coalesce($6, clock_timestamp() - $7::interval), $8, $9, $10, $11, $12, $13,
				CASE WHEN $3 IN ('deleted', 'recovered', 'purged') THEN clock_timestamp() - $7::interval END,
				CASE WHEN $3 IN ('deleted', 'purged') THEN coalesce($14, clock_timestamp() + interval '30 days') END,
				$15, CASE WHEN $3 IN ('sync_paused', 'stranded') OR $16 THEN clock_timestamp() END, CASE WHEN $16 THEN clock_timestamp() END,
				$17, $18, clock_timestamp() - $19::interval)`,
			r.id, ws, r.kind, r.item, r.kind+":"+r.id.String(), r.at, r.occurred, r.actorKind, r.actor, r.user, r.readers,
			r.label, r.hint, r.purgeAfter, r.to, r.replayed, r.person, r.cause, r.created)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return r.id
}

// sender is an event sender of a leader over m, driven by the test (send,
// flush), its backoff an hour: a test's next try is its own call.
func (w *world) sender(t *testing.T, m *Members, logs *membershiptest.Logs) *eventSender {
	t.Helper()
	l := w.leader(m, logs, lockKey(t))
	l.EventBackoffMin, l.EventBackoffMax = time.Hour, time.Hour
	return newEventSender(l)
}

// flush sends ws's queue until it is empty, the platform answering.
func flush(t *testing.T, s *eventSender, ws uuid.UUID) {
	t.Helper()
	for range 100 {
		more, ok := s.send(context.Background(), ws)
		if !ok {
			t.Fatal("the store could not be read or written")
		}
		if !more {
			return
		}
	}
	t.Fatal("the queue never emptied")
}

// sentTo are the events of ws the fake platform accepted, in order.
func (w *world) sentTo(ws uuid.UUID) []kc.Event {
	var out []kc.Event
	for _, ev := range w.fake.Events("wappie") {
		if ev.WorkspaceID == ws.String() {
			out = append(out, ev)
		}
	}
	return out
}

func idsOf(events []kc.Event) []uuid.UUID {
	out := make([]uuid.UUID, len(events))
	for i, ev := range events {
		out[i] = uuid.MustParse(ev.EventID)
	}
	return out
}

// delivery is a row's delivery columns.
type delivery struct {
	outcome, code string
	into          *uuid.UUID
	settled       bool
}

func (w *world) delivery(t *testing.T, ws, id uuid.UUID) delivery {
	t.Helper()
	ctx := context.Background()
	var d delivery
	if err := pg.InTenantTx(ctx, w.pool, ws.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(outcome, ''), coalesce(reject_code, ''), coalesce_into, settled_at IS NOT NULL
			FROM (SELECT outcome, reject_code, coalesced_into AS coalesce_into, settled_at FROM item_events WHERE event_id = $1) e`, id).
			Scan(&d.outcome, &d.code, &d.into, &d.settled)
	}); err != nil {
		t.Fatalf("event %s: %v", id, err)
	}
	return d
}

// queue is a workspace's queue columns.
type queue struct {
	tries    int
	due      bool
	class    string
	notFound bool
}

func (w *world) queue(t *testing.T, ws uuid.UUID) queue {
	t.Helper()
	var q queue
	if err := w.pool.QueryRow(context.Background(), `SELECT events_tries, coalesce(events_due_at <= clock_timestamp(), true),
		coalesce(events_error, ''), events_not_found_since IS NOT NULL FROM contract_workspaces WHERE workspace_id = $1`, ws).
		Scan(&q.tries, &q.due, &q.class, &q.notFound); err != nil {
		t.Fatal(err)
	}
	return q
}

// relay is a client of the fake platform whose events requests answer may
// answer instead: given the request, pointed at the fake, and its body, it
// returns the answer to give, or nil for the fake's own.
func (w *world) relay(t *testing.T, answer func(r *http.Request, body []byte) *http.Response) *Client {
	t.Helper()
	platform, err := url.Parse(w.fake.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := clientOn(func(r *http.Request) (*http.Response, error) {
		out := r.Clone(r.Context())
		out.URL.Scheme, out.URL.Host, out.Host = platform.Scheme, platform.Host, platform.Host
		if strings.HasSuffix(r.URL.Path, "/events") {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			out.Body = io.NopCloser(bytes.NewReader(body))
			if res := answer(out, body); res != nil {
				return res, nil
			}
			out.Body = io.NopCloser(bytes.NewReader(body))
		}
		return http.DefaultTransport.RoundTrip(out)
	}, nil)
	if err := c.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	return c
}

// batchOf is the events of a request's body.
func batchOf(t *testing.T, body []byte) []kc.Event {
	t.Helper()
	var b kc.Events
	if err := json.Unmarshal(body, &b); err != nil {
		t.Errorf("a batch's body: %v", err)
	}
	return b.Events
}

// answered is a signed answer of results to r.
func (w *world) answered(t *testing.T, r *http.Request, results ...kc.EventResult) *http.Response {
	t.Helper()
	body, err := json.Marshal(kc.EventResults{Results: results})
	if err != nil {
		t.Fatal(err)
	}
	return signedAnswer(r, w.secret, http.StatusOK, body, time.Now())
}

// refused is a signed refusal of r with code.
func (w *world) refused(r *http.Request, status int, code string) *http.Response {
	return signedAnswer(r, w.secret, status, fmt.Appendf(nil, `{"code":%q,"message":"test"}`, code), time.Now())
}

// forward lets the fake platform take r, and drops its answer.
func forward(t *testing.T, r *http.Request) {
	t.Helper()
	res, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		t.Errorf("the fake platform: %v", err)
		return
	}
	_ = res.Body.Close() //nolint:errcheck // the answer is dropped on purpose
}

func ptr[T any](v T) *T { return &v }

// TB4: one row of each type, read from the queue and rendered, byte for
// byte as testdata/events/*.json (the time the golden's: the row's own is
// the database's, checked first), each and all valid as the kit validates
// them; readers null above 5000, a list at 5000.
func TestEventGoldenFiles(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	ws := fixed("a000", 1)
	w.exec(ctx, t, `INSERT INTO tenants (id, name) VALUES ($1, 'Equipe')`, ws)
	w.exec(ctx, t, `INSERT INTO contract_workspaces (workspace_id, kind, named_at) VALUES ($1, 'team', clock_timestamp() - interval '1 minute')`, ws)
	owner, other, lost := fixed("a0c2", 1), fixed("c3d4", 2), fixed("c3d4", 3)
	purgeAt := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	both := []uuid.UUID{owner, other}
	rows := []eventRow{
		{kind: "deleted", actor: &owner, readers: both, purgeAfter: &purgeAt},
		{kind: "sync_paused", actorKind: "key", actor: &owner, readers: both},
		{kind: "recovered", actor: &owner, readers: both},
		{kind: "purged", actorKind: "app", purgeAfter: &purgeAt},
		{kind: "moved_out", actor: &owner, readers: []uuid.UUID{owner}, to: ptr(fixed("a000", 2))},
		{kind: "stranded", actor: &owner, readers: []uuid.UUID{owner, lost}, person: &lost, cause: ptr("revoked")},
	}
	for i := range rows {
		rows[i].id, rows[i].item = fixed("d000", i+1), fixed("e000", 4)
		if rows[i].kind != "purged" {
			// The purge nulls them.
			rows[i].label, rows[i].hint = ptr("Vendas"), ptr("…5678")
		}
		w.event(t, ws, rows[i])
	}
	batch, err := w.contract.EventBatch(ctx, ws, kc.MaxEvents)
	if err != nil || len(batch.Events) != len(rows) || batch.More || batch.NotSent+batch.Coalesced+len(batch.Expired) != 0 {
		t.Fatalf("the queue: %+v %v", batch, err)
	}
	at := kc.T(time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC))
	var all []kc.Event
	for i, e := range batch.Events {
		ev := EventOf(ws, e)
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: %v", rows[i].kind, err)
		}
		if ev.EventID != rows[i].id.String() || !ev.OccurredAt.Equal(e.OccurredAt) || e.OccurredAt.Nanosecond()%1000 != 0 {
			t.Errorf("%s: event %s at %v, the row %s at %v", rows[i].kind, ev.EventID, ev.OccurredAt, rows[i].id, e.OccurredAt)
		}
		ev.OccurredAt = at
		all = append(all, ev)
		got, err := json.MarshalIndent(ev, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, '\n')
		golden := filepath.Join("testdata", "events", rows[i].kind+".json")
		if *updateGolden {
			if err := os.MkdirAll(filepath.Dir(golden), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(golden, got, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v (run with -update to create it)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from %s:\n%s", rows[i].kind, golden, got)
		}
	}
	if err := (kc.Events{Events: all}).Validate(); err != nil {
		t.Fatalf("the batch: %v", err)
	}

	// More readers than an event carries.
	crowd := store.ContractEvent{EventID: fixed("d000", 9), Type: "sync_paused", ItemID: fixed("e000", 4), OccurredAt: at.Time,
		ActorKind: "person", ActorSub: &owner}
	for range kc.MaxReaders {
		crowd.Readers = append(crowd.Readers, uuid.New())
	}
	if ev := EventOf(ws, crowd); ev.Readers == nil || len(*ev.Readers) != kc.MaxReaders || ev.Validate() != nil {
		t.Fatalf("5000 readers: %v", ev.Validate())
	}
	crowd.Readers = append(crowd.Readers, uuid.New())
	if ev := EventOf(ws, crowd); ev.Readers != nil || ev.Validate() != nil {
		t.Fatalf("5001 readers go as null: %v", ev.Validate())
	}
	b, err := json.Marshal(EventOf(ws, crowd))
	if err != nil || !bytes.Contains(b, []byte(`"readers":null`)) {
		t.Fatalf("5001 readers: %s %v", b, err)
	}
}

// eventFromWire is the queue's event a wire event renders from, false for
// one Wappie never sends (a mailbox's).
func eventFromWire(ev kc.Event) (store.ContractEvent, bool) {
	kind := ""
	for k, v := range eventTypes {
		if v == ev.Type {
			kind = k
		}
	}
	id, err := uuid.Parse(ev.EventID)
	item, ierr := uuid.Parse(ev.Item.ID)
	if kind == "" || err != nil || ierr != nil || ev.Item.Kind != kc.ItemNumber || (ev.To != nil && *ev.To != kc.MovedToPersonal) {
		return store.ContractEvent{}, false
	}
	e := store.ContractEvent{EventID: id, Type: kind, ItemID: item, OccurredAt: ev.OccurredAt.Time, ActorKind: ev.ActorKind,
		Label: ev.Item.Label, Hint: ev.Item.Hint, Cause: ev.Cause}
	if ev.Actor != nil {
		e.ActorSub = ptr(uuid.MustParse(*ev.Actor))
	}
	if ev.Readers == nil {
		for range kc.MaxReaders + 1 {
			e.Readers = append(e.Readers, uuid.New())
		}
	} else {
		e.Readers = []uuid.UUID{}
		for _, r := range *ev.Readers {
			e.Readers = append(e.Readers, uuid.MustParse(r))
		}
	}
	if ev.PurgeAt != nil {
		e.PurgeAfter = ptr(ev.PurgeAt.Time)
	}
	if ev.Person != nil {
		e.PersonSub = ptr(uuid.MustParse(*ev.Person))
	}
	return e, true
}

// TB2's event part: every event of wire.json through Wappie's own check
// before a send (the kit's Validate), which takes exactly the valid ones;
// and each valid one, a number's, through Wappie's own encoder comes back
// as the vector.
func TestEventWireVectors(t *testing.T) {
	var v wireVectors
	readVectors(t, "wire.json", &v)
	if len(v.Events) == 0 {
		t.Fatal("wire.json: no events")
	}
	trips := 0
	for _, c := range v.Events {
		var ev kc.Event
		decoded := json.Unmarshal(c.Value, &ev) == nil
		if got := decoded && ev.Validate() == nil; got != c.Valid {
			t.Errorf("%s: Wappie would send it %v, valid %v", c.Name, got, c.Valid)
		}
		if !c.Valid {
			continue
		}
		e, ok := eventFromWire(ev)
		if !ok {
			continue
		}
		got, err := json.Marshal(EventOf(uuid.MustParse(ev.WorkspaceID), e))
		if err != nil {
			t.Fatal(err)
		}
		var a, b any
		if err := json.Unmarshal(got, &a); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(c.Value, &b); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: Wappie's encoder gives\n%s\nwant\n%s", c.Name, got, c.Value)
		}
		trips++
	}
	if trips < 8 {
		t.Fatalf("only %d vectors went through the encoder", trips)
	}
}

// TB31 (with TB26's sending clause): what is never sent, and what is.
// Never: a row written before the first observe, or before the workspace
// was named; one of a workspace no document names; a pause, a stranding
// or a move written while the contract was off; a replayed pause; a
// replayed deletion, recovery or purge that occurred before the first
// observe, or after it and before the naming. Sent: everything else, a
// deletion, a recovery and a purge written while off included (after the
// return to observe, a purge after its deletion), and a replayed deletion,
// recovery or purge that occurred after both, in an off period too, which
// comes back duplicate when the platform holds it already. A replayed row
// is as release A's replay writes it (no readers, no sub, a recovery with
// no actor at all): none is told as an actor without a sub, a deletion's
// and a recovery's take their number's label, a deleted one's included,
// and a purge's has none.
func TestEventsBeforeTransportNotSent(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	s := w.sender(t, w.members, logs)
	flush(t, s, w.team)
	// The first observe three hours ago, the team named two hours ago, and
	// an off period from 50 to 40 minutes ago.
	w.exec(ctx, t, `UPDATE contract_state SET events_from = clock_timestamp() - interval '3 hours',
		events_off = tstzmultirange(tstzrange(clock_timestamp() - interval '50 minutes', clock_timestamp() - interval '40 minutes'))`)
	w.exec(ctx, t, `UPDATE contract_workspaces SET named_at = clock_timestamp() - interval '2 hours' WHERE workspace_id = $1`, w.team)
	unnamed := uuid.New()
	w.localTeam(t, unnamed, "Piloto A", member{w.owner, "owner", "active"})
	readers := []uuid.UUID{w.sub, w.secondSub}
	types := []string{"deleted", "sync_paused", "recovered", "purged", "moved_out", "stranded"}
	always := func(kind string) bool { return kind == "deleted" || kind == "recovered" || kind == "purged" }
	row := func(r eventRow) uuid.UUID {
		t.Helper()
		if r.actorKind == "" && r.kind == "purged" {
			r.actorKind = "app"
		}
		if r.actorKind != "app" {
			r.actor, r.readers = &w.sub, readers
		}
		return w.event(t, w.team, r)
	}
	var want, never []uuid.UUID
	for _, kind := range types {
		never = append(never, row(eventRow{kind: kind, created: "4 hours"}), row(eventRow{kind: kind, created: "150 minutes"}))
		want = append(want, row(eventRow{kind: kind, created: "1 hour"}))
		if id := row(eventRow{kind: kind, created: "45 minutes"}); always(kind) {
			want = append(want, id)
		} else {
			never = append(never, id)
		}
	}
	// A replayed row as release A's replay writes it (replay.go): the
	// ledger's id and time, no readers and no sub; a deletion with its
	// deleter's local account, a recovery with no actor at all, a purge
	// the app's.
	replay := func(r eventRow) uuid.UUID {
		t.Helper()
		r.created, r.replayed = "0", true
		switch r.kind {
		case "deleted":
			r.user = &w.owner
		case "purged":
			r.actorKind = "app"
		}
		return w.event(t, w.team, r)
	}
	never = append(never, replay(eventRow{kind: "sync_paused", occurred: "30 minutes"}))
	var replayed []uuid.UUID
	for _, kind := range []string{"deleted", "recovered", "purged"} {
		// After the first observe and the naming, in an off period too
		// (Round 2: off periods do not hold these three back).
		ids := []uuid.UUID{replay(eventRow{kind: kind, occurred: "30 minutes"}), replay(eventRow{kind: kind, occurred: "45 minutes"})}
		want, replayed = append(want, ids...), append(replayed, ids...)
		// Before the first observe; after it, before the naming.
		never = append(never, replay(eventRow{kind: kind, occurred: "4 hours"}), replay(eventRow{kind: kind, occurred: "150 minutes"}))
	}
	notNamed := w.event(t, unnamed, eventRow{kind: "deleted", actor: &w.sub, readers: readers})
	if ids, err := w.contract.EventWorkspaces(ctx); err != nil || !slices.Contains(ids, w.team) || slices.Contains(ids, unnamed) {
		t.Fatalf("the queues that owe: %v %v, want the team's and not the unnamed one's", ids, err)
	}
	flush(t, s, w.team)
	if got := idsOf(w.sentTo(w.team)); !slices.Equal(got, want) {
		t.Fatalf("sent %v, want %v", got, want)
	}
	for _, id := range never {
		if d := w.delivery(t, w.team, id); d.settled || d.code != "" {
			t.Errorf("a row never to send was delivered or parked: %+v", d)
		}
	}
	if more, ok := s.send(ctx, unnamed); more || !ok {
		t.Fatalf("the queue of a workspace no document names: more %v, ok %v", more, ok)
	}
	if len(w.sentTo(unnamed)) != 0 || w.delivery(t, unnamed, notNamed).settled {
		t.Fatal("a workspace no document names sent an event")
	}
	for _, id := range want {
		if d := w.delivery(t, w.team, id); d.outcome != store.ContractEventAccepted {
			t.Errorf("a sent row: %+v", d)
		}
	}
	// A replayed row of a number Wappie no longer has: no label; the actor
	// as the ledger left it, never told as one without a sub.
	for _, ev := range w.sentTo(w.team) {
		if !slices.Contains(replayed, uuid.MustParse(ev.EventID)) {
			continue
		}
		var actor string
		if ev.Actor != nil {
			actor = *ev.Actor
		}
		ledgered := map[string]string{kc.EventDeleted: w.sub.String(), kc.EventRecovered: "", kc.EventPurged: ""}[ev.Type]
		if ev.Item.Label != nil || ev.Item.Hint != nil || actor != ledgered || (ev.Readers != nil && len(*ev.Readers) != 0) {
			t.Fatalf("a replayed %s rendered: %+v", ev.Type, ev)
		}
	}
	if lines := logs.Lines("actor has no platform sub"); len(lines) != 0 || w.state(t).ErrorClass == store.ContractErrorEventActor {
		t.Fatalf("a replayed row told as an actor without a sub: %v", lines)
	}

	// A restore's replay of a deletion the platform holds already, of a
	// number deleted since: the same event (its id, type, item and time),
	// which comes back duplicate.
	deleted := w.number(t, w.team, "Vendas", 9, w.owner)
	if _, err := store.NewDevices(w.pool).Quarantine(ctx, w.team, w.owner, deleted, nil); err != nil {
		t.Fatal(err)
	}
	flush(t, s, w.team)
	var held uuid.UUID
	var at time.Time
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT event_id, occurred_at FROM item_events WHERE item_id = $1 AND type = 'deleted'`,
			deleted).Scan(&held, &at); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM item_events WHERE event_id = $1`, held)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	replay(eventRow{id: held, kind: "deleted", item: deleted, at: &at})
	// And of its purge, the janitor not yet run: the number's row still
	// there, its label not the purge's.
	replay(eventRow{kind: "purged", item: deleted, occurred: "0"})
	// The ledger keeps no label and no sub: the number's label, read with
	// deleted numbers visible, and the actor's link, at send time.
	batch, err := w.contract.EventBatch(ctx, w.team, kc.MaxEvents)
	if err != nil || len(batch.Events) != 2 {
		t.Fatalf("the replayed deletion's queue: %+v %v", batch, err)
	}
	if ev := EventOf(w.team, batch.Events[0]); ev.Item.Label == nil || *ev.Item.Label != "Vendas" || ev.Item.Hint == nil ||
		ev.Actor == nil || *ev.Actor != w.sub.String() || !ev.OccurredAt.Equal(at) {
		t.Fatalf("the replayed deletion rendered: %+v", ev)
	}
	if ev := EventOf(w.team, batch.Events[1]); ev.Type != kc.EventPurged || ev.Item.Label != nil || ev.Item.Hint != nil {
		t.Fatalf("the replayed purge of a number not yet purged rendered: %+v", ev)
	}
	flush(t, s, w.team)
	if d := w.delivery(t, w.team, held); d.outcome != store.ContractEventDuplicate {
		t.Fatalf("a replayed deletion the platform holds: %+v", d)
	}
	n := 0
	for _, ev := range w.sentTo(w.team) {
		if ev.EventID == held.String() {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the platform holds the deletion %d times", n)
	}

	// TB26's sending clause: what is written while off, then the return to
	// observe.
	if _, err := w.contract.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	gone := uuid.New()
	off := map[string]uuid.UUID{}
	for _, kind := range types {
		r := eventRow{kind: kind}
		if kind == "deleted" || kind == "purged" {
			r.item = gone
		}
		off[kind] = row(r)
	}
	ch, err := w.contract.SetMode(ctx, store.ContractObserve)
	if err != nil || ch.ToSend != 3 || ch.HeldBack != 3 {
		t.Fatalf("the return to observe: %+v %v", ch, err)
	}
	before := len(w.sentTo(w.team))
	flush(t, s, w.team)
	got := idsOf(w.sentTo(w.team)[before:])
	if !slices.Equal(got, []uuid.UUID{off["deleted"], off["recovered"], off["purged"]}) {
		t.Fatalf("sent after the off period %v, want its deletion, recovery and purge, in order", got)
	}
	for _, kind := range []string{"sync_paused", "moved_out", "stranded"} {
		if d := w.delivery(t, w.team, off[kind]); d.settled || d.code != "" {
			t.Fatalf("a %s written while off: %+v", kind, d)
		}
	}
}

// The actor (README 9; the plan's 4.11): a person with no platform sub, a
// key whose creator has none, and a replayed deletion whose deleter is
// such a local account go as actor null with their kind, each logged at
// ERROR once per event and leader however often it is sent, and recorded
// event_actor_unknown for contract status --check; a key with no creator,
// and a replayed recovery, of which the ledger keeps no actor, go as actor
// null with no ERROR.
func TestEventActorWithoutSub(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	local := w.localPerson(t)
	readers := []uuid.UUID{w.sub, w.secondSub}
	faults := []uuid.UUID{
		w.event(t, w.team, eventRow{kind: "deleted", user: &local, readers: readers}),
		w.event(t, w.team, eventRow{kind: "sync_paused", actorKind: "key", user: &local, readers: readers}),
		w.event(t, w.team, eventRow{kind: "deleted", user: &local, replayed: true}),
	}
	quiet := []uuid.UUID{
		w.event(t, w.team, eventRow{kind: "sync_paused", actorKind: "key", readers: readers}),
		w.event(t, w.team, eventRow{kind: "recovered", replayed: true}),
	}
	// The first batch answered 503 (both the client's tries): every event
	// read twice, and sent three times.
	var calls atomic.Int32
	client := w.relay(t, func(r *http.Request, body []byte) *http.Response {
		if calls.Add(1) <= 2 {
			return w.refused(r, http.StatusServiceUnavailable, kc.CodeUnavailable)
		}
		return nil
	})
	logs := &membershiptest.Logs{}
	s := w.sender(t, &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}, logs)
	if _, ok := s.send(ctx, w.team); !ok {
		t.Fatal("the store")
	}
	flush(t, s, w.team)
	if calls.Load() != 3 {
		t.Fatalf("%d batches, want 3", calls.Load())
	}
	kinds := map[uuid.UUID]string{}
	for _, ev := range w.sentTo(w.team) {
		if ev.Actor != nil {
			t.Fatalf("an actor without a sub sent as %s", *ev.Actor)
		}
		kinds[uuid.MustParse(ev.EventID)] = ev.ActorKind
	}
	for i, id := range append(slices.Clone(faults), quiet...) {
		want := []string{"person", "key", "person", "key", "person"}[i]
		if kinds[id] != want {
			t.Fatalf("event %d sent with actor_kind %q, want %q", i, kinds[id], want)
		}
		told := len(logs.Lines("level=ERROR", "actor has no platform sub", id.String()))
		if fault := i < len(faults); (told == 1) != fault || told > 1 {
			t.Fatalf("event %d: %d ERRORs, a fault %v:\n%s", i, told, fault, logs)
		}
	}
	if !strings.Contains(logs.Lines("actor has no platform sub", faults[0].String())[0], "user="+local.String()) {
		t.Fatalf("the ERROR does not name the local account:\n%s", logs)
	}
	if st := w.state(t); st.ErrorClass != store.ContractErrorEventActor {
		t.Fatalf("the ERROR recorded: %q", st.ErrorClass)
	}
}

// TB32 (with TB23's sender clauses): one queue per workspace, each sent in
// its order; a workspace the platform does not know holds only its own
// queue; at most 100 events a batch, and a body under 248 KiB; one sender
// across two processes, the old one silent once its lock is gone, until it
// leads again if it does, and whichever leads next sending; and after an
// outage at the backoff's cap, the first signed feed answer makes every
// queue due at once.
func TestEventQueues(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	// A team the platform names to Wappie, and one it never did (its only
	// member an account Wappie does not follow), which Wappie records.
	big, err := w.fake.AddTeam("Grande", w.sub.String())
	if err != nil {
		t.Fatal(err)
	}
	bigID := uuid.MustParse(big)
	w.localTeam(t, bigID, "Grande", member{w.owner, "owner", "active"})
	w.members.SignIn(ctx, w.sub)
	stranger := uuid.New()
	if _, err := w.fake.AddAccount(stranger.String()); err != nil {
		t.Fatal(err)
	}
	unknown, err := w.fake.AddTeam("Desconhecida", stranger.String())
	if err != nil {
		t.Fatal(err)
	}
	unknownID := uuid.MustParse(unknown)
	w.localTeam(t, unknownID, "Desconhecida", member{w.owner, "owner", "active"})
	w.exec(ctx, t, `INSERT INTO contract_workspaces (workspace_id, kind, named_at) VALUES ($1, 'team', clock_timestamp() - interval '1 minute')`, unknownID)

	readers := []uuid.UUID{w.sub, w.secondSub}
	var order []uuid.UUID
	for range 250 {
		order = append(order, w.event(t, w.team, eventRow{kind: "deleted", actor: &w.sub, readers: readers}))
	}
	var refused []uuid.UUID
	for range 7 {
		refused = append(refused, w.event(t, unknownID, eventRow{kind: "deleted", actor: &w.sub, readers: readers}))
	}
	var crowd []uuid.UUID
	for range 3000 {
		crowd = append(crowd, uuid.New())
	}
	var heavy []uuid.UUID
	for range 5 {
		heavy = append(heavy, w.event(t, bigID, eventRow{kind: "deleted", actor: &w.sub, readers: crowd}))
	}

	key := lockKey(t)
	type process struct {
		count *counting
		logs  *membershiptest.Logs
	}
	var procs []process
	for range 2 {
		c := &counting{}
		client := NewClient(&http.Client{Transport: c}, w.fake.URL, nil)
		if err := client.Use(w.secret, ""); err != nil {
			t.Fatal(err)
		}
		logs := &membershiptest.Logs{}
		c.marks = logs.Logger()
		m := &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
		l := w.leader(m, logs, key)
		l.EventBackoffMin, l.EventBackoffMax = 50*time.Millisecond, 200*time.Millisecond
		run(t, l)
		procs = append(procs, process{c, logs})
	}
	// The fake logs a batch once it has answered it, after it took its
	// events: the wait covers each queue's log too.
	logged := func(ws uuid.UUID) int {
		n := 0
		for _, b := range w.fake.Batches() {
			if b.Workspace == ws.String() && b.Status == http.StatusOK {
				n += b.Events
			}
		}
		return n
	}
	eventually(t, 30*time.Second, "both queues the platform knows sent, and their batches logged", func() bool {
		return len(w.sentTo(w.team)) == len(order) && len(w.sentTo(bigID)) == len(heavy) &&
			logged(w.team) == len(order) && logged(bigID) == len(heavy)
	})
	if got := idsOf(w.sentTo(w.team)); !slices.Equal(got, order) {
		t.Fatal("the team's events left out of their order")
	}
	if got := idsOf(w.sentTo(bigID)); !slices.Equal(got, heavy) {
		t.Fatal("the big team's events left out of their order")
	}
	var plain, crowded []int
	for _, b := range w.fake.Batches() {
		if b.Events > kc.MaxEvents || b.Bytes > 248<<10 {
			t.Fatalf("a batch of %d events, %d bytes", b.Events, b.Bytes)
		}
		switch b.Workspace {
		case w.team.String():
			plain = append(plain, b.Events)
		case big:
			crowded = append(crowded, b.Events)
		}
	}
	if !slices.Equal(plain, []int{100, 100, 50}) || !slices.Equal(crowded, []int{2, 2, 1}) {
		t.Fatalf("batches: %v, of 3000 readers %v", plain, crowded)
	}
	// The workspace the platform does not know: its queue backs off, alone.
	eventually(t, 10*time.Second, "the unknown workspace refused", func() bool {
		q := w.queue(t, unknownID)
		return q.notFound && q.tries > 0 && q.class == "refused:not_found"
	})
	for _, id := range refused {
		if d := w.delivery(t, unknownID, id); d.settled || d.code != "" {
			t.Fatalf("an event of the unknown workspace: %+v", d)
		}
	}
	if q := w.queue(t, w.team); q.tries != 0 || q.class != "" || q.notFound {
		t.Fatalf("the known team's queue: %+v", q)
	}

	// One sender: only the leader sent, never two batches at once.
	if n := w.fake.Most(contracttest.CallEvents); n != 1 {
		t.Fatalf("%d batches at once", n)
	}
	leading := -1
	for i, p := range procs {
		if p.count.events.Load() > 0 {
			if leading >= 0 {
				t.Fatal("both processes sent events")
			}
			leading = i
		}
	}
	if leading < 0 {
		t.Fatal("no process sent events")
	}
	// The leader's lock connection killed: whichever process leads next
	// sends (TB23 pins which), and the old one sends nothing from the loss
	// until it leads again, if it does.
	old := procs[leading]
	pid := w.lockHolder(t, key)
	if _, err := w.pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the old leader stops", func() bool { return len(old.logs.Lines("contract: the leader's lock is lost")) > 0 })
	late := w.event(t, w.team, eventRow{kind: "deleted", actor: &w.sub, readers: readers})
	eventually(t, 10*time.Second, "a leader sends after the takeover", func() bool {
		return w.delivery(t, w.team, late).outcome == store.ContractEventAccepted
	})
	time.Sleep(500 * time.Millisecond)
	if sentAfterLoss(old.logs) {
		t.Fatalf("the old leader sent a batch after its lock went:\n%s", old.logs)
	}

	// An outage with the queue's backoff at its cap (set in the database);
	// then the first signed feed answer brings it back at once.
	w.fake.SetDown(true)
	down := w.event(t, w.team, eventRow{kind: "deleted", actor: &w.sub, readers: readers})
	eventually(t, 10*time.Second, "a failed batch, and a failed feed call", func() bool {
		return w.queue(t, w.team).tries > 0 && w.state(t).FeedError != ""
	})
	w.exec(ctx, t, `UPDATE contract_workspaces SET events_due_at = clock_timestamp() + interval '1 hour', events_tries = 12
		WHERE workspace_id = $1`, w.team)
	time.Sleep(300 * time.Millisecond)
	// The follower's first page after the outage brings the queue back. It
	// comes a long-poll after the last generation notice (any test's, on
	// the database every test shares), which cuts the long-poll in flight:
	// the queue is timed from the leader's own word of that page.
	answered := func() int {
		n := 0
		for _, p := range procs {
			n += len(p.logs.Lines("contract: the feed answers again"))
		}
		return n
	}
	pages := answered()
	w.fake.SetDown(false)
	eventually(t, soon, "the feed's first page after the outage", func() bool { return answered() > pages })
	back := time.Now()
	eventually(t, 10*time.Second, "the queue back with the feed", func() bool {
		return w.delivery(t, w.team, down).outcome == store.ContractEventAccepted
	})
	if took := time.Since(back); took > 5*time.Second {
		t.Fatalf("the queue came back %v after the feed", took)
	}
}

// A queue whose store calls fail (here the platform's answer cannot be
// recorded: a trigger refuses every settle) is due as it was, and the
// leader's sender tries it again only after a backoff of its own, doubled
// up to its cap, not every pass; once the store takes the answer, the
// events are delivered.
func TestEventStoreFailuresBackOff(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	w.exec(ctx, t, `CREATE FUNCTION refuse_settle() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.settled_at IS NOT NULL AND OLD.settled_at IS NULL THEN
				RAISE EXCEPTION 'test: the settle is refused';
			END IF;
			RETURN NEW;
		END $$`)
	w.exec(ctx, t, `CREATE TRIGGER refuse_settle BEFORE UPDATE ON item_events FOR EACH ROW EXECUTE FUNCTION refuse_settle()`)
	row := w.event(t, w.team, eventRow{kind: "deleted", actor: &w.sub, readers: []uuid.UUID{w.sub, w.secondSub}})
	c := &counting{}
	client := NewClient(&http.Client{Transport: c}, w.fake.URL, nil)
	if err := client.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	m := &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
	// The backoff from 20 ms, doubled up to 200 ms.
	run(t, w.leader(m, logs, lockKey(t)))
	eventually(t, 10*time.Second, "the first batch", func() bool { return c.events.Load() > 0 })
	time.Sleep(1500 * time.Millisecond)
	// 20, 40, 80 and 160 ms, then 200 ms: about a dozen in 1.5 s; every
	// pass (20 ms apart) would be over fifty.
	if n := c.events.Load(); n > 16 {
		t.Fatalf("%d batches in 1.5 s while the store fails", n)
	}
	if d := w.delivery(t, w.team, row); d.settled {
		t.Fatalf("settled while the store refuses: %+v", d)
	}
	if len(logs.Lines("level=WARN", "could not record the platform's answer to events")) == 0 {
		t.Fatalf("no WARN for the store's failure:\n%s", logs)
	}
	w.exec(ctx, t, `DROP TRIGGER refuse_settle ON item_events`)
	eventually(t, 5*time.Second, "the events delivered once the store takes the answer", func() bool {
		return w.delivery(t, w.team, row).outcome == store.ContractEventDuplicate
	})
}

// TB32's resend: a signed 503 after the platform kept the batch (both the
// client's tries), then the queue's next try: the same ids again, each
// back duplicate, each kept once.
func TestEventResend(t *testing.T) {
	w := newEventWorld(t)
	readers := []uuid.UUID{w.sub, w.secondSub}
	var rows []uuid.UUID
	for range 3 {
		rows = append(rows, w.event(t, w.team, eventRow{kind: "deleted", actor: &w.sub, readers: readers}))
	}
	var fail atomic.Int32
	fail.Store(2)
	var sent [][]uuid.UUID
	client := w.relay(t, func(r *http.Request, body []byte) *http.Response {
		sent = append(sent, idsOf(batchOf(t, body)))
		if fail.Add(-1) < 0 {
			return nil
		}
		forward(t, r)
		return w.refused(r, http.StatusServiceUnavailable, kc.CodeUnavailable)
	})
	logs := &membershiptest.Logs{}
	s := w.sender(t, &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}, logs)
	if _, ok := s.send(context.Background(), w.team); !ok {
		t.Fatal("the store")
	}
	if q := w.queue(t, w.team); q.tries != 1 || q.due || q.class != "refused:unavailable" {
		t.Fatalf("after a signed 503: %+v", q)
	}
	if d := w.delivery(t, w.team, rows[0]); d.settled {
		t.Fatalf("a row settled on a 503: %+v", d)
	}
	flush(t, s, w.team)
	if len(sent) != 3 || !slices.Equal(sent[0], rows) || !slices.Equal(sent[1], rows) || !slices.Equal(sent[2], rows) {
		t.Fatalf("the batches sent: %v, want %v three times", sent, rows)
	}
	for _, id := range rows {
		if d := w.delivery(t, w.team, id); d.outcome != store.ContractEventDuplicate {
			t.Fatalf("after the resend: %+v", d)
		}
	}
	if got := idsOf(w.sentTo(w.team)); !slices.Equal(got, rows) {
		t.Fatalf("the platform holds %v", got)
	}
	if q := w.queue(t, w.team); q.tries != 0 || !q.due || q.class != "" {
		t.Fatalf("the queue after the answer: %+v", q)
	}
}

// TB33: the platform's verdicts. accepted and duplicate settle; conflict
// and invalid_request park with an ERROR, and so does an event Wappie
// would not send (local_invalid), the queue going on; a day of not_found
// parks the queue's rows, which a document naming the workspace again,
// and separately a restart, send again; a batch refused whole goes again
// one event per call, and only the bad one parks; and an answer whose
// result names another event settles nothing.
func TestEventOutcomes(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	readers := []uuid.UUID{w.sub, w.secondSub}
	deleted := func(ws uuid.UUID, extra ...func(*eventRow)) uuid.UUID {
		t.Helper()
		r := eventRow{kind: "deleted", actor: &w.sub, readers: readers, label: ptr("Vendas")}
		for _, f := range extra {
			f(&r)
		}
		return w.event(t, ws, r)
	}
	logs := &membershiptest.Logs{}
	s := w.sender(t, w.members, logs)
	recorded := func(class string) {
		t.Helper()
		if st, err := w.contract.State(ctx); err != nil || st.ErrorClass != class {
			t.Fatalf("the ERROR recorded: %q (%v), want %q", st.ErrorClass, err, class)
		}
		w.exec(ctx, t, `UPDATE contract_state SET error_class = NULL, error_at = NULL`)
	}
	reset := func(id uuid.UUID, set string) {
		t.Helper()
		if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE item_events SET settled_at = NULL, outcome = NULL`+set+` WHERE event_id = $1`, id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	// accepted, then the same event again: duplicate.
	first := deleted(w.team)
	flush(t, s, w.team)
	if d := w.delivery(t, w.team, first); d.outcome != store.ContractEventAccepted {
		t.Fatalf("accepted: %+v", d)
	}
	reset(first, "")
	flush(t, s, w.team)
	if d := w.delivery(t, w.team, first); d.outcome != store.ContractEventDuplicate {
		t.Fatalf("duplicate: %+v", d)
	}
	// The same id at another time: conflict, parked; the queue goes on.
	reset(first, ", occurred_at = occurred_at + interval '1 second'")
	next := deleted(w.team)
	flush(t, s, w.team)
	if d := w.delivery(t, w.team, first); d.code != store.EventParkedConflict || d.settled {
		t.Fatalf("conflict: %+v", d)
	}
	if d := w.delivery(t, w.team, next); d.outcome != store.ContractEventAccepted {
		t.Fatalf("the queue after a conflict: %+v", d)
	}
	if len(logs.Lines("level=ERROR", "an event is parked", "code=conflict", first.String())) != 1 {
		t.Fatalf("no ERROR for the conflict:\n%s", logs)
	}
	recorded(store.ContractErrorEventParked)
	// An event Wappie would not send (an address for a label), a pause the
	// read folds two more into: parked before the send, its folded rows
	// with it, by that one send; the rest of its batch goes.
	item := uuid.New()
	pausing := func() uuid.UUID {
		t.Helper()
		return w.event(t, w.team, eventRow{kind: "sync_paused", item: item, actor: &w.sub, user: &w.owner, readers: readers,
			label: ptr("vendas@loja.com")})
	}
	bad := pausing()
	folds := []uuid.UUID{pausing(), pausing()}
	good := deleted(w.team)
	if _, ok := s.send(ctx, w.team); !ok {
		t.Fatal("the store")
	}
	for _, id := range append([]uuid.UUID{bad}, folds...) {
		if d := w.delivery(t, w.team, id); d.code != store.EventParkedLocalInvalid || d.settled {
			t.Fatalf("local_invalid, a pause or a row folded into it: %+v", d)
		}
	}
	if d := w.delivery(t, w.team, good); d.outcome != store.ContractEventAccepted {
		t.Fatalf("beside a local_invalid: %+v", d)
	}
	if lines := logs.Lines("level=ERROR", "Wappie would not send it", bad.String()); len(lines) != 1 || strings.Contains(lines[0], "loja") {
		t.Fatalf("the local_invalid ERROR: %v", lines)
	}
	recorded(store.ContractErrorEventParked)

	// invalid_request for one event, in an answer that accepts the other.
	one, two := deleted(w.team), deleted(w.team)
	answers := w.relay(t, func(r *http.Request, body []byte) *http.Response {
		evs := batchOf(t, body)
		var rs []kc.EventResult
		for _, ev := range evs {
			if ev.EventID == two.String() {
				rs = append(rs, kc.EventResult{EventID: ev.EventID, Outcome: kc.OutcomeRejected, Code: ptr(kc.CodeInvalid)})
			} else {
				rs = append(rs, kc.EventResult{EventID: ev.EventID, Outcome: kc.OutcomeAccepted})
			}
		}
		return w.answered(t, r, rs...)
	})
	relayed := w.sender(t, &Members{Client: answers, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}, logs)
	flush(t, relayed, w.team)
	if d := w.delivery(t, w.team, one); d.outcome != store.ContractEventAccepted {
		t.Fatalf("beside an invalid_request: %+v", d)
	}
	if d := w.delivery(t, w.team, two); d.code != store.EventParkedInvalid {
		t.Fatalf("invalid_request: %+v", d)
	}
	recorded(store.ContractErrorEventParked)

	// A batch refused whole: one event per call, only the bad one parks.
	whole := []uuid.UUID{deleted(w.team), deleted(w.team), deleted(w.team)}
	var calls [][]uuid.UUID
	split := w.relay(t, func(r *http.Request, body []byte) *http.Response {
		evs := batchOf(t, body)
		calls = append(calls, idsOf(evs))
		if len(evs) > 1 || evs[0].EventID == whole[1].String() {
			return w.refused(r, http.StatusBadRequest, kc.CodeInvalid)
		}
		return nil
	})
	splitter := w.sender(t, &Members{Client: split, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}, logs)
	flush(t, splitter, w.team)
	if want := [][]uuid.UUID{whole, whole[:1], whole[1:2], whole[2:]}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("the calls: %v, want %v", calls, want)
	}
	if d := w.delivery(t, w.team, whole[1]); d.code != store.EventParkedInvalid {
		t.Fatalf("the bad event of a batch refused whole: %+v", d)
	}
	for _, id := range []uuid.UUID{whole[0], whole[2]} {
		if d := w.delivery(t, w.team, id); d.outcome != store.ContractEventAccepted {
			t.Fatalf("a good event of a batch refused whole: %+v", d)
		}
	}
	if len(logs.Lines("level=ERROR", "refused a batch of events whole")) != 1 {
		t.Fatalf("no ERROR for the batch refused whole:\n%s", logs)
	}
	recorded(store.ContractErrorEventParked)
	// A batch refused whole whose first event alone gets a signed 503: the
	// queue backs off, and the events after it wait with it (README 9: a
	// workspace's in order); its next try sends all three, in order.
	ordered := []uuid.UUID{deleted(w.team), deleted(w.team), deleted(w.team)}
	before := len(w.sentTo(w.team))
	halted := w.relay(t, func(r *http.Request, body []byte) *http.Response {
		evs := batchOf(t, body)
		if len(evs) > 1 {
			return w.refused(r, http.StatusBadRequest, kc.CodeInvalid)
		}
		if evs[0].EventID == ordered[0].String() {
			return w.refused(r, http.StatusServiceUnavailable, kc.CodeUnavailable)
		}
		return nil
	})
	halting := w.sender(t, &Members{Client: halted, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}, logs)
	if _, ok := halting.send(ctx, w.team); !ok {
		t.Fatal("the store")
	}
	if got := w.sentTo(w.team)[before:]; len(got) != 0 {
		t.Fatalf("events after a failed first one were delivered first: %v", idsOf(got))
	}
	if q := w.queue(t, w.team); q.tries != 1 || q.due || q.class != "refused:unavailable" {
		t.Fatalf("the queue after the first event's 503: %+v", q)
	}
	for _, id := range ordered {
		if d := w.delivery(t, w.team, id); d.settled || d.code != "" {
			t.Fatalf("an event of the halted batch: %+v", d)
		}
	}
	recorded(store.ContractErrorEventsRefused)
	flush(t, s, w.team)
	if got := idsOf(w.sentTo(w.team)[before:]); !slices.Equal(got, ordered) {
		t.Fatalf("sent %v after the backoff, want %v", got, ordered)
	}

	// A result naming another event: an unverified answer, nothing settled.
	stray := deleted(w.team)
	strayed := w.relay(t, func(r *http.Request, body []byte) *http.Response {
		var rs []kc.EventResult
		for range batchOf(t, body) {
			rs = append(rs, kc.EventResult{EventID: uuid.NewString(), Outcome: kc.OutcomeAccepted})
		}
		return w.answered(t, r, rs...)
	})
	strays := w.sender(t, &Members{Client: strayed, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}, logs)
	if _, ok := strays.send(ctx, w.team); !ok {
		t.Fatal("the store")
	}
	if d := w.delivery(t, w.team, stray); d.settled || d.code != "" {
		t.Fatalf("an answer naming another event settled: %+v", d)
	}
	if q := w.queue(t, w.team); q.tries != 1 || q.class != "unverified" {
		t.Fatalf("the queue after an unverified answer: %+v", q)
	}
	flush(t, s, w.team)
	if d := w.delivery(t, w.team, stray); d.outcome != store.ContractEventAccepted {
		t.Fatalf("sent again: %+v", d)
	}

	// A day of not_found, in two teams the platform names to nobody that
	// Wappie records; then one named again by a document, the other at a
	// restart.
	stranger := uuid.New()
	if _, err := w.fake.AddAccount(stranger.String()); err != nil {
		t.Fatal(err)
	}
	var teams []uuid.UUID
	parked := map[uuid.UUID][]uuid.UUID{}
	for _, name := range []string{"Renomeada", "Restaurada"} {
		id, err := w.fake.AddTeam(name, stranger.String())
		if err != nil {
			t.Fatal(err)
		}
		team := uuid.MustParse(id)
		teams = append(teams, team)
		w.localTeam(t, team, name, member{w.owner, "owner", "active"})
		// Its snapshots accepted: only the events' not_found makes a name
		// given again bring it back.
		w.exec(ctx, t, `INSERT INTO contract_workspaces (workspace_id, kind, named_at, snapshot_ok_at)
			VALUES ($1, 'team', clock_timestamp() - interval '1 minute', clock_timestamp())`, team)
		parked[team] = []uuid.UUID{deleted(team), deleted(team)}
		if _, ok := s.send(ctx, team); !ok {
			t.Fatal("the store")
		}
		if q := w.queue(t, team); !q.notFound || q.tries != 1 || q.due {
			t.Fatalf("a first not_found: %+v", q)
		}
		w.exec(ctx, t, `UPDATE contract_workspaces SET events_not_found_since = clock_timestamp() - interval '25 hours' WHERE workspace_id = $1`, team)
		if _, ok := s.send(ctx, team); !ok {
			t.Fatal("the store")
		}
		for _, id := range parked[team] {
			if d := w.delivery(t, team, id); d.code != store.EventParkedNotFound {
				t.Fatalf("after a day of not_found: %+v", d)
			}
		}
		if len(logs.Lines("level=ERROR", "the platform has not known it for a day", team.String())) != 1 {
			t.Fatalf("no ERROR for the day of not_found:\n%s", logs)
		}
		recorded(store.ContractErrorEventParked)
		// A row written once parked parks at once.
		late := deleted(team)
		if _, ok := s.send(ctx, team); !ok {
			t.Fatal("the store")
		}
		if d := w.delivery(t, team, late); d.code != store.EventParkedNotFound {
			t.Fatalf("a row after the park: %+v", d)
		}
		parked[team] = append(parked[team], late)
		w.exec(ctx, t, `UPDATE contract_state SET error_class = NULL, error_at = NULL`)
	}
	// Named again: Wappie's held sub joins the first team, and its sign-in's
	// document names it. The release wakes the leader's sender: the parked
	// queue has no due time for the naming to make due.
	listen, err := w.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Release()
	if _, err := listen.Exec(ctx, `LISTEN `+store.ContractEventsChannel); err != nil {
		t.Fatal(err)
	}
	if err := w.fake.SetRole(teams[0].String(), w.sub.String(), kc.RoleMember); err != nil {
		t.Fatal(err)
	}
	w.members.SignIn(ctx, w.sub)
	if q := w.queue(t, teams[0]); q.notFound || !q.due {
		t.Fatalf("named again: %+v", q)
	}
	woken, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = w.backends.Notice(woken, listen.Conn(), store.ContractEventsChannel, teams[0].String())
	cancel()
	if err != nil {
		t.Fatalf("the release woke no sender: %v", err)
	}
	flush(t, s, teams[0])
	for _, id := range parked[teams[0]] {
		if d := w.delivery(t, teams[0], id); d.outcome != store.ContractEventAccepted {
			t.Fatalf("named again, sent again: %+v", d)
		}
	}
	// The second: the platform names it (a PUT Wappie does not store), and a
	// restart releases its rows.
	if err := w.fake.SetRole(teams[1].String(), w.secondSub.String(), kc.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := w.members.Client.Subscribe(ctx, w.secondSub.String()); err != nil {
		t.Fatal(err)
	}
	if d := w.delivery(t, teams[1], parked[teams[1]][0]); d.code != store.EventParkedNotFound {
		t.Fatalf("before the restart: %+v", d)
	}
	st := w.state(t)
	gen := uuid.New()
	if done, err := w.contract.Restart(ctx, st.Generation, st.FeedCursor, &gen, false); err != nil || !done {
		t.Fatalf("the restart: %v %v", done, err)
	}
	flush(t, s, teams[1])
	for _, id := range parked[teams[1]] {
		if d := w.delivery(t, teams[1], id); d.outcome != store.ContractEventAccepted {
			t.Fatalf("after the restart, sent again: %+v", d)
		}
	}

	// Its 29 days spent: parked as expired, with an ERROR; 28 days and 23
	// hours: sent.
	expired := deleted(w.team, func(r *eventRow) { r.occurred = "29 days 1 minute"; r.created = "0" })
	young := deleted(w.team, func(r *eventRow) { r.occurred = "28 days 23 hours"; r.created = "0" })
	flush(t, s, w.team)
	if d := w.delivery(t, w.team, expired); d.code != store.EventParkedExpired {
		t.Fatalf("29 days old: %+v", d)
	}
	if d := w.delivery(t, w.team, young); d.outcome != store.ContractEventAccepted {
		t.Fatalf("28 days old: %+v", d)
	}
	if len(logs.Lines("level=ERROR", "never delivered in their 29 days", expired.String())) != 1 {
		t.Fatalf("no ERROR for the expired event:\n%s", logs)
	}
	recorded(store.ContractErrorEventParked)
}

// The events' bounds (README 3, 9 and 11; the plan's 4.11), pinned with
// literals: a test that reads a constant cannot pin it.
func TestEventBounds(t *testing.T) {
	for name, c := range map[string]struct{ got, want time.Duration }{
		"the first backoff":       {eventBackoffMin, 5 * time.Second},
		"the longest backoff":     {eventBackoffMax, time.Hour},
		"the look at every queue": {eventsScanEvery, 5 * time.Minute},
		"the longest idle":        {eventsIdle, time.Minute},
		"a not_found's day":       {store.ContractEventNotFoundFor, 24 * time.Hour},
		"the expiry":              {store.ContractEventExpiry, 29 * 24 * time.Hour},
	} {
		if c.got != c.want {
			t.Errorf("%s: %v, want %v", name, c.got, c.want)
		}
	}
	if eventsBodyLimit != 248<<10 || eventsBodyLimit >= 256<<10 {
		t.Errorf("a batch's body limit: %d, want 248 KiB, under the call's 256 (README 3)", eventsBodyLimit)
	}
	// A resend at the backoff's cap still comes back duplicate: the
	// platform's inbox holds an event for 30 days (README 11).
	if store.ContractEventExpiry+eventBackoffMax >= 30*24*time.Hour {
		t.Errorf("the expiry %v leaves no room in the platform's 30 days", store.ContractEventExpiry)
	}
}

// The event sender paces its calls (the P3a review): each batch goes at
// least Members.Pace after the one before, timed as the client sends it by
// the turn it went on (counting.pace), with one due queue each in five
// workspaces; and none goes without a turn, nor a turn before its time.
func TestEventsArePaced(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	const pace = 200 * time.Millisecond
	readers := []uuid.UUID{w.sub, w.secondSub}
	for i := range 5 {
		team, err := w.fake.AddTeam(fmt.Sprintf("Equipe %d", i), w.sub.String())
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(team)
		w.localTeam(t, id, fmt.Sprintf("Equipe %d", i), member{w.owner, "owner", "active"})
		w.exec(ctx, t, `INSERT INTO contract_workspaces (workspace_id, kind, named_at) VALUES ($1, 'team', clock_timestamp() - interval '1 minute')`, id)
		w.event(t, id, eventRow{kind: "deleted", actor: &w.sub, readers: readers})
	}
	c := &counting{}
	client := NewClient(&http.Client{Transport: c}, w.fake.URL, nil)
	if err := client.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	m := &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: pace}
	c.pace(m)
	run(t, w.leader(m, logs, lockKey(t)))
	eventuallySteps(t, 30*time.Second, "five batches", 5, func() int { return int(c.events.Load()) })
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kept(t)
	for i := 1; i < len(c.posts); i++ {
		if gap := c.posts[i].Sub(c.posts[i-1]); gap < pace {
			t.Fatalf("batch %d went %v after the one before, under the pace %v", i, gap, pace)
		}
	}
}

// The leader's calls share one pace (the whole-branch review): the round's
// PUTs, the snapshots and the batches of events, all due at once at a
// leader's start, go at most one every Members.Pace between them, so that
// together they stay at a fifth of the platform's 50 a second, as the
// hook's budget counts them. Each is timed as the client sends it by the
// turn it went on (counting.pace); no window of a second holds more than
// one second's worth of turns and the one call each sender may still be
// sending on an earlier turn; and none goes without a turn, nor a turn
// before its time.
func TestTheLeadersCallsShareOnePace(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	const pace = 100 * time.Millisecond
	readers := []uuid.UUID{w.sub, w.secondSub}
	for i := range 6 {
		team, err := w.fake.AddTeam(fmt.Sprintf("Equipe %d", i), w.sub.String())
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(team)
		w.localTeam(t, id, fmt.Sprintf("Equipe %d", i), member{w.owner, "owner", "active"})
		w.exec(ctx, t, `INSERT INTO contract_workspaces (workspace_id, kind, named_at) VALUES ($1, 'team', clock_timestamp() - interval '1 minute')`, id)
		w.event(t, id, eventRow{kind: "deleted", actor: &w.sub, readers: readers})
	}
	// Six people the platform follows no more, as a GET's signed not_found
	// tells (Unfollowed): its feed then carries no document of theirs, so
	// only the round's PUTs bring them back, whether the round or the
	// feed's first page goes first at the leader's start.
	for range 6 {
		_, sub, _ := w.heldAtHome(t)
		if err := w.members.Client.Unsubscribe(ctx, sub.String()); err != nil {
			t.Fatal(err)
		}
		if err := w.contract.Unfollowed(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}
	c := &counting{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%d PUTs of accounts, %d snapshots, %d batches of events", c.accounts.Load(), c.access.Load(), c.events.Load())
		}
	})
	client := NewClient(&http.Client{Transport: c}, w.fake.URL, nil)
	if err := client.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	m := &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: pace}
	c.pace(m)
	run(t, w.leader(m, logs, lockKey(t)))
	eventuallySteps(t, 30*time.Second, "the round, the snapshots and the events", 18, func() int {
		return int(min(c.accounts.Load(), 6) + min(c.access.Load(), 6) + min(c.events.Load(), 6))
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kept(t)
	most := 0
	for i := range c.all {
		n := 0
		for j := i; j < len(c.all) && c.all[j].Sub(c.all[i]) < time.Second; j++ {
			n++
		}
		most = max(most, n)
	}
	// One turn every 100 ms is 10 in a second, and each of the three
	// senders (the round's, the snapshots' and the events') may add one
	// call it sends late on a turn before the window: 13. Three senders
	// each at their own pace would be up to 30.
	if most > 13 {
		t.Fatalf("%d of the leader's calls within a second, at a pace of %v between any two (%d calls in all)", most, pace, len(c.all))
	}
}

// The results matched by position (README 9): one per event, each the
// event's own id or empty, each an outcome README 9 defines.
func TestEventResults(t *testing.T) {
	a, b := uuid.NewString(), uuid.NewString()
	events := []kc.Event{{EventID: a}, {EventID: b}}
	for _, c := range []struct {
		name    string
		results []kc.EventResult
		ok      bool
	}{
		{"accepted and duplicate", []kc.EventResult{{EventID: a, Outcome: "accepted"}, {EventID: b, Outcome: "duplicate"}}, true},
		{"an empty id", []kc.EventResult{{EventID: "", Outcome: "rejected", Code: ptr("invalid_request")}, {EventID: b, Outcome: "accepted"}}, true},
		{"the ids swapped", []kc.EventResult{{EventID: b, Outcome: "accepted"}, {EventID: a, Outcome: "accepted"}}, false},
		{"one short", []kc.EventResult{{EventID: a, Outcome: "accepted"}}, false},
		{"an unknown outcome", []kc.EventResult{{EventID: a, Outcome: "kept"}, {EventID: b, Outcome: "accepted"}}, false},
		{"a rejection with no code", []kc.EventResult{{EventID: a, Outcome: "rejected"}, {EventID: b, Outcome: "accepted"}}, false},
		{"a rejection for a passing fault", []kc.EventResult{{EventID: a, Outcome: "rejected", Code: ptr("unavailable")}, {EventID: b, Outcome: "accepted"}}, false},
	} {
		if _, ok := eventResults(events, c.results); ok != c.ok {
			t.Errorf("%s: %v, want %v", c.name, ok, c.ok)
		}
	}
}

// TB34: ten stops and starts by one actor in an hour send one event with
// the union of their readers, its folded rows unsettled until its signed
// answer; another actor's pause its own; a pause 61 minutes later again,
// one under an hour after a delivered one nothing; a parked pause parks
// its folded rows; and a pause whose only other reader has no sub (an
// unlinked local account) is settled not_sent and sends nothing, as one
// read by a standing service account, which release A records no row for.
func TestPauseCoalescing(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	devices := store.NewDevices(w.pool)
	logs := &membershiptest.Logs{}
	s := w.sender(t, w.members, logs)
	pause := func(device, by uuid.UUID) {
		t.Helper()
		if _, err := devices.Pause(ctx, w.team, device, store.PauseActor{User: by}); err != nil {
			t.Fatal(err)
		}
		if err := devices.SetPaused(ctx, w.team.String(), device.String(), false); err != nil {
			t.Fatal(err)
		}
	}
	pauses := func(device uuid.UUID) []uuid.UUID {
		t.Helper()
		var ids []uuid.UUID
		if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT event_id FROM item_events WHERE item_id = $1 AND type = 'sync_paused' ORDER BY seq`, device)
			if err != nil {
				return err
			}
			ids, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return ids
	}
	// A third reader joins after the third pause.
	third, thirdSub, _ := w.heldAtHome(t)
	w.localTeam(t, w.team, "", member{third, "member", "active"})
	for i := range 10 {
		if i == 3 {
			if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
				return readsTx(ctx, tx, w.team, w.device, third)
			}); err != nil {
				t.Fatal(err)
			}
		}
		pause(w.device, w.owner)
	}
	ten := pauses(w.device)
	if len(ten) != 10 {
		t.Fatalf("%d pauses recorded", len(ten))
	}
	// The platform down: the head and its nine folded rows, none settled.
	w.fake.SetDown(true)
	if _, ok := s.send(ctx, w.team); !ok {
		t.Fatal("the store")
	}
	for _, id := range ten[1:] {
		if d := w.delivery(t, w.team, id); d.settled || d.into == nil || *d.into != ten[0] {
			t.Fatalf("a folded row before the head's answer: %+v", d)
		}
	}
	w.fake.SetDown(false)
	// The head's answer settles its folded rows, in its own transaction.
	if _, ok := s.send(ctx, w.team); !ok {
		t.Fatal("the store")
	}
	for _, id := range ten[1:] {
		if d := w.delivery(t, w.team, id); d.outcome != "coalesced" || *d.into != ten[0] {
			t.Fatalf("a folded row after the head's answer: %+v", d)
		}
	}
	flush(t, s, w.team)
	sent := w.sentTo(w.team)
	if len(sent) != 1 || sent[0].EventID != ten[0].String() || sent[0].Type != kc.EventSyncPaused {
		t.Fatalf("ten pauses sent %d events", len(sent))
	}
	if got, want := *sent[0].Readers, []string{w.sub.String(), w.secondSub.String(), thirdSub.String()}; !sameSet(got, want) {
		t.Fatalf("the readers %v, want the union %v", got, want)
	}
	if d := w.delivery(t, w.team, ten[0]); d.outcome != store.ContractEventAccepted {
		t.Fatalf("the head: %+v", d)
	}
	for _, id := range ten[1:] {
		if d := w.delivery(t, w.team, id); d.outcome != "coalesced" || *d.into != ten[0] {
			t.Fatalf("a folded row after the head's answer: %+v", d)
		}
	}

	// Another actor: its own event.
	pause(w.device, w.second)
	flush(t, s, w.team)
	if sent := w.sentTo(w.team); len(sent) != 2 || *sent[1].Actor != w.secondSub.String() {
		t.Fatalf("another actor's pause: %d events", len(sent))
	}
	// Under an hour after a delivered one: folded into it, nothing sent.
	pause(w.device, w.owner)
	within := pauses(w.device)
	flush(t, s, w.team)
	if d := w.delivery(t, w.team, within[len(within)-1]); len(w.sentTo(w.team)) != 2 || d.outcome != "coalesced" || *d.into != ten[0] {
		t.Fatalf("a pause under an hour after a delivered one: %+v, %d events", d, len(w.sentTo(w.team)))
	}
	// 61 minutes later: sent again.
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE item_events SET occurred_at = occurred_at - interval '61 minutes' WHERE item_id = $1`, w.device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	pause(w.device, w.owner)
	flush(t, s, w.team)
	if sent := w.sentTo(w.team); len(sent) != 3 || *sent[2].Actor != w.sub.String() {
		t.Fatalf("a pause 61 minutes later: %d events", len(sent))
	}

	// A parked pause parks its folded rows with its code.
	other := w.number(t, w.team, "Suporte", 2, w.owner, w.second)
	for range 3 {
		pause(other, w.owner)
	}
	three := pauses(other)
	conflicts := w.relay(t, func(r *http.Request, body []byte) *http.Response {
		var rs []kc.EventResult
		for _, ev := range batchOf(t, body) {
			rs = append(rs, kc.EventResult{EventID: ev.EventID, Outcome: kc.OutcomeRejected, Code: ptr(kc.CodeConflict)})
		}
		return w.answered(t, r, rs...)
	})
	refusing := w.sender(t, &Members{Client: conflicts, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}, logs)
	if _, ok := refusing.send(ctx, w.team); !ok {
		t.Fatal("the store")
	}
	for _, id := range three {
		if d := w.delivery(t, w.team, id); d.code != store.EventParkedConflict || d.settled {
			t.Fatalf("a parked pause's rows: %+v", d)
		}
	}

	// Nobody but the actor with a sub to tell: settled not_sent.
	local := w.localPerson(t)
	w.localTeam(t, w.team, "", member{local, "member", "active"})
	lonely := w.number(t, w.team, "Sozinho", 3, w.owner, local)
	pause(lonely, w.owner)
	before := len(w.sentTo(w.team))
	flush(t, s, w.team)
	if ids := pauses(lonely); len(ids) != 1 || w.delivery(t, w.team, ids[0]).outcome != "not_sent" || len(w.sentTo(w.team)) != before {
		t.Fatalf("a pause only an unlinked account reads: %v", ids)
	}
	// A standing service account is no reader of release A's: no row.
	service := uuid.New()
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role) VALUES ($1, $2, $3, $4, 'service')`,
			service, w.team, service.String()[:8]+"@service.test", random(t, 32)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO workspace_memberships (tenant_id, user_id, role, status) VALUES ($1, $2, 'service', 'active')
			ON CONFLICT DO NOTHING`, w.team, service)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	served := w.number(t, w.team, "Robo", 4, w.owner, service)
	pause(served, w.owner)
	flush(t, s, w.team)
	if ids := pauses(served); len(ids) != 0 || len(w.sentTo(w.team)) != before {
		t.Fatalf("a pause only a service account reads: %v", ids)
	}
}

// README 9's actor is the person behind the act, "for an API key, its
// creator's sub, so the creator counts as the actor": a person's stop and
// one by their key under the hour after it send one item.sync_paused, the
// person's, with the union of the readers.
func TestPauseCoalescingByAKeysCreator(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	devices := store.NewDevices(w.pool)
	logs := &membershiptest.Logs{}
	s := w.sender(t, w.members, logs)
	var key uuid.UUID
	if err := w.pool.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, created_by) VALUES ($1, $2, 'x', $3) RETURNING id`,
		w.team, uuid.NewString()[:8], w.owner).Scan(&key); err != nil {
		t.Fatal(err)
	}
	third, thirdSub, _ := w.heldAtHome(t)
	w.localTeam(t, w.team, "", member{third, "member", "active"})
	for i, by := range []store.PauseActor{{User: w.owner}, {Key: key}} {
		if i == 1 {
			if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
				return readsTx(ctx, tx, w.team, w.device, third)
			}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := devices.Pause(ctx, w.team, w.device, by); err != nil {
			t.Fatal(err)
		}
		if err := devices.SetPaused(ctx, w.team.String(), w.device.String(), false); err != nil {
			t.Fatal(err)
		}
	}
	flush(t, s, w.team)
	sent := w.sentTo(w.team)
	if len(sent) != 1 || sent[0].Type != kc.EventSyncPaused || sent[0].ActorKind != "person" || *sent[0].Actor != w.sub.String() {
		t.Fatalf("a person's pause and their key's: %d events %+v", len(sent), sent)
	}
	if got, want := *sent[0].Readers, []string{w.sub.String(), w.secondSub.String(), thirdSub.String()}; !sameSet(got, want) {
		t.Fatalf("the readers %v, want the union %v", got, want)
	}
}

func sameSet(a, b []string) bool {
	return len(a) == len(b) && !slices.ContainsFunc(a, func(s string) bool { return !slices.Contains(b, s) })
}
