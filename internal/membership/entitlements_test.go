package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
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

// The entitlements part in the leader (E0 slice 17), on a real database
// and the fake platform: it follows the feed in observe, acknowledges,
// sends the GETs, logs what each document would do with ids only, holds an
// enforce document's workspace at observe, and enforces nothing.

// entTimes are the entitlements part's timings for the tests.
func entTimes() EntitlementsConfig {
	return EntitlementsConfig{Wait: 1, BackoffMin: 20 * time.Millisecond, BackoffMax: 200 * time.Millisecond,
		ResetFloor: 300 * time.Millisecond, AckEvery: 100 * time.Millisecond, AckAtLeast: time.Second,
		GetBackoffMin: 20 * time.Millisecond, GetBackoffMax: 200 * time.Millisecond, GetPace: 400 * time.Millisecond,
		TimelineEvery: 100 * time.Millisecond, CapEvery: 100 * time.Millisecond, Idle: 200 * time.Millisecond}
}

// entLeader is w's leader with the entitlements part's cfg, its mode
// observe.
func (w *world) entLeader(t *testing.T, logs *membershiptest.Logs, cfg EntitlementsConfig) *Leader {
	t.Helper()
	if _, err := w.contract.SetEntMode(context.Background(), store.EntObserve, true); err != nil {
		t.Fatal(err)
	}
	l := w.leader(w.members, logs, lockKeyOf(w))
	l.Settings = settingsTimes()
	l.Entitlements = cfg
	return l
}

// entRow is ws's document row, false when none.
func (w *world) entRow(t *testing.T, ws uuid.UUID) (store.EntRow, bool) {
	t.Helper()
	r, ok, err := w.contract.EntRow(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	return r, ok
}

// applied waits for ws's document at version or above.
func (w *world) applied(t *testing.T, ws uuid.UUID, version int64) store.EntRow {
	t.Helper()
	var r store.EntRow
	eventually(t, soon, fmt.Sprintf("%s's document v%d applied", ws, version), func() bool {
		var ok bool
		r, ok = w.entRow(t, ws)
		return ok && r.AppliedAt != nil && r.Version != nil && *r.Version >= version
	})
	return r
}

// teamDoc is a document the fake publishes for the team: the default one,
// with switches as given ("" on).
func teamDoc(mode string, off ...string) kc.EntitlementsDoc {
	d := contracttest.DefaultEntitlementsDoc(App)
	d.Mode = mode
	d.State.Since = kc.T(time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond))
	for _, name := range off {
		switch name {
		case kc.SwitchAPI:
			d.Switches.API = kc.SwitchOff
		case kc.SwitchNewLinks:
			d.Switches.NewLinks = kc.SwitchOff
		case kc.SwitchSync:
			d.Switches.Sync = kc.SwitchOff
		case kc.SwitchSend:
			d.Switches.Send = kc.SwitchOff
		}
	}
	return d
}

// The feed is followed from the leader's start, every named workspace's
// document applied, and the acknowledgement sent through the head.
func TestEntitlementsFollowsAndAcknowledges(t *testing.T) {
	w := newSnapshotWorld(t)
	logs := &membershiptest.Logs{}
	run(t, w.entLeader(t, logs, entTimes()))
	w.applied(t, w.team, 1)
	w.applied(t, w.home, 1)
	eventually(t, soon, "an acknowledgement through the head", func() bool {
		st, err := w.contract.EntState(context.Background())
		if err != nil || st.AckedThrough == nil {
			return false
		}
		acks := w.fake.EntitlementsApplied(App)
		return len(acks) > 0 && acks[len(acks)-1].Through == st.FeedCursor && st.FeedCursor >= 2
	})
	if len(logs.Lines("contract: entitlements applied", "workspace="+w.team.String(), "mode=observe")) == 0 {
		t.Fatalf("no applied line:\n%s", logs.String())
	}
	if most := w.fake.Most(contracttest.CallEntitlements); most != 1 {
		t.Fatalf("%d entitlements feed requests at once", most)
	}
}

// An observe document with every switch off and a timeline whose time
// came changes nothing Wappie enforces: the numbers, the workspace's
// storage figures and capacity stay as they were; the log says what it
// would stop.
func TestEntitlementsObserveEnforcesNothing(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO workspace_capacity (tenant_id, max_devices) VALUES ($1, 3)
			ON CONFLICT (tenant_id) DO UPDATE SET max_devices = 3`, w.team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	dump := func() string {
		var out string
		if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT json_agg(d ORDER BY id)::text FROM devices d) || '|' ||
				(SELECT row(storage_archive_bytes, storage_object_bytes, storage_limit_bytes, storage_paused_at, storage_over_since, status)::text
				   FROM tenants WHERE id = $1) || '|' ||
				(SELECT coalesce(json_agg(c)::text, '') FROM workspace_capacity c WHERE tenant_id = $1)`, w.team).Scan(&out)
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := dump()
	d := teamDoc(kc.ModeObserve, kc.SwitchAPI, kc.SwitchNewLinks, kc.SwitchSync, kc.SwitchSend)
	computed := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Microsecond)
	d.ComputedAt = kc.T(computed)
	d.State.Since = kc.T(computed)
	// Every switch is off already: the step names one all the same, a
	// timeline step being any switch named off.
	d.Timeline = []kc.TimelineStep{{At: kc.T(computed.Add(time.Hour)), Off: []string{kc.SwitchSync}}}
	if _, err := w.fake.SetEntitlements(App, w.team.String(), d); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	run(t, w.entLeader(t, logs, entTimes()))
	w.applied(t, w.team, 2)
	eventually(t, soon, "the step logged", func() bool {
		return len(logs.Lines("contract: entitlements step would fire", "workspace="+w.team.String(), "switch=sync")) > 0
	})
	for _, name := range kc.EntitlementSwitches() {
		if len(logs.Lines("contract: entitlements would stop", "workspace="+w.team.String(), "switch="+name)) == 0 {
			t.Errorf("no would-stop line for %s:\n%s", name, logs.String())
		}
	}
	if after := dump(); after != before {
		t.Fatalf("observe changed what Wappie enforces:\n%s\n%s", before, after)
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(logs.Lines("contract: entitlements step would fire")); n != 1 {
		t.Fatalf("the step logged %d times", n)
	}
}

// An enforce document holds its workspace at observe at once (the brake's
// row, enforce_in_e0, not told), logs one ERROR and records it; nothing is
// enforced. An enforce and expired document with a trim order is stored
// with its order, which is never run.
func TestEntEnforceDocumentBrakedInE0(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	if _, err := w.fake.SetEntitlements(App, w.team.String(), teamDoc(kc.ModeEnforce, kc.SwitchNewLinks)); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	stop := run(t, w.entLeader(t, logs, entTimes()))
	r := w.applied(t, w.team, 2)
	if r.BrakeKind != store.BrakeEnforceInE0 || r.BrakeTold || r.EverEnforceAt == nil || r.Mode != kc.ModeEnforce {
		t.Fatalf("the enforce document's row: %+v", r)
	}
	eventually(t, soon, "the ERROR", func() bool {
		return len(logs.Lines("level=ERROR", "contract: entitlements enforce document held (E0)", "workspace="+w.team.String(),
			"trim_present=false")) > 0
	})
	eventually(t, soon, "the ERROR recorded", func() bool { return w.state(t).ErrorClass == store.ContractErrorEntEnforceInE0 })
	if len(logs.Lines("contract: entitlements would stop", "switch=new_links", "held_at_observe=true")) == 0 {
		t.Fatalf("the held workspace's would-stop line:\n%s", logs.String())
	}

	// An enforce and expired document carrying a trim order: from the
	// vectors' own, under this world's generation and workspace, taken
	// directly once the leader stopped.
	stop()
	gen := *w.state(t).Generation
	raw := vectorDocWithTrim(t)
	raw = bytes.ReplaceAll(raw, []byte(entVectorWorkspace), []byte(w.home.String()))
	raw = bytes.ReplaceAll(raw, []byte(entVectorGeneration), []byte(gen.String()))
	var d kc.EntitlementsDoc
	if err := json.Unmarshal(raw, &d); err != nil || d.Validate() != nil || len(d.Trim) == 0 {
		t.Fatalf("the vector's document: %v %v", err, d.Validate())
	}
	ew := newEntitlementsWork(w.leader(w.members, logs, lockKeyOf(w.world)), nil, nil)
	st, err := w.contract.EntState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	page := kc.EntitlementsFeed{Generation: gen.String(), Head: st.FeedCursor + d.Version, PublishedThrough: kc.T(time.Now()),
		Items: []kc.EntitlementsFeedItem{}, NextAfter: st.FeedCursor}
	// The page is taken directly: the leader's own long-poll is not asked
	// for it.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	members["version"] = json.RawMessage(strconv.FormatInt(st.FeedCursor+1, 10))
	if raw, err = json.Marshal(members); err != nil {
		t.Fatal(err)
	}
	page.Items = append(page.Items, kc.EntitlementsFeedItem{Seq: st.FeedCursor + 1, Doc: raw})
	page.NextAfter, page.Head = st.FeedCursor+1, st.FeedCursor+1
	if err := ew.take(ctx, gen, st.FeedCursor, page); err != nil {
		t.Fatal(err)
	}
	h, ok := w.entRow(t, w.home)
	if !ok || h.BrakeKind != store.BrakeEnforceInE0 || h.State != kc.WorkspaceExpired || !bytes.Equal(h.Doc, raw) {
		t.Fatalf("the trim document's row: %+v", h)
	}
	if len(logs.Lines("contract: entitlements enforce document held (E0)", "workspace="+w.home.String(), "trim_present=true")) == 0 {
		t.Fatalf("no ERROR for the trim document:\n%s", logs.String())
	}
	// Nothing ran: no trim result was ever posted, and no number changed.
	if n := w.fake.Count(contracttest.CallTrimResults); n != 0 {
		t.Fatalf("%d trim results posted", n)
	}
}

// The vectors' ids the documents carry.
const (
	entVectorWorkspace  = "01a034b7-d09c-7121-b7f8-41f210a9244a"
	entVectorGeneration = "0199b1e0-0000-7000-8000-000000000001"
)

// vectorDocWithTrim is the first document of wire-entitlements.json's
// documents that is valid and carries a trim order, as its bytes are.
func vectorDocWithTrim(t *testing.T) []byte {
	t.Helper()
	var v struct {
		Documents []struct {
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"documents"`
	}
	readVectors(t, "wire-entitlements.json", &v)
	for _, c := range v.Documents {
		var d kc.EntitlementsDoc
		if c.Valid && json.Unmarshal(c.Value, &d) == nil && len(d.Trim) > 0 && d.App == App {
			return c.Value
		}
	}
	t.Fatal("no valid document with a trim order in the vectors")
	return nil
}

// A workspace's total crossing its document's cap_bytes logs would stop,
// then would lift, once each, with no figure.
func TestEntitlementsCapCrossingLogged(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	d := teamDoc(kc.ModeObserve)
	d.Storage = kc.EntitlementsStorage{QuotaBytes: 900001, AllowanceBytes: 900001, CapBytes: 945001}
	if _, err := w.fake.SetEntitlements(App, w.team.String(), d); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	cfg := entTimes()
	run(t, w.entLeader(t, logs, cfg))
	w.applied(t, w.team, 2)
	set := func(bytes int64) {
		t.Helper()
		if _, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_archive_bytes = $2, storage_object_bytes = 0 WHERE id = $1`, w.team, bytes); err != nil {
			t.Fatal(err)
		}
	}
	set(945002)
	eventually(t, soon, "would stop", func() bool {
		return len(logs.Lines("contract: entitlements cap would stop", "workspace="+w.team.String(), "direction=up")) == 1
	})
	set(945001)
	eventually(t, soon, "would lift", func() bool {
		return len(logs.Lines("contract: entitlements cap would lift", "workspace="+w.team.String(), "direction=down")) == 1
	})
	time.Sleep(5 * cfg.CapEvery)
	if len(logs.Lines("cap would stop")) != 1 || len(logs.Lines("cap would lift")) != 1 {
		t.Fatalf("a crossing logged more than once:\n%s", logs.String())
	}
	for _, figure := range []string{"945001", "945002", "900001"} {
		if strings.Contains(logs.String(), figure) {
			t.Fatalf("a figure %s in the log", figure)
		}
	}
}

// The acknowledgement goes at once after a switch changed, and otherwise
// at most once every AckEvery and at least once every AckAtLeast.
func TestEntitlementsAckCadence(t *testing.T) {
	w := newSnapshotWorld(t)
	var mu sync.Mutex
	var at []time.Time
	w.fake.Before(contracttest.CallEntitlementsApplied, func(string) {
		mu.Lock()
		defer mu.Unlock()
		at = append(at, time.Now())
	})
	cfg := entTimes()
	cfg.AckEvery, cfg.AckAtLeast = 700*time.Millisecond, 1500*time.Millisecond
	logs := &membershiptest.Logs{}
	run(t, w.entLeader(t, logs, cfg))
	w.applied(t, w.team, 1)
	time.Sleep(4 * time.Second)
	mu.Lock()
	quiet := append([]time.Time(nil), at...)
	mu.Unlock()
	if len(quiet) < 3 {
		t.Fatalf("%d acknowledgements in a quiet feed", len(quiet))
	}
	for i := 1; i < len(quiet); i++ {
		gap := quiet[i].Sub(quiet[i-1])
		if gap > cfg.AckAtLeast+time.Second {
			t.Fatalf("%v between two acknowledgements, past the minute's bound", gap)
		}
	}
	// A switch changed: at once, sooner than AckEvery after the last.
	mu.Lock()
	n := len(at)
	mu.Unlock()
	changed := time.Now()
	if _, err := w.fake.SetEntitlements(App, w.team.String(), teamDoc(kc.ModeObserve, kc.SwitchSend)); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "the urgent acknowledgement", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(at) > n && at[len(at)-1].After(changed)
	})
	mu.Lock()
	first := at[n]
	mu.Unlock()
	if d := first.Sub(changed); d > cfg.AckAtLeast {
		t.Fatalf("the urgent acknowledgement came %v after the change", d)
	}
}

// A bad document of a workspace is refused alone: listed in the next
// acknowledgement, that workspace's GET sent once, the cursor past it.
func TestEntitlementsBadDocumentGETOnce(t *testing.T) {
	w := newSnapshotWorld(t)
	logs := &membershiptest.Logs{}
	var mu sync.Mutex
	gets := map[string]int{}
	w.fake.Before(contracttest.CallEntitlementsDoc, func(ws string) {
		mu.Lock()
		defer mu.Unlock()
		gets[ws]++
	})
	run(t, w.entLeader(t, logs, entTimes()))
	w.applied(t, w.team, 1)
	w.applied(t, w.home, 1)
	w.settledDoc(t, w.team)
	w.settledDoc(t, w.home)
	eventually(t, soon, "no GET due", func() bool {
		due, err := w.contract.EntGetsDue(context.Background(), 10)
		return err == nil && len(due) == 0
	})
	mu.Lock()
	before := gets[w.team.String()]
	mu.Unlock()
	seq, err := w.fake.PublishRawEntitlements(App, w.team.String(), json.RawMessage(`{"v":1,"workspace_id":"`+w.team.String()+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "the refusal acknowledged", func() bool {
		for _, a := range w.fake.EntitlementsApplied(App) {
			for _, r := range a.Refused {
				if r.Seq == seq && r.Code == kc.RefusedInvalidDocument && r.WorkspaceID != nil && *r.WorkspaceID == w.team.String() {
					return true
				}
			}
		}
		return false
	})
	eventually(t, soon, "the GET", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gets[w.team.String()] == before+1
	})
	time.Sleep(time.Second)
	mu.Lock()
	defer mu.Unlock()
	if gets[w.team.String()] != before+1 {
		t.Fatalf("%d GETs after one bad document", gets[w.team.String()]-before)
	}
	if len(logs.Lines("level=WARN", "contract: entitlements document refused", "seq="+strconv.FormatInt(seq, 10), "code=invalid_document")) == 0 {
		t.Fatalf("no refused line:\n%s", logs.String())
	}
}

// A bad document whose workspace_id cannot be read holds every kept
// workspace back: each gets its GET, at most one every GetPace.
func TestEntitlementsUnreadableWorkspaceGETsPaced(t *testing.T) {
	w := newSnapshotWorld(t)
	logs := &membershiptest.Logs{}
	var mu sync.Mutex
	var at []time.Time
	cfg := entTimes()
	run(t, w.entLeader(t, logs, cfg))
	w.applied(t, w.team, 1)
	w.applied(t, w.home, 1)
	w.settledDoc(t, w.team)
	w.settledDoc(t, w.home)
	// Only the GETs the bad document made due: none was due before it.
	eventually(t, soon, "no GET due", func() bool {
		due, err := w.contract.EntGetsDue(context.Background(), 10)
		return err == nil && len(due) == 0
	})
	w.fake.Before(contracttest.CallEntitlementsDoc, func(string) {
		mu.Lock()
		defer mu.Unlock()
		at = append(at, time.Now())
	})
	if _, err := w.fake.PublishRawEntitlements(App, uuid.NewString(), json.RawMessage(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "both GETs", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(at) >= 2
	})
	mu.Lock()
	defer mu.Unlock()
	if gap := at[1].Sub(at[0]); gap < cfg.GetPace-50*time.Millisecond {
		t.Fatalf("two GETs %v apart, under the pace %v", gap, cfg.GetPace)
	}
	for _, ws := range []uuid.UUID{w.team, w.home} {
		eventually(t, soon, "the hold released by its GET", func() bool {
			r, _ := w.entRow(t, ws)
			return !r.FeedHeldBack && r.GetFreshAt != nil
		})
	}
}

// A signed not_found on a named workspace's GET keeps its last document,
// frozen, and asks no more.
func TestEntitlementsNotFoundFreezes(t *testing.T) {
	w := newSnapshotWorld(t)
	logs := &membershiptest.Logs{}
	run(t, w.entLeader(t, logs, entTimes()))
	w.applied(t, w.team, 1)
	w.settledDoc(t, w.team)
	r, _ := w.entRow(t, w.team)
	w.fake.RefuseAlways(contracttest.CallEntitlementsDoc, kc.CodeNotFound)
	if _, err := w.fake.PublishRawEntitlements(App, w.team.String(), json.RawMessage(`{"v":1,"workspace_id":"`+w.team.String()+`"}`)); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "the not_found", func() bool {
		got, _ := w.entRow(t, w.team)
		return got.NotFoundSince != nil
	})
	got, _ := w.entRow(t, w.team)
	if !bytes.Equal(got.Doc, r.Doc) || got.GetDueAt != nil || *got.Version != *r.Version {
		t.Fatalf("after a not_found: %+v", got)
	}
	n := w.fake.Count(contracttest.CallEntitlementsDoc)
	time.Sleep(time.Second)
	if w.fake.Count(contracttest.CallEntitlementsDoc) != n {
		t.Fatal("a GET after a not_found on a named workspace")
	}
	if len(logs.Lines("contract: entitlements not_found", "workspace="+w.team.String())) == 0 {
		t.Fatalf("no not_found line:\n%s", logs.String())
	}
}

// A generation notice cuts the long-poll in flight: the next request goes
// at once, not after the wait.
func TestEntitlementsGenerationNoticeCutsPoll(t *testing.T) {
	w := newSnapshotWorld(t)
	var mu sync.Mutex
	var at []time.Time
	w.fake.Before(contracttest.CallEntitlements, func(string) {
		mu.Lock()
		defer mu.Unlock()
		at = append(at, time.Now())
	})
	cfg := entTimes()
	cfg.Wait = 20
	logs := &membershiptest.Logs{}
	run(t, w.entLeader(t, logs, cfg))
	w.applied(t, w.team, 1)
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	n := len(at)
	mu.Unlock()
	cut := time.Now()
	if _, err := w.pool.Exec(context.Background(), `SELECT pg_notify($1, 'generation')`, store.ContractModeChannel); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "a request after the notice", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(at) > n && at[len(at)-1].After(cut)
	})
}

// Two resets within the floor: the second waits it out, logs one ERROR and
// records it.
func TestEntitlementsResetLoopFloor(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	l := w.leader(w.members, logs, lockKeyOf(w.world))
	l.Entitlements = entTimes()
	ew := newEntitlementsWork(l, nil, nil)
	gen := *w.state(t).Generation
	next := uuid.New()
	if done, err := ew.reset(ctx, gen, &next, "test"); err != nil || !done {
		t.Fatalf("the first reset: %v %v", done, err)
	}
	start := time.Now()
	third := uuid.New()
	if done, err := ew.reset(ctx, next, &third, "test"); err != nil || !done {
		t.Fatalf("the second reset: %v %v", done, err)
	}
	if took := time.Since(start); took < 200*time.Millisecond {
		t.Fatalf("the second reset waited %v, under the floor", took)
	}
	if len(logs.Lines("level=ERROR", "contract: a second reset from the entitlements feed within a minute waits")) != 1 {
		t.Fatalf("the floor's ERROR:\n%s", logs.String())
	}
	if st := w.state(t); st.ErrorClass != store.ContractErrorEntResetLoop {
		t.Fatalf("the ERROR recorded: %q", st.ErrorClass)
	}
}

// Every line the part logs, through a JSON handler, holds ids, enums and
// times only: no member of a document but those, and no figure.
func TestEntitlementsLogsIDsOnly(t *testing.T) {
	w := newSnapshotWorld(t)
	var buf lockedBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := teamDoc(kc.ModeEnforce, kc.SwitchSync)
	d.Storage = kc.EntitlementsStorage{QuotaBytes: 98765432101, AllowanceBytes: 98765432101, CapBytes: 87654321012,
		UsedBytes: ptr(int64(76543210123)), MeasuredThrough: ptr(kc.T(time.Now().Add(-time.Hour)))}
	d.Links = kc.EntitlementsLinks{Plan: "https://console.thehappie.co/secret-plan-link", Storage: "https://console.thehappie.co/secret-storage-link"}
	if _, err := w.fake.SetEntitlements(App, w.team.String(), d); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(context.Background(), `UPDATE tenants SET storage_archive_bytes = 87654321999 WHERE id = $1`, w.team); err != nil {
		t.Fatal(err)
	}
	l := w.entLeader(t, &membershiptest.Logs{}, entTimes())
	l.Log = logger
	w.members.Log = logger
	run(t, l)
	w.applied(t, w.team, 2)
	eventually(t, soon, "the cap's line", func() bool { return strings.Contains(buf.String(), "cap would stop") })
	out := buf.String()
	for _, s := range []string{"98765432101", "87654321012", "76543210123", "87654321999", "secret-plan-link", "secret-storage-link",
		"quota_bytes", "cap_bytes", "\"storage\"", "\"switches\""} {
		if strings.Contains(out, s) {
			t.Fatalf("the log holds %q:\n%s", s, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("a line that is no JSON: %q", line)
		}
		for k, v := range m {
			if _, nested := v.(map[string]any); nested {
				t.Fatalf("a group %q in %q: a struct logged whole", k, line)
			}
		}
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// settledDoc waits until ws's snapshot is settled and the fake's latest
// document of it is the one applied: the places the fake counts from
// Wappie's snapshot publish a workspace's document again, and a test that
// writes a document's row must not race that next version.
func (w *snapshotWorld) settledDoc(t *testing.T, ws uuid.UUID) {
	t.Helper()
	w.settle(t, ws)
	eventually(t, soon, "the latest document applied", func() bool {
		d, ok := w.fake.Entitlements(App, ws.String())
		r, held := w.entRow(t, ws)
		return ok && held && r.Version != nil && *r.Version == d.Version
	})
}

// entWork is an entitlements part of w's leader that does not run: a test
// calls its passes directly.
func (w *snapshotWorld) entWork(logs *membershiptest.Logs) *entitlementsWork {
	l := w.leader(w.members, logs, lockKeyOf(w.world))
	l.Entitlements = entTimes()
	return newEntitlementsWork(l, nil, nil)
}

// While the account side holds no generation (after a signed gone), no GET
// goes: its answer could only ask for a reset.
func TestEntitlementsGETWaitsWithoutGeneration(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	ew := w.entWork(&membershiptest.Logs{})
	gen := w.state(t).Generation
	if gen == nil {
		t.Fatal("no generation")
	}
	if ok, err := w.contract.RestartFromEntitlements(ctx, *gen, nil); err != nil || !ok {
		t.Fatalf("the reset to none: %v %v", ok, err)
	}
	due, err := w.contract.EntGetsDue(ctx, 10)
	if err != nil || len(due) == 0 {
		t.Fatalf("no GET due after the reset: %v", err)
	}
	n := w.fake.Count(contracttest.CallEntitlementsDoc)
	loop, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	ew.getLoop(loop)
	if got := w.fake.Count(contracttest.CallEntitlementsDoc) - n; got != 0 {
		t.Fatalf("%d GETs with no generation", got)
	}
}

// A GET's answer of the generation it went under, which a reset replaced
// while it was in flight, is dropped: the reset is never taken back.
func TestEntitlementsLateGETAnswerKeepsReset(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	ew := w.entWork(logs)
	if _, err := w.fake.SetEntitlements(App, w.team.String(), teamDoc(kc.ModeObserve)); err != nil {
		t.Fatal(err)
	}
	gen := *w.state(t).Generation
	other := uuid.New()
	if ok, err := w.contract.RestartFromEntitlements(ctx, gen, &other); err != nil || !ok {
		t.Fatalf("the reset meanwhile: %v %v", ok, err)
	}
	if !ew.get(ctx, store.EntGetDue{Workspace: w.team}, gen) {
		t.Fatal("ctx ended")
	}
	if now := w.state(t).Generation; now == nil || *now != other {
		t.Fatalf("the generation after a late answer: %v, want %s", now, other)
	}
	if len(logs.Lines("the platform's generation changed")) != 0 {
		t.Fatalf("a reset from a late answer:\n%s", logs.String())
	}
	if r, ok := w.entRow(t, w.team); !ok || r.GetDueAt == nil {
		t.Fatalf("the GET not left due: %+v", r)
	}
}

// A GET that answers enforce holds its workspace at observe, as a feed
// document does, and the would-stop and cap lines carry the marker.
func TestEntitlementsGETEnforceBraked(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	ew := w.entWork(logs)
	d := teamDoc(kc.ModeEnforce, kc.SwitchNewLinks)
	d.Storage = kc.EntitlementsStorage{QuotaBytes: 900001, AllowanceBytes: 900001, CapBytes: 945001}
	if _, err := w.fake.SetEntitlements(App, w.team.String(), d); err != nil {
		t.Fatal(err)
	}
	if !ew.get(ctx, store.EntGetDue{Workspace: w.team}, *w.state(t).Generation) {
		t.Fatal("ctx ended")
	}
	r, ok := w.entRow(t, w.team)
	if !ok || r.BrakeKind != store.BrakeEnforceInE0 || r.BrakeTold || r.Mode != kc.ModeEnforce || r.AppliedAt == nil {
		t.Fatalf("the GET's enforce document: %+v", r)
	}
	for _, want := range [][]string{
		{"level=ERROR", "contract: entitlements enforce document held (E0)", "workspace=" + w.team.String()},
		{"contract: entitlements applied", "seq=get", "workspace=" + w.team.String(), "mode=enforce", "held_at_observe=true"},
		{"contract: entitlements would stop", "switch=new_links", "held_at_observe=true"},
	} {
		if len(logs.Lines(want...)) == 0 {
			t.Fatalf("no line %q:\n%s", want, logs.String())
		}
	}
	if st := w.state(t); st.ErrorClass != store.ContractErrorEntEnforceInE0 {
		t.Fatalf("the ERROR recorded: %q", st.ErrorClass)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_archive_bytes = 945002, storage_object_bytes = 0 WHERE id = $1`, w.team); err != nil {
		t.Fatal(err)
	}
	ew.checkCaps(ctx)
	if len(logs.Lines("contract: entitlements cap would stop", "workspace="+w.team.String(), "held_at_observe=true")) != 1 {
		t.Fatalf("the held workspace's cap line:\n%s", logs.String())
	}
}
