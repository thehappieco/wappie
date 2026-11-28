package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
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
)

// The usage report in the leader (E0 slice 18), on a real database and the
// fake platform.

// usageTimes are the usage sender's timings for the tests.
func usageTimes() UsageConfig {
	return UsageConfig{Every: 100 * time.Millisecond, Floor: time.Hour, Coalesce: 2 * time.Second,
		BackoffMin: 20 * time.Millisecond, BackoffMax: 200 * time.Millisecond, InvalidRetry: time.Second}
}

// usageLeader is w's leader with entitlements observing and usage on.
func (w *world) usageLeader(t *testing.T, logs *membershiptest.Logs, cfg UsageConfig) *Leader {
	t.Helper()
	ec := entTimes()
	ec.Usage = cfg
	l := w.entLeader(t, logs, ec)
	if _, err := w.contract.SetEntUsage(context.Background(), store.UsageOn); err != nil {
		t.Fatal(err)
	}
	return l
}

// reports are the usage reports of ws the fake answered, as it last kept
// or answered one: its usage_seq, or 0 for none.
func (w *world) usageSeq(ws uuid.UUID) int64 {
	u, ok := w.fake.UsageSent(App, ws.String())
	if !ok {
		return 0
	}
	return u.UsageSeq
}

// TestUsageWireVectors: wire-usage.json's reports through the kit's strict
// decoding and ValidateAt, its answers through UsageAnswer, and its intake
// of an open workspace through Wappie's client and the fake.
func TestUsageWireVectors(t *testing.T) {
	var v struct {
		Reports []struct {
			Name  string          `json:"name"`
			Now   int64           `json:"now"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"reports"`
		Answers []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"answers"`
		Intake []struct {
			Name      string          `json:"name"`
			Held      json.RawMessage `json:"held"`
			Mode      string          `json:"mode"`
			Workspace string          `json:"workspace"`
			Value     json.RawMessage `json:"value"`
			Kept      bool            `json:"kept"`
		} `json:"intake"`
	}
	readVectors(t, "wire-usage.json", &v)
	if len(v.Reports) != 44 || len(v.Answers) != 11 || len(v.Intake) != 11 {
		t.Fatalf("%d reports, %d answers, %d intake", len(v.Reports), len(v.Answers), len(v.Intake))
	}
	for _, c := range v.Reports {
		var u kc.Usage
		valid := len(c.Value) <= kc.UsageReportBodyLimit && kc.DecodeStrict(c.Value, &u) == nil && u.ValidateAt(time.Unix(c.Now, 0)) == nil
		if valid != c.Valid {
			t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
		}
	}
	for _, c := range v.Answers {
		var a kc.UsageAnswer
		valid := json.Unmarshal(c.Value, &a) == nil && a.Validate() == nil
		if valid != c.Valid {
			t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
		}
	}
	ran := 0
	for _, c := range v.Intake {
		if c.Workspace != "open" || c.Mode != "keep" {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			w := newWorld(t)
			_, _, home := w.heldAtHome(t)
			put := func(raw json.RawMessage) bool {
				t.Helper()
				raw = bytes.ReplaceAll(raw, []byte(entVectorWorkspace), []byte(home.String()))
				var u kc.Usage
				if err := json.Unmarshal(raw, &u); err != nil {
					t.Fatal(err)
				}
				kept, err := w.members.Client.PutUsage(context.Background(), home.String(), u)
				if err != nil {
					t.Fatal(err)
				}
				return kept
			}
			if len(c.Held) > 0 && string(c.Held) != "null" {
				var held struct {
					Body json.RawMessage `json:"body"`
				}
				if err := json.Unmarshal(c.Held, &held); err != nil {
					t.Fatal(err)
				}
				put(held.Body)
			}
			if kept := put(c.Value); kept != c.Kept {
				t.Fatalf("kept %v, want %v", kept, c.Kept)
			}
		})
	}
	if ran != 7 {
		t.Fatalf("%d intake cases ran", ran)
	}
}

// Every named workspace is reported, an empty one with items []; a
// deletion's notice makes its workspace's next report go at once; the
// report's figures are its measurement's, and it is kept 8 hours.
func TestUsageEmptyWorkspace(t *testing.T) {
	w := newSnapshotWorld(t)
	logs := &membershiptest.Logs{}
	run(t, w.usageLeader(t, logs, usageTimes()))
	eventually(t, soon, "both reports", func() bool { return w.usageSeq(w.home) > 0 && w.usageSeq(w.team) > 0 })
	u, _ := w.fake.UsageSent(App, w.home.String())
	if len(u.Items) != 0 || u.TotalBytes != 0 || u.RuleVersion != store.UsageRule {
		t.Fatalf("the empty workspace's report: %v, %d items", u, len(u.Items))
	}
	reports, err := w.contract.UsageReports(context.Background(), w.home)
	if err != nil || len(reports) == 0 || reports[0].Seq != u.UsageSeq {
		t.Fatalf("the report kept: %d %v", len(reports), err)
	}
	if len(logs.Lines("contract: usage sent", "workspace="+w.home.String(), "rule_version=wappie-storage/1")) == 0 {
		t.Fatalf("no sent line:\n%s", logs.String())
	}
}

// TestUsageCadence: a deletion, recovery, purge or move notice, a crossing
// of the document's cap_bytes, and a usage_after each make a report go
// ahead of the floor's; the 1 % trigger alone is coalesced; a report sent
// past its trigger's deadline is logged late.
func TestUsageCadence(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	d := teamDoc(kc.ModeObserve)
	d.Storage = kc.EntitlementsStorage{QuotaBytes: 1000, AllowanceBytes: 1000, CapBytes: 1050}
	if _, err := w.fake.SetEntitlements(App, w.team.String(), d); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	cfg := usageTimes()
	run(t, w.usageLeader(t, logs, cfg))
	w.applied(t, w.team, 2)
	eventually(t, soon, "the first report", func() bool { return w.usageSeq(w.team) > 0 })
	settle := func() int64 {
		t.Helper()
		var last int64
		eventually(t, soon, "no report due", func() bool {
			last = w.usageSeq(w.team)
			rows, err := w.contract.UsageRows(ctx)
			if err != nil {
				return false
			}
			for _, r := range rows {
				if r.Workspace == w.team && r.DueAt != nil && r.DueAt.Before(time.Now()) {
					return false
				}
			}
			return true
		})
		return last
	}
	// An event's notice.
	before := settle()
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at, purge_after)
			VALUES (uuidv7(), $1, 'deleted', $2, 'deleted:cadence', clock_timestamp(), 'person', clock_timestamp(), clock_timestamp() + interval '30 days')`,
			w.team, w.device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "a report after the event", func() bool { return w.usageSeq(w.team) > before })

	// A crossing of the cap, either way.
	before = settle()
	var archive, object int64
	if err := w.pool.QueryRow(ctx, `SELECT storage_archive_bytes, storage_object_bytes FROM tenants WHERE id = $1`, w.team).
		Scan(&archive, &object); err != nil || archive+object > 1000 {
		t.Fatalf("the team's totals: %d %d %v", archive, object, err)
	}
	set := func(a, o int64) {
		t.Helper()
		if _, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_archive_bytes = $2, storage_object_bytes = $3 WHERE id = $1`, w.team, a, o); err != nil {
			t.Fatal(err)
		}
	}
	// The report sent measures the totals the triggers compare, so the
	// tenant's figures stay consistent with its inventory only through the
	// measurement's sum: a mismatch is logged, and the report is not sent.
	// The crossing is seen all the same: it makes the report due.
	set(2000, 0)
	eventually(t, 5*time.Second, "the crossing made due", func() bool {
		return len(logs.Lines("contract: usage not measured", "workspace="+w.team.String(), "class=mismatch")) > 0 ||
			w.usageSeq(w.team) > before
	})
	set(archive, object)

	// A usage_after later than the last report.
	before = settle()
	d.Requests.UsageAfter = ptr(kc.T(time.Now().UTC().Truncate(time.Microsecond)))
	d.ComputedAt = kc.T(time.Now().UTC().Add(time.Second).Truncate(time.Microsecond))
	if _, err := w.fake.SetEntitlements(App, w.team.String(), d); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "a report after usage_after", func() bool { return w.usageSeq(w.team) > before })
	u, _ := w.fake.UsageSent(App, w.team.String())
	if !u.MeasuredAt.After(d.Requests.UsageAfter.Time) {
		t.Fatalf("the report was measured at %v, not after usage_after %v", u.MeasuredAt, d.Requests.UsageAfter)
	}

	// The 1 % trigger alone waits out the coalescing since the last report.
	rows, err := w.contract.UsageRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Workspace == w.team && (r.PctAfter == nil || r.LastSentAt == nil || r.PctAfter.Sub(*r.LastSentAt) < cfg.Coalesce-time.Second) {
			t.Fatalf("the coalescing after a report: %+v", r)
		}
	}

	// A late report: a crossing made due well past its minute.
	before = settle()
	if err := w.contract.UsageMark(ctx, w.team, store.UsageCrossing, time.Now().Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the late report", func() bool {
		return len(logs.Lines("level=WARN", "contract: usage report late", "workspace="+w.team.String(), "trigger=crossing")) > 0
	})
	eventually(t, 5*time.Second, "the late report recorded", func() bool {
		st, err := w.contract.EntStatus(ctx)
		if err != nil {
			return false
		}
		for _, r := range st.Usage {
			if r.Workspace == w.team && r.LateAt != nil && r.LateTrigger == store.UsageCrossing {
				return true
			}
		}
		return false
	})
	_ = before
}

// With usage off and the follower on, nothing is measured or sent.
func TestUsageSwitchOff(t *testing.T) {
	w := newSnapshotWorld(t)
	logs := &membershiptest.Logs{}
	run(t, w.entLeader(t, logs, entTimes()))
	w.applied(t, w.team, 1)
	time.Sleep(time.Second)
	if n := w.fake.Count(contracttest.CallUsage); n != 0 {
		t.Fatalf("%d usage reports with usage off", n)
	}
	var seqs int
	if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM contract_usage_seq`).Scan(&seqs); err != nil || seqs != 0 {
		t.Fatalf("%d measurements with usage off (%v)", seqs, err)
	}
	if _, err := w.contract.SetEntUsage(context.Background(), store.UsageOn); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "a report once usage is on", func() bool { return w.usageSeq(w.team) > 0 })
	if _, err := w.contract.SetEntUsage(context.Background(), store.UsageOff); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "usage stopped", func() bool { return len(logs.Lines("contract: usage stopped")) > 0 })
	n := w.fake.Count(contracttest.CallUsage)
	time.Sleep(500 * time.Millisecond)
	if w.fake.Count(contracttest.CallUsage) != n {
		t.Fatal("a report after usage off")
	}
}

// A workspace whose GET answered not_found stops being reported until a
// document of it reaches the feed again.
func TestUsageNotFoundStopsAndResumes(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(strings.Join(logs.Lines("contract: "), "\n"))
		}
	})
	run(t, w.usageLeader(t, logs, usageTimes()))
	w.applied(t, w.team, 1)
	eventually(t, soon, "the first report", func() bool { return w.usageSeq(w.team) > 0 })
	// The places the fake counts from Wappie's snapshot publish the team's
	// document again: it settles first, or its next version would resume
	// the workspace (as a document reaching the feed should).
	w.settledDoc(t, w.team)
	// The workspace's GET answers not_found, as for a team closed past its
	// 30 days.
	w.fake.RefuseAlways(contracttest.CallEntitlementsDoc, kc.CodeNotFound)
	if err := w.contract.EntGetDueNow(ctx, w.team); err != nil {
		t.Fatal(err)
	}
	stopped := func() bool {
		st, err := w.contract.EntStatus(ctx)
		if err != nil {
			return false
		}
		for _, r := range st.Usage {
			if r.Workspace == w.team {
				return r.StoppedSince != nil
			}
		}
		return false
	}
	eventually(t, soon, "the workspace stopped", stopped)
	if err := w.contract.UsageMark(ctx, w.team, store.UsageEvent, time.Now()); err != nil {
		t.Fatal(err)
	}
	n := w.usageSeq(w.team)
	time.Sleep(time.Second)
	if w.usageSeq(w.team) != n {
		t.Fatal("a stopped workspace was reported")
	}
	// A document of it reaches the feed again.
	w.fake.RefuseAlways(contracttest.CallEntitlementsDoc, "")
	if _, err := w.fake.SetEntitlements(App, w.team.String(), teamDoc(kc.ModeObserve, kc.SwitchSend)); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "a report after the document", func() bool { return w.usageSeq(w.team) > n })
	if stopped() {
		t.Fatal("still stopped")
	}
}

// Each report of a workspace whose document says closed sends its GET.
func TestUsageClosedSendsGET(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	run(t, w.usageLeader(t, logs, usageTimes()))
	w.applied(t, w.team, 1)
	eventually(t, soon, "the first report", func() bool { return w.usageSeq(w.team) > 0 })
	w.settledDoc(t, w.team)
	if _, err := w.pool.Exec(ctx, `UPDATE contract_ent_docs SET state = 'closed' WHERE workspace_id = $1`, w.team); err != nil {
		t.Fatal(err)
	}
	n := w.fake.Count(contracttest.CallEntitlementsDoc)
	if err := w.contract.UsageMark(ctx, w.team, store.UsageEvent, time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "the GET after the report", func() bool { return w.fake.Count(contracttest.CallEntitlementsDoc) > n })
}

// No figure of a report reaches the log: a JSON handler captures it all,
// and none of the seeded byte values appears.
func TestUsageNeverLogsFigures(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	// A message whose accounted bytes the workspace's totals carry.
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO messages (tenant_id, device_id, seq, wa_id, chat_key, kind, type, source, ts, body_sealed)
			VALUES ($1, $2, 1, 'figure', 'chat', 'message', 'text', 'live', clock_timestamp(), decode(repeat('ab', 12345), 'hex'))`, w.team, w.device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var total int64
	if err := w.pool.QueryRow(ctx, `SELECT storage_archive_bytes + storage_object_bytes FROM tenants WHERE id = $1`, w.team).Scan(&total); err != nil || total == 0 {
		t.Fatalf("the seeded total: %d %v", total, err)
	}
	var buf lockedBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l := w.usageLeader(t, &membershiptest.Logs{}, usageTimes())
	l.Log = logger
	w.members.Log = logger
	run(t, l)
	eventually(t, soon, "the report", func() bool { return w.usageSeq(w.team) > 0 })
	u, _ := w.fake.UsageSent(App, w.team.String())
	if u.TotalBytes != total {
		t.Fatalf("the report's total %d, the workspace's %d", u.TotalBytes, total)
	}
	out := buf.String()
	for _, figure := range []int64{total, u.TotalBytes, u.SharedBytes} {
		if figure > 9 && strings.Contains(out, strconv.FormatInt(figure, 10)) {
			t.Fatalf("a figure %d in the log:\n%s", figure, out)
		}
	}
	for _, it := range u.Items {
		for _, figure := range []int64{it.Bytes, it.RecentBytes, it.FixedBytes, it.UndatedBytes} {
			if figure > 9 && strings.Contains(out, strconv.FormatInt(figure, 10)) {
				t.Fatalf("an item's figure %d in the log:\n%s", figure, out)
			}
		}
	}
	for _, s := range []string{"total_bytes", "recent_bytes", "shared_bytes"} {
		if strings.Contains(out, s) {
			t.Fatalf("the log names %s:\n%s", s, out)
		}
	}
}

// A report is kept at least 8 hours after its measured_at, then pruned.
func TestUsageReportsKept8h(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	if _, err := w.contract.UsageRows(ctx); err != nil {
		t.Fatal(err)
	}
	m, err := w.contract.MeasureUsage(ctx, w.team)
	if err != nil {
		t.Fatal(err)
	}
	old := m
	old.Seq, old.MeasuredAt = m.Seq-1, time.Now().Add(-store.UsageKeep-time.Minute)
	recent := m
	recent.Seq, recent.MeasuredAt = m.Seq-2, time.Now().Add(-store.UsageKeep+time.Minute)
	for _, r := range []store.UsageMeasure{old, recent} {
		if _, err := w.pool.Exec(ctx, `INSERT INTO contract_usage_reports (workspace_id, usage_seq, measured_at, body) VALUES ($1, $2, $3, '{}')`,
			r.Workspace, r.Seq, r.MeasuredAt); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.contract.UsageSent(ctx, m, []byte(`{}`), true, time.Hour, time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	reports, err := w.contract.UsageReports(ctx, w.team)
	if err != nil {
		t.Fatal(err)
	}
	var seqs []int64
	for _, r := range reports {
		seqs = append(seqs, r.Seq)
	}
	if len(seqs) != 2 || seqs[0] != m.Seq || seqs[1] != recent.Seq {
		t.Fatalf("the reports kept: %v (sent %d, recent %d, old %d)", seqs, m.Seq, recent.Seq, old.Seq)
	}
}

// usageRow is ws's usage cadence row.
func (w *world) usageRow(t *testing.T, ws uuid.UUID) store.UsageRow {
	t.Helper()
	rows, err := w.contract.UsageRows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Workspace == ws {
			return r
		}
	}
	t.Fatalf("no usage row of %s", ws)
	return store.UsageRow{}
}

// A report refused invalid_request waits out its park: the trigger that
// made it due, still holding, never brings it forward; and the report was
// kept before its PUT went, with no sent_at, as one whose answer was lost.
func TestUsageRefusedWaitsItsPark(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	cfg := usageTimes()
	cfg.InvalidRetry = 3 * time.Second
	run(t, w.usageLeader(t, logs, cfg))
	eventually(t, soon, "the first report", func() bool { return w.usageSeq(w.team) > 0 })
	first := w.usageSeq(w.team)
	w.fake.RefuseAlways(contracttest.CallUsage, kc.CodeInvalid)
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at, purge_after)
			VALUES (uuidv7(), $1, 'deleted', $2, 'deleted:park', clock_timestamp(), 'person', clock_timestamp(), clock_timestamp() + interval '30 days')`,
			w.team, w.device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	refused := func() int {
		return len(logs.Lines("contract: usage refused", "workspace="+w.team.String(), "code="+kc.CodeInvalid))
	}
	eventually(t, 5*time.Second, "the refused report", func() bool { return refused() > 0 })
	time.Sleep(cfg.InvalidRetry * 2 / 3)
	if n := refused(); n != 1 {
		t.Fatalf("%d refused reports within the park:\n%s", n, strings.Join(logs.Lines("contract: usage"), "\n"))
	}
	reports, err := w.contract.UsageReports(ctx, w.team)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) == 0 || reports[0].Seq <= first || reports[0].SentAt != nil {
		t.Fatalf("the refused report not kept unsent: %d reports, first %d", len(reports), first)
	}
	w.fake.RefuseAlways(contracttest.CallUsage, "")
	eventually(t, 5*time.Second, "the report after the park", func() bool { return w.usageSeq(w.team) > first })
}

// A mark made while a report backs off keeps the backoff's due_at, and
// the trigger's first due time; a zero time marks on the database's clock.
func TestUsageMarkKeepsBackoff(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	c := w.contract
	if _, err := c.UsageRows(ctx); err != nil {
		t.Fatal(err)
	}
	m, err := c.MeasureUsage(ctx, w.team)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UsageSent(ctx, m, []byte(`{}`), true, time.Hour, time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	crossed := time.Now().Add(-2 * time.Minute).UTC().Truncate(time.Microsecond)
	if err := c.UsageMark(ctx, w.team, store.UsageCrossing, crossed); err != nil {
		t.Fatal(err)
	}
	if err := c.UsageFailed(ctx, w.team, "timeout", time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []string{store.UsageCrossing, store.UsageAfter, store.UsageEvent, store.UsagePercent} {
		if err := c.UsageMark(ctx, w.team, trigger, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.UsageMark(ctx, w.team, store.UsageFloor, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	r := w.usageRow(t, w.team)
	if r.DueAt == nil || time.Until(*r.DueAt) < 50*time.Minute || r.DueTrigger != store.UsageCrossing ||
		r.DueFirstAt == nil || !r.DueFirstAt.Equal(crossed) {
		t.Fatalf("the marks within the backoff: %+v", r)
	}
	due, err := c.UsageDue(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range due {
		if d.Workspace == w.team {
			t.Fatal("a report backing off is due")
		}
	}
	// Once the backoff ran out and a report was sent, a mark now is due
	// now.
	if _, err := w.pool.Exec(ctx, `UPDATE contract_usage SET due_at = clock_timestamp() WHERE workspace_id = $1`, w.team); err != nil {
		t.Fatal(err)
	}
	if m, err = c.MeasureUsage(ctx, w.team); err != nil {
		t.Fatal(err)
	}
	if err := c.UsageSent(ctx, m, []byte(`{}`), true, time.Hour, time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.UsageMark(ctx, w.team, store.UsageEvent, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if r := w.usageRow(t, w.team); r.DueTrigger != store.UsageEvent || r.DueAt == nil || r.DueFirstAt == nil || !r.DueAt.Equal(*r.DueFirstAt) {
		t.Fatalf("a mark now: %+v", r)
	}
}

// check marks the 1 % move of a workspace that holds no document from
// 100 MB, and the minute's look at item_events finds an event the last
// report's snapshot did not see, one written before its measured_at.
func TestUsageCheckWithoutDocument(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	c := w.contract
	l := w.leader(w.members, &membershiptest.Logs{}, lockKeyOf(w.world))
	l.Entitlements = entTimes()
	l.Entitlements.Usage = usageTimes()
	u := newEntitlementsWork(l, nil, nil).usage
	if _, err := c.UsageRows(ctx); err != nil {
		t.Fatal(err)
	}
	if r, ok := w.entRow(t, w.team); ok && r.Doc != nil {
		t.Fatalf("the team holds a document: %+v", r)
	}
	m, err := c.MeasureUsage(ctx, w.team)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UsageSent(ctx, m, []byte(`{}`), true, time.Hour, 0, ""); err != nil {
		t.Fatal(err)
	}
	grow := func(by int64) {
		t.Helper()
		if _, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_archive_bytes = storage_archive_bytes + $2 WHERE id = $1`, w.team, by); err != nil {
			t.Fatal(err)
		}
	}
	grow(usagePercentFloor - 1)
	u.check(ctx)
	if r := w.usageRow(t, w.team); r.DueTrigger != store.UsageFloor {
		t.Fatalf("a move under 100 MB: %+v", r)
	}
	grow(1)
	u.check(ctx)
	if r := w.usageRow(t, w.team); r.DueTrigger != store.UsagePercent || r.DueAt == nil || time.Until(*r.DueAt) > time.Minute {
		t.Fatalf("a move of 100 MB: %+v", r)
	}
	grow(-usagePercentFloor)

	// An event written before measured_at, committed after the snapshot.
	r := w.usageRow(t, w.team)
	if found, err := c.UsageEventsSince(ctx, w.team, *r.LastMeasuredAt, r.LastEvents); err != nil || found {
		t.Fatalf("an event before any: %v %v", found, err)
	}
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at, purge_after, created_at)
			VALUES (uuidv7(), $1, 'deleted', $2, 'deleted:missed', clock_timestamp(), 'person', clock_timestamp(), clock_timestamp() + interval '30 days', $3)`,
			w.team, w.device, r.LastMeasuredAt.Add(-time.Minute))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if found, err := c.UsageEventsSince(ctx, w.team, *r.LastMeasuredAt, r.LastEvents); err != nil || !found {
		t.Fatalf("the event the snapshot missed: %v %v", found, err)
	}
	// The next report's snapshot sees it: it is found no more.
	m, err = c.MeasureUsage(ctx, w.team)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Events) != 1 {
		t.Fatalf("the snapshot's events: %v", m.Events)
	}
	if err := c.UsageSent(ctx, m, []byte(`{}`), true, time.Hour, 0, ""); err != nil {
		t.Fatal(err)
	}
	r = w.usageRow(t, w.team)
	if found, err := c.UsageEventsSince(ctx, w.team, *r.LastMeasuredAt, r.LastEvents); err != nil || found {
		t.Fatalf("an event the last report saw: %v %v", found, err)
	}
}

// A report of a workspace no account document names any more asks its
// GET, as one whose document says closed does.
func TestUsageAsksGetUnnamed(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	ask := func() bool {
		t.Helper()
		ok, err := w.contract.UsageAsksGet(ctx, w.team)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if ask() {
		t.Fatal("a named workspace asks its GET")
	}
	if _, err := w.pool.Exec(ctx, `UPDATE contract_accounts SET doc = jsonb_set(doc, '{workspaces}',
		coalesce((SELECT jsonb_agg(x) FROM jsonb_array_elements(doc->'workspaces') x WHERE x->>'id' <> $1::text), '[]'::jsonb))
		WHERE doc IS NOT NULL`, w.team); err != nil {
		t.Fatal(err)
	}
	if !ask() {
		t.Fatal("a workspace no document names asks no GET")
	}
}
