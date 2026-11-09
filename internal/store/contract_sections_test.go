package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The numbers section (0052; the plan's 2.5, 2.6, 2.8 and 3.5): what it
// reads of each number and registration, who paused, can_link, its seq on
// the workspace's one clock beside the snapshot's, and its sender's state.

// recordLocal records w's workspace as a platform team, with a snapshot
// numbered, as the leader's sender leaves one: a section names it.
func (w *delWorld) recordLocal(t *testing.T, c *store.Contract) {
	t.Helper()
	ctx := context.Background()
	if _, err := w.pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, w.tenant); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.SnapshotSeq(ctx, w.tenant, time.Now()); err != nil || !ok {
		t.Fatalf("the snapshot's seq: %v %v", ok, err)
	}
}

func (w *delWorld) numbers(ctx context.Context, t *testing.T, c *store.Contract) store.ContractNumbers {
	t.Helper()
	n, ok, err := c.NumbersOf(ctx, w.tenant)
	if err != nil || !ok {
		t.Fatalf("the numbers: %v %v", ok, err)
	}
	return n
}

func itemOf(n store.ContractNumbers, id uuid.UUID) (store.ContractNumber, bool) {
	for _, it := range n.Items {
		if it.ID == id {
			return it, true
		}
	}
	return store.ContractNumber{}, false
}

// TestNumbersOf: every input a numbers row is drawn from, for every
// connection a number can be in, and who paused it.
func TestNumbersOf(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	sessionStore(t, w.pool)
	c := store.NewContract(w.pool)
	w.recordLocal(t, c)
	ownerSub := linkSub(t, w.pool, w.owner)
	reader := w.person(t, "reader", "member")
	creator := w.person(t, "creator", "admin")
	creatorSub := linkSub(t, w.pool, creator)
	status := func(d uuid.UUID, s wa.Status, reason string) {
		t.Helper()
		if err := w.devices.SetStatus(ctx, w.tenant.String(), d.String(), s, reason); err != nil {
			t.Fatal(err)
		}
	}

	online, offline, pairing, banned := w.number(t, "online"), w.number(t, "offline"), w.number(t, "pairing"), w.number(t, "banned")
	status(offline, wa.StatusOffline, "")
	status(pairing, wa.StatusPairing, "")
	status(banned, wa.StatusBanned, "temporary")
	phone := w.number(t, "phone")
	status(phone, wa.StatusLoggedOut, "unlinked (logged out from the phone)")
	deleted := w.number(t, "deleted")
	w.quarantine(t, deleted)
	purging := w.number(t, "purging")
	w.quarantine(t, purging)
	w.scoped(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET purge_started_at = clock_timestamp() WHERE id = $1`, purging)
		return err
	})

	// Who paused: a person who told a reader, a key's creator, a pause
	// that told nobody, a second stop by another, a move, a recovery.
	byPerson, byKey, silent, twice, moved, recovered := w.number(t, "person"), w.number(t, "key"), w.number(t, "silent"),
		w.number(t, "twice"), w.number(t, "moved"), w.number(t, "recovered")
	for _, d := range []uuid.UUID{byPerson, byKey, twice} {
		w.reads(t, reader, d)
	}
	if _, err := w.devices.Pause(ctx, w.tenant, byPerson, store.PauseActor{User: w.owner}); err != nil {
		t.Fatal(err)
	}
	key, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "creator's", store.ScopeFull, &creator, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.Pause(ctx, w.tenant, byKey, store.PauseActor{Key: w.keyID(ctx, t, key)}); err != nil {
		t.Fatal(err)
	}
	if p, err := w.devices.Pause(ctx, w.tenant, silent, store.PauseActor{User: w.owner}); err != nil || p.Recorded {
		t.Fatalf("a pause that tells nobody: %+v %v", p, err)
	}
	if _, err := w.devices.Pause(ctx, w.tenant, twice, store.PauseActor{User: w.owner}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.Pause(ctx, w.tenant, twice, store.PauseActor{User: creator}); err != nil {
		t.Fatal(err)
	}
	w.execOne(t, `UPDATE devices SET paused = true, pause_cause = 'move', pause_seq = pause_seq + 1 WHERE id = $1`, moved)
	w.quarantine(t, recovered)
	w.recover(t, recovered)
	w.execOne(t, `UPDATE devices SET current_epoch = 3 WHERE id = $1`, online)

	n := w.numbers(ctx, t, c)
	if !n.Local || n.Seq <= n.SnapshotSeq || n.MeasuredAt.IsZero() || n.Over() || !n.CanLink || n.StoragePaused {
		t.Fatalf("the section: %+v", n)
	}
	type want struct {
		status, logout, cause string
		deleted, paused       bool
		recovery              bool
		kind                  string
		sub                   *uuid.UUID
	}
	for name, c := range map[string]struct {
		id uuid.UUID
		want
	}{
		"online":              {online, want{status: "online"}},
		"offline":             {offline, want{status: "offline"}},
		"pairing":             {pairing, want{status: "pairing"}},
		"banned":              {banned, want{status: "banned"}},
		"the phone's logout":  {phone, want{status: "logged_out", logout: "phone"}},
		"deleted":             {deleted, want{status: "logged_out", logout: "deletion", cause: "deletion", deleted: true, paused: true, recovery: true, kind: "app"}},
		"its purge started":   {purging, want{status: "logged_out", logout: "deletion", cause: "deletion", deleted: true, paused: true, kind: "app"}},
		"a person's pause":    {byPerson, want{status: "online", cause: "person", paused: true, kind: "person", sub: &ownerSub}},
		"a key's pause":       {byKey, want{status: "online", cause: "person", paused: true, kind: "key", sub: &creatorSub}},
		"a pause told nobody": {silent, want{status: "online", cause: "person", paused: true}},
		"a second stop":       {twice, want{status: "online", cause: "person", paused: true, kind: "person", sub: &ownerSub}},
		"a move's pause":      {moved, want{status: "online", cause: "move", paused: true, kind: "app"}},
		"a recovery":          {recovered, want{status: "logged_out", logout: "deletion", cause: "person", paused: true, kind: "person", sub: &ownerSub}},
	} {
		it, ok := itemOf(n, c.id)
		if !ok {
			t.Errorf("%s: no row", name)
			continue
		}
		subOK := (it.PausedBySub == nil) == (c.sub == nil) && (c.sub == nil || *it.PausedBySub == *c.sub)
		if it.Status != c.status || it.LogoutCause != c.logout || it.PauseCause != c.cause || it.Deleted != c.deleted ||
			it.Paused != c.paused || it.RecoveryOpen != c.recovery || it.PausedByKind != c.kind || !subOK || !it.Known {
			t.Errorf("%s: %+v, want %+v", name, it, c.want)
		}
		// Never an actor with no time, and a pause always has its time.
		if (it.PausedByKind != "" && it.PausedAt == nil) || (it.Paused && it.PausedAt == nil) {
			t.Errorf("%s: an actor or a pause with no time: %+v", name, it)
		}
	}
	if it, _ := itemOf(n, online); it.Epoch != 3 || it.LastConnectedAt == nil {
		t.Fatalf("the epoch and the connection time: %+v", it)
	}

	// Pending registrations: newest first, no identity, never connected,
	// not deleted; past 50, the list is cut and says so.
	var pending []uuid.UUID
	for i := range 3 {
		d, err := w.devices.Create(ctx, w.tenant.String(), "new", wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		pending = append(pending, uuid.MustParse(d.ID))
		if i == 1 {
			w.execOne(t, `UPDATE devices SET paused = true WHERE id = $1`, uuid.MustParse(d.ID))
		}
	}
	n = w.numbers(ctx, t, c)
	if len(n.Pending) != 3 || n.Pending[0].ID != pending[2] || !n.Pending[1].Paused || n.Pending[0].Paused {
		t.Fatalf("the pending registrations: %+v", n.Pending)
	}
	for _, p := range pending {
		if _, ok := itemOf(n, p); ok {
			t.Fatal("a registration is a number")
		}
	}
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO devices (tenant_id, label) SELECT $1, 'more' FROM generate_series(1, 47)`, w.tenant)
		return err
	})
	if n = w.numbers(ctx, t, c); len(n.Pending) != store.NumbersMaxPending || n.PendingOver || n.ItemsOver {
		t.Fatalf("50 pending: %d, over %v", len(n.Pending), n.PendingOver)
	}
	if _, err := w.devices.Create(ctx, w.tenant.String(), "one more", wa.ModePassive); err != nil {
		t.Fatal(err)
	}
	if n = w.numbers(ctx, t, c); len(n.Pending) != store.NumbersMaxPending || !n.PendingOver || !n.Over() {
		t.Fatalf("51 pending: %d, over %v", len(n.Pending), n.PendingOver)
	}
}

// can_link counts as check_device_capacity does: a deleted number takes
// no place, so at capacity minus one beside a deleted number a number can
// still be linked; the storage stop and a workspace not active close it.
func TestNumbersCanLink(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	c := store.NewContract(w.pool)
	w.recordLocal(t, c)
	live := w.number(t, "live")
	deleted := w.number(t, "deleted")
	w.quarantine(t, deleted)
	_ = live
	w.capacity(t, 2)
	if n := w.numbers(ctx, t, c); !n.CanLink {
		t.Fatal("one live number of two places, beside a deleted one: no link")
	}
	if _, err := w.devices.Create(ctx, w.tenant.String(), "new", wa.ModePassive); err != nil {
		t.Fatalf("the link can_link offered: %v", err)
	}
	if n := w.numbers(ctx, t, c); n.CanLink {
		t.Fatal("at capacity: a link")
	}
	w.capacity(t, 5)
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at = clock_timestamp() WHERE id = $1`, w.tenant); err != nil {
		t.Fatal(err)
	}
	if n := w.numbers(ctx, t, c); n.CanLink || !n.StoragePaused {
		t.Fatalf("stopped by its storage: %+v", n)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at = NULL, status = 'suspended' WHERE id = $1`, w.tenant); err != nil {
		t.Fatal(err)
	}
	if n := w.numbers(ctx, t, c); n.CanLink || n.StoragePaused {
		t.Fatalf("a suspended workspace: %+v", n)
	}
	// A recorded workspace Wappie does not hold: an empty section.
	other := recordWorkspace(t, w.pool, "team")
	if _, ok, err := c.NumbersOf(ctx, other); err != nil || ok {
		t.Fatalf("a workspace with no snapshot yet: %v %v", ok, err)
	}
	if _, _, err := c.SnapshotSeq(ctx, other, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n, ok, err := c.NumbersOf(ctx, other); err != nil || !ok || n.Local || n.CanLink || len(n.Items) != 0 || len(n.Pending) != 0 {
		t.Fatalf("a workspace Wappie does not hold: %+v %v %v", n, ok, err)
	}
	// A parked section is not read.
	if _, err := w.pool.Exec(ctx, `UPDATE contract_sections SET parked_at = clock_timestamp() WHERE workspace_id = $1`, w.tenant); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.NumbersOf(ctx, w.tenant); err != nil || ok {
		t.Fatalf("a parked section: %v %v", ok, err)
	}
}

// TestSnapshotSeqAboveSections: the snapshot's and the sections' seqs rise
// on one clock, each above the other's last.
func TestSnapshotSeqAboveSections(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	c := store.NewContract(w.pool)
	w.recordLocal(t, c)
	ahead := time.Now().Add(time.Hour)
	snap, _, err := c.SnapshotSeq(ctx, w.tenant, ahead)
	if err != nil || snap != ahead.UnixMilli() {
		t.Fatalf("a snapshot measured ahead: %d %v", snap, err)
	}
	n := w.numbers(ctx, t, c)
	if n.Seq != snap+1 || n.SnapshotSeq != snap {
		t.Fatalf("a section after it: %d (snapshot %d)", n.Seq, n.SnapshotSeq)
	}
	n2 := w.numbers(ctx, t, c)
	if n2.Seq != n.Seq+1 {
		t.Fatalf("the next section: %d after %d", n2.Seq, n.Seq)
	}
	if next, _, err := c.SnapshotSeq(ctx, w.tenant, time.Now()); err != nil || next != n2.Seq+1 {
		t.Fatalf("a snapshot after the sections: %d %v, want %d", next, err, n2.Seq+1)
	}
}

// TestSectionSeqKeepsSnapshotOutcome: a section's seq given between
// SnapshotSeq and SnapshotSent leaves the snapshot's outcome recorded.
func TestSectionSeqKeepsSnapshotOutcome(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	c := store.NewContract(w.pool)
	w.recordLocal(t, c)
	for _, outcome := range []store.ContractSnapshotOutcome{store.SnapshotFailed, store.SnapshotAccepted} {
		measured := time.Now()
		seq, _, err := c.SnapshotSeq(ctx, w.tenant, measured)
		if err != nil {
			t.Fatal(err)
		}
		n := w.numbers(ctx, t, c)
		rec, err := c.SnapshotSent(ctx, w.tenant, seq, measured, outcome, "transport", snapshotTimes)
		if err != nil || !rec.Recorded {
			t.Fatalf("the snapshot's outcome %d after a section at %d: %+v %v", outcome, n.Seq, rec, err)
		}
		row := readSnapshotRow(t, w.pool, w.tenant)
		if outcome == store.SnapshotAccepted && (row.OKAt == nil || row.Tries != 0) || outcome == store.SnapshotFailed && row.Tries != 1 {
			t.Fatalf("after outcome %d: %+v", outcome, row)
		}
		if n.Seq <= seq {
			t.Fatalf("the section's seq %d is not above the snapshot's %d", n.Seq, seq)
		}
	}
}

// SectionSent has SnapshotSent's table of outcomes, on contract_sections.
func TestSectionSent(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	c := store.NewContract(w.pool)
	w.recordLocal(t, c)
	type sectionRow struct {
		seq          int64
		ok, nf, park *time.Time
		due          time.Time
		tries        int
		class        string
	}
	read := func() sectionRow {
		t.Helper()
		var r sectionRow
		if err := w.pool.QueryRow(ctx, `SELECT state_seq, ok_at, not_found_since, parked_at, due_at, tries, coalesce(error, '')
			FROM contract_sections WHERE workspace_id = $1 AND section = 'numbers'`, w.tenant).
			Scan(&r.seq, &r.ok, &r.nf, &r.park, &r.due, &r.tries, &r.class); err != nil {
			t.Fatal(err)
		}
		return r
	}
	due, ok, err := c.NextSection(ctx)
	if err != nil || !ok || due.Workspace != w.tenant || due.Section != store.SectionNumbers || !due.Due {
		t.Fatalf("the first due: %+v %v %v", due, ok, err)
	}
	send := func(outcome store.ContractSnapshotOutcome, class string) store.ContractSnapshotRecord {
		t.Helper()
		// Sent when due, as the sender sends: measured after its due time.
		if _, err := w.pool.Exec(ctx, `UPDATE contract_sections SET due_at = clock_timestamp() WHERE parked_at IS NULL`); err != nil {
			t.Fatal(err)
		}
		n := w.numbers(ctx, t, c)
		rec, err := c.SectionSent(ctx, w.tenant, store.SectionNumbers, n.Seq, n.MeasuredAt, outcome, class, snapshotTimes)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	if rec := send(store.SnapshotAccepted, ""); !rec.Recorded || rec.Again {
		t.Fatalf("accepted: %+v", rec)
	}
	if r := read(); r.ok == nil || r.tries != 0 || r.due.Sub(*r.ok) < 54*time.Minute {
		t.Fatalf("accepted: %+v", r)
	}
	for i := 1; i <= 2; i++ {
		if rec := send(store.SnapshotFailed, "transport"); rec.Tries != i {
			t.Fatalf("failure %d: %+v", i, rec)
		}
	}
	if r := read(); r.tries != 2 || r.class != "transport" || r.ok == nil {
		t.Fatalf("after two failures: %+v", r)
	}
	if rec := send(store.SnapshotNotFound, "not_found"); rec.NotFoundSince == nil || rec.Parked {
		t.Fatalf("a not_found: %+v", rec)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE contract_sections SET not_found_since = clock_timestamp() - interval '25 hours'`); err != nil {
		t.Fatal(err)
	}
	if rec := send(store.SnapshotNotFound, "not_found"); !rec.Parked {
		t.Fatalf("a day of not_found: %+v", rec)
	}
	if _, ok, err := c.NumbersOf(ctx, w.tenant); err != nil || ok {
		t.Fatalf("a parked section read: %v %v", ok, err)
	}
	if _, ok, _ := c.NextSection(ctx); ok {
		t.Fatal("a parked section is due")
	}
	// The leader's start releases it for one try.
	if err := c.SectionsDue(ctx); err != nil {
		t.Fatal(err)
	}
	if r := read(); r.park != nil || r.nf == nil {
		t.Fatalf("after the leader's start: %+v", r)
	}
	if rec := send(store.SnapshotRefused, "invalid_request"); !rec.Parked || rec.NotFoundSince != nil {
		t.Fatalf("refused: %+v", rec)
	}
	if err := c.SectionsDue(ctx); err != nil {
		t.Fatal(err)
	}
	// A seq passed by another read records nothing; a due time set after
	// the measurement stands.
	n := w.numbers(ctx, t, c)
	w.numbers(ctx, t, c)
	if rec, err := c.SectionSent(ctx, w.tenant, store.SectionNumbers, n.Seq, n.MeasuredAt, store.SnapshotAccepted, "", snapshotTimes); err != nil || rec.Recorded {
		t.Fatalf("an outcome another read passed: %+v %v", rec, err)
	}
	n = w.numbers(ctx, t, c)
	if err := c.SectionsDirty(ctx, []uuid.UUID{w.tenant}, false, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE contract_sections SET due_at = clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	before := read().tries
	if rec, err := c.SectionSent(ctx, w.tenant, store.SectionNumbers, n.Seq, n.MeasuredAt, store.SnapshotFailed, "transport", snapshotTimes); err != nil ||
		!rec.Again || rec.Tries != before {
		t.Fatalf("a failure after a due now: %+v %v", rec, err)
	}
	if r := read(); r.due.After(time.Now().Add(time.Second)) {
		t.Fatalf("the due time set after the measurement did not stand: %+v", r)
	}
}

// SectionsDirty debounces: a section due later comes due within the
// debounce, one due sooner stays, one backing off keeps its backoff, and a
// parked one its park.
func TestSectionsDirty(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	c := store.NewContract(w.pool)
	w.recordLocal(t, c)
	ws := []uuid.UUID{w.tenant, recordWorkspace(t, w.pool, "team"), recordWorkspace(t, w.pool, "team"), recordWorkspace(t, w.pool, "team")}
	for i, sql := range []string{
		`UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour' WHERE workspace_id = $1`,
		`UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 second' WHERE workspace_id = $1`,
		`UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour', tries = 2 WHERE workspace_id = $1`,
		`UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour', parked_at = clock_timestamp() WHERE workspace_id = $1`,
	} {
		if _, err := w.pool.Exec(ctx, sql, ws[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.SectionsDirty(ctx, nil, true, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	for i, soon := range []bool{true, true, false, false} {
		var n int
		if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM contract_sections WHERE workspace_id = $1
			AND due_at <= clock_timestamp() + interval '2 seconds'`, ws[i]).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if (n == 1) != soon {
			t.Errorf("section %d due soon: %v, want %v", i, n == 1, soon)
		}
	}
}

// SectionsRecovered makes every section that backs off due now with its
// tries forgotten (the platform answers again after an outage), keeping
// its not_found run and its last failure's class; a section that is not
// failing keeps its due time, and a parked one its park.
func TestSectionsRecovered(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	c := store.NewContract(w.pool)
	w.recordLocal(t, c)
	ws := []uuid.UUID{w.tenant, recordWorkspace(t, w.pool, "team"), recordWorkspace(t, w.pool, "team"), recordWorkspace(t, w.pool, "team")}
	for i, sql := range []string{
		`UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour', tries = 12, error = 'transport' WHERE workspace_id = $1`,
		`UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour', tries = 3, error = 'not_found',
			not_found_since = clock_timestamp() - interval '1 hour' WHERE workspace_id = $1`,
		`UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour' WHERE workspace_id = $1`,
		`UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour', tries = 2, parked_at = clock_timestamp() WHERE workspace_id = $1`,
	} {
		if _, err := w.pool.Exec(ctx, sql, ws[i]); err != nil {
			t.Fatal(err)
		}
	}
	n, err := c.SectionsRecovered(ctx)
	if err != nil || n != 2 {
		t.Fatalf("recovered %d %v", n, err)
	}
	for i, want := range []struct {
		due   bool
		tries int
		error string
	}{{true, 0, "transport"}, {true, 0, "not_found"}, {false, 0, ""}, {false, 2, ""}} {
		var due bool
		var tries int
		var class string
		var notFound, parked *time.Time
		if err := w.pool.QueryRow(ctx, `SELECT due_at <= clock_timestamp(), tries, coalesce(error, ''), not_found_since, parked_at
			FROM contract_sections WHERE workspace_id = $1`, ws[i]).Scan(&due, &tries, &class, &notFound, &parked); err != nil {
			t.Fatal(err)
		}
		if due != want.due || tries != want.tries || class != want.error {
			t.Errorf("section %d: due %v tries %d error %q, want %+v", i, due, tries, class, want)
		}
		if i == 1 && notFound == nil {
			t.Error("the not_found run is forgotten")
		}
		if i == 3 && parked == nil {
			t.Error("the park is released")
		}
	}
}
