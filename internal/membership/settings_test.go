package membership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"whatserver2/internal/wa"
)

// The settings part in the leader (the plan's 5.4 and 5.5) on a real
// database and the fake platform: the numbers section's cadence, the
// command feed, the ledger, the executor's kind_not_accepted, the results,
// the reset and the mode.

// settingsTimes are the settings part's timings for the tests: short, but
// the debounces the cadence tests pin.
func settingsTimes() SettingsConfig {
	return SettingsConfig{CommandWait: 1, CommandBackoffMin: 20 * time.Millisecond, CommandBackoffMax: 200 * time.Millisecond,
		ResetFloor: 200 * time.Millisecond, SectionDebounce: 100 * time.Millisecond, ConnectionDebounce: 100 * time.Millisecond,
		SectionBackoffMin: 20 * time.Millisecond, SectionBackoffMax: 200 * time.Millisecond, PairingLook: 100 * time.Millisecond,
		ResultsBackoffMin: 20 * time.Millisecond, ResultsBackoffMax: 200 * time.Millisecond, Idle: 200 * time.Millisecond,
		TrimEvery: time.Hour}
}

// settingsLeader is w's leader with the settings part's cfg.
func (w *world) settingsLeader(m *Members, logs *membershiptest.Logs, cfg SettingsConfig) *Leader {
	l := w.leader(m, logs, lockKeyOf(w))
	l.Settings = cfg
	return l
}

// lockKeyOf is a lock of the world's own.
func lockKeyOf(*world) string { return "contract:settings:" + uuid.NewString() }

// settingsOn switches the settings mode to mode, the platform told.
func (w *world) settingsOn(t *testing.T, mode string) {
	t.Helper()
	if _, err := w.contract.SetSettingsMode(context.Background(), mode, true); err != nil {
		t.Fatal(err)
	}
}

// sectionsAccepted are the numbers sections of ws the fake answered 200.
func (w *world) sectionsAccepted(ws uuid.UUID) []membershiptest.Section {
	var out []membershiptest.Section
	for _, s := range w.fake.Sections(ws.String()) {
		if s.Status == http.StatusOK {
			out = append(out, s)
		}
	}
	return out
}

// settleSection waits until ws's numbers section was accepted and nothing
// is pending for it: its next is the hourly one.
func (w *world) settleSection(t *testing.T, ws uuid.UUID) {
	t.Helper()
	eventually(t, soon, "the section settled", func() bool {
		var quiet bool
		if err := w.pool.QueryRow(context.Background(), `SELECT ok_at IS NOT NULL AND due_at > clock_timestamp() + interval '10 minutes'
			AND tries = 0 FROM contract_sections WHERE workspace_id = $1 AND section = 'numbers'`, ws).Scan(&quiet); err != nil {
			return false
		}
		return quiet
	})
}

// sectionDueAhead is how far ahead of the database's clock ws's section is
// due, off the hourly (under 10 minutes) with no failure; 0 otherwise.
func (w *world) sectionDueAhead(t *testing.T, ws uuid.UUID) time.Duration {
	t.Helper()
	var due, now time.Time
	var tries int
	if err := w.pool.QueryRow(context.Background(), `SELECT due_at, clock_timestamp(), tries FROM contract_sections
		WHERE workspace_id = $1 AND section = 'numbers'`, ws).Scan(&due, &now, &tries); err != nil {
		t.Fatal(err)
	}
	if ahead := due.Sub(now); tries == 0 && ahead < 10*time.Minute {
		return ahead
	}
	return 0
}

// offer makes the fake keep a numbers section of ws, newer than Wappie's
// last, that lists kinds, as a release that runs them would send it: the
// console then offers them (IssueCommand).
func (w *world) offer(t *testing.T, ws uuid.UUID, kinds ...string) {
	t.Helper()
	doc, ok := w.fake.Settings("wappie", ws.String(), kc.SectionNumbers)
	if !ok {
		t.Fatal("the fake keeps no numbers section")
	}
	doc.StateSeq++
	doc.Accepts = kinds
	client := w.fake.Client("wappie")
	client.Base, client.HTTP = w.fake.URL, &http.Client{}
	if err := client.PutSettings(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
}

// rename issues an item.rename of device in ws by actor.
func (w *world) rename(t *testing.T, ws, device, actor uuid.UUID) string {
	t.Helper()
	id, err := w.fake.IssueCommand("wappie", contracttest.CommandSpec{Kind: kc.OpItemRename, Workspace: ws.String(), Actor: actor.String(),
		Target: kc.CommandTarget{Item: device.String()}, Params: json.RawMessage(`{"before":{"label":"Vendas"},"after":{"label":"Vendas SP"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// ledgerRow is a command's ledger row as the tests read it.
type ledgerRow struct {
	outcome, code, delivery, rejectCode string
	stateSeq                            *int64
	kind                                string
	generation                          uuid.UUID
}

func (w *world) ledgerRow(t *testing.T, id string) (ledgerRow, bool) {
	t.Helper()
	var r ledgerRow
	err := w.pool.QueryRow(context.Background(), `SELECT coalesce(outcome, ''), coalesce(code, ''), coalesce(delivery, ''),
		coalesce(reject_code, ''), state_seq, coalesce(kind, ''), generation FROM contract_commands WHERE id = $1`, id).
		Scan(&r.outcome, &r.code, &r.delivery, &r.rejectCode, &r.stateSeq, &r.kind, &r.generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return r, true
}

// TestSettingsFollowsTheFeed: in read, the command feed is followed: one
// request at a time, the next asked as soon as the last is answered, never
// waiting more than its wait between two; and the cursor a request
// acknowledges is asked only once the commands up to it are committed to
// the ledger.
func TestSettingsFollowsTheFeed(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	var mu sync.Mutex
	var asked []time.Time
	var acks []string
	var issued string
	w.fake.Before(contracttest.CallCommands, func(after string) {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, time.Now())
		if issued == "" || after == "0" {
			return
		}
		// A request after the command's cseq acknowledges it: its row is
		// committed before.
		cmd, _ := w.fake.Command("wappie", issued)
		if n, err := strconv.ParseInt(after, 10, 64); err == nil && n >= cmd.CSeq {
			var taken bool
			if err := w.pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM contract_commands WHERE id = $1)`, issued).
				Scan(&taken); err != nil || !taken {
				acks = append(acks, after)
			}
		}
	})
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
	w.settleSection(t, w.team)
	w.offer(t, w.team, kc.OpItemRename)
	id := w.rename(t, w.team, w.device, w.sub)
	mu.Lock()
	issued = id
	mu.Unlock()
	eventually(t, soon, "the command answered", func() bool {
		r, ok := w.ledgerRow(t, id)
		return ok && r.delivery == store.DeliveryAccepted
	})
	start := time.Now()
	time.Sleep(3 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(acks) > 0 {
		t.Fatalf("the cursor %v was acknowledged before its command's row was committed", acks)
	}
	if most := w.fake.Most(contracttest.CallCommands); most != 1 {
		t.Fatalf("%d command feed requests at once", most)
	}
	var recent []time.Time
	for _, at := range asked {
		if at.After(start) {
			recent = append(recent, at)
		}
	}
	// A wait of 1 s: a request at least every second and a little, for
	// three seconds.
	if len(recent) < 2 {
		t.Fatalf("%d command feed requests in 3 s", len(recent))
	}
	for i := 1; i < len(recent); i++ {
		if gap := recent[i].Sub(recent[i-1]); gap > 2*time.Second {
			t.Fatalf("%v between two command feed requests, past the wait", gap)
		}
	}
	if s, err := w.contract.SettingsState(ctx); err != nil || s.FirstReadAt == nil || s.ReadAt == nil || s.FeedError != "" {
		t.Fatalf("the feed's state: %+v %v", s, err)
	}
	// The default wait is the contract's: at least one request every 26 s.
	if (SettingsConfig{}).commandWait() != 25 || commandBackoffMax >= 120*time.Second {
		t.Fatal("the command feed's wait or backoff")
	}
}

// TestSettingsKindNotAccepted (a gate): in read, a command the console
// issued from a section that listed its kind (a section the fake's own
// client sent) is answered kind_not_accepted with the seq it was judged
// on, the fake keeps that result, and Wappie's next section lists no kind:
// accepts is [] on the wire, and so are its empty lists.
func TestSettingsKindNotAccepted(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
	w.settleSection(t, w.team)
	w.offer(t, w.team, kc.OpItemRename)
	id := w.rename(t, w.team, w.device, w.sub)
	var res kc.CommandResult
	eventually(t, soon, "the result kept", func() bool {
		var ok bool
		res, ok = w.fake.CommandResult("wappie", id)
		return ok
	})
	if res.Outcome != kc.OutcomeRefused || res.Code == nil || *res.Code != kc.CodeKindNotAccepted || res.StateSeq == nil ||
		res.RetryAfter != nil || res.Detail != nil {
		t.Fatalf("the result: %+v", res)
	}
	var seq int64
	if err := w.pool.QueryRow(ctx, `SELECT greatest(sections_seq, snapshot_seq) FROM contract_workspaces WHERE workspace_id = $1`, w.team).
		Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if *res.StateSeq < 1 || *res.StateSeq > seq {
		t.Fatalf("judged on seq %d; the workspace's clock is at %d", *res.StateSeq, seq)
	}
	eventually(t, soon, "the answer recorded", func() bool {
		r, _ := w.ledgerRow(t, id)
		return r.kind == kc.OpItemRename && r.delivery == store.DeliveryAccepted
	})
	// Its next section: due now (a rename of the number), with no kind.
	n := len(w.sectionsAccepted(w.team))
	if err := store.NewDevices(w.pool).Rename(ctx, w.team.String(), w.device.String(), "Vendas SP"); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "the next section", func() bool { return len(w.sectionsAccepted(w.team)) > n })
	doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
	if !ok || doc.Accepts == nil || len(doc.Accepts) != 0 {
		t.Fatalf("the kept section's accepts: %#v", doc.Accepts)
	}
	sent := w.sectionsAccepted(w.team)
	body := string(sent[len(sent)-1].Body)
	for _, want := range []string{`"accepts":[]`, `"pending":[]`} {
		if !strings.Contains(body, want) {
			t.Errorf("the section on the wire has no %s: %s", want, body)
		}
	}
	if strings.Contains(body, ":null,\"accepts\"") || strings.Contains(body, `"items":null`) {
		t.Errorf("a list is null on the wire: %s", body)
	}
}

// remac is a client of the fake platform whose command feed answers have
// every command signed again with secret, which Wappie does not hold, and
// the answer signed again with Wappie's: a command whose MAC holds under
// none of Wappie's secrets, in a page that is the platform's.
func (w *world) remac(t *testing.T, secret string) *Client {
	t.Helper()
	platform, err := url.Parse(w.fake.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := clientOn(func(r *http.Request) (*http.Response, error) {
		out := r.Clone(r.Context())
		out.URL.Scheme, out.URL.Host, out.Host = platform.Scheme, platform.Host, platform.Host
		res, err := http.DefaultTransport.RoundTrip(out)
		if err != nil || !strings.HasSuffix(r.URL.Path, "/commands") || res.StatusCode != http.StatusOK {
			return res, err
		}
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close() //nolint:errcheck // read whole
		if err != nil {
			return nil, err
		}
		var page kc.CommandFeed
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		for i, it := range page.Items {
			signed, err := kc.SignCommand(it.Command, App, secret)
			if err != nil {
				return nil, err
			}
			page.Items[i].Command = signed
		}
		body, err = json.Marshal(page)
		if err != nil {
			return nil, err
		}
		return signedAnswer(out, w.secret, http.StatusOK, body, time.Now()), nil
	}, nil)
	if err := c.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestSettingsInvalidCommand: a command whose MAC holds under none of
// Wappie's secrets is refused invalid_command at take, in the take's
// transaction: its row keeps no decoded field, a contract_command_invalid
// security event names no person, invalid_at is stamped, one ERROR is
// logged and recorded for --check; its result is posted.
func TestSettingsInvalidCommand(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	m := &Members{Client: w.remac(t, membershiptest.Secret(t)), Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
	run(t, w.settingsLeader(m, logs, settingsTimes()))
	eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
	w.settleSection(t, w.team)
	w.offer(t, w.team, kc.OpItemRename)
	id := w.rename(t, w.team, w.device, w.sub)
	eventually(t, soon, "the result kept", func() bool {
		_, ok := w.fake.CommandResult("wappie", id)
		return ok
	})
	res, _ := w.fake.CommandResult("wappie", id)
	if res.Outcome != kc.OutcomeRefused || *res.Code != kc.CodeInvalidCommand || res.StateSeq != nil {
		t.Fatalf("the result: %+v", res)
	}
	if r, _ := w.ledgerRow(t, id); r.kind != "" || r.code != kc.CodeInvalidCommand {
		t.Fatalf("the ledger row: %+v", r)
	}
	var n int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE kind = 'contract_command_invalid'
		AND user_id IS NULL AND sub IS NULL AND detail->>'id' = $1 AND detail->>'why' = 'mac' AND NOT detail ? 'body'`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d security events for the command", n)
	}
	s, err := w.contract.SettingsState(ctx)
	if err != nil || s.InvalidAt == nil {
		t.Fatalf("invalid_at: %+v %v", s, err)
	}
	// Logged and recorded right after the take's commit, the poster maybe
	// sooner.
	eventually(t, soon, "the ERROR recorded", func() bool { return w.state(t).ErrorClass == store.ContractErrorCommandInvalid })
	if lines := logs.Lines("level=ERROR", "contract: commands refused invalid_command", "why_mac=1"); len(lines) != 1 {
		t.Fatalf("the ERROR:\n%s", logs.String())
	}
}

// TestNumbersFlappingConnection: a number that flips between online and
// offline sends at most one section per connection debounce (here 2 s for
// 30), however often it flips; a logout sends one within the 2 s debounce.
func TestNumbersFlappingConnection(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	cfg := settingsTimes()
	cfg.SectionDebounce, cfg.ConnectionDebounce = 0, 2*time.Second
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, cfg))
	eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
	w.settleSection(t, w.team)
	devices := store.NewDevices(w.pool)
	n := len(w.sectionsAccepted(w.team))
	start := time.Now()
	for i := 0; time.Since(start) < 5*time.Second; i++ {
		status := wa.StatusOnline
		if i%2 == 1 {
			status = wa.StatusOffline
		}
		if err := devices.SetStatus(ctx, w.team.String(), w.device.String(), status, ""); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Five seconds of flips at a 2 s debounce: at most three, and the last
	// within the debounce after them.
	time.Sleep(2500 * time.Millisecond)
	w.settleSection(t, w.team)
	if got := len(w.sectionsAccepted(w.team)) - n; got < 1 || got > 3 {
		t.Fatalf("%d sections for five seconds of flips", got)
	}
	n = len(w.sectionsAccepted(w.team))
	if err := devices.SetStatus(ctx, w.team.String(), w.device.String(), wa.StatusLoggedOut, "unlinked (logged out from the phone)"); err != nil {
		t.Fatal(err)
	}
	var late time.Duration
	eventually(t, soon, "the logout's section", func() bool {
		if a := w.sectionDueAhead(t, w.team); a > sectionDebounce {
			late = max(late, a)
		}
		return len(w.sectionsAccepted(w.team)) > n
	})
	if late > 0 {
		t.Fatalf("the logout's section was due %v ahead, past the debounce", late)
	}
	w.settleSection(t, w.team)
	sent := w.sectionsAccepted(w.team)
	if got := len(sent) - n; got != 1 || !strings.Contains(string(sent[len(sent)-1].Body), `"connection":"logged_out_phone"`) {
		t.Fatalf("%d sections for a logout", got)
	}
}

// TestSectionForNewWorkspace: a workspace a document names after the
// leader started gets its numbers section without a restart.
func TestSectionForNewWorkspace(t *testing.T) {
	w := newSnapshotWorld(t)
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
	team, err := w.fake.AddTeam("Outra", w.sub.String())
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(team)
	eventually(t, soon, "the new workspace's section", func() bool { return len(w.sectionsAccepted(id)) > 0 })
	doc, ok := w.fake.Settings("wappie", team, kc.SectionNumbers)
	if !ok || doc.SnapshotSeq == nil || *doc.SnapshotSeq < 1 {
		t.Fatalf("the section: %+v", doc)
	}
}

// TestSectionDuringSnapshot (DS3): a numbers section sent while a
// snapshot's PUT is in flight leaves that snapshot's outcome recorded (its
// accepted time, no snapshot due again), and the two rise on one clock: the
// section above the snapshot in flight, the next snapshot above the
// section.
func TestSectionDuringSnapshot(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
	w.settle(t, w.team)
	w.settleSection(t, w.team)
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	w.fake.Before(contracttest.CallAccess, func(ws string) {
		if ws == w.team.String() {
			once.Do(func() {
				close(held)
				<-release
			})
		}
	})
	defer w.fake.Before(contracttest.CallAccess, nil)
	w.exec(ctx, t, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() WHERE workspace_id = $1`, w.team)
	select {
	case <-held:
	case <-time.After(soon):
		t.Fatal("the snapshot never went")
	}
	var inFlight int64
	var since time.Time
	if err := w.pool.QueryRow(ctx, `SELECT snapshot_seq, clock_timestamp() FROM contract_workspaces WHERE workspace_id = $1`, w.team).
		Scan(&inFlight, &since); err != nil {
		t.Fatal(err)
	}
	n := len(w.sectionsAccepted(w.team))
	w.exec(ctx, t, `UPDATE contract_sections SET due_at = clock_timestamp() WHERE workspace_id = $1`, w.team)
	eventually(t, soon, "a section while the snapshot is in flight", func() bool { return len(w.sectionsAccepted(w.team)) > n })
	sent := w.sectionsAccepted(w.team)
	section := sent[len(sent)-1]
	if section.StateSeq <= inFlight || section.SnapshotSeq != inFlight {
		t.Fatalf("the section's seq %d (snapshot_seq %d), the snapshot in flight's %d", section.StateSeq, section.SnapshotSeq, inFlight)
	}
	close(release)
	eventually(t, soon, "the snapshot's outcome recorded", func() bool {
		var ok bool
		if err := w.pool.QueryRow(ctx, `SELECT snapshot_ok_at > $2 AND snapshot_tries = 0 AND snapshot_seq = $3
			AND snapshot_due_at > clock_timestamp() + interval '10 minutes' FROM contract_workspaces WHERE workspace_id = $1`,
			w.team, since, inFlight).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	})
	next, ok, err := w.contract.SnapshotNumbered(ctx, w.team)
	if err != nil || !ok || next.Seq <= section.StateSeq {
		t.Fatalf("the next snapshot's seq %d, the section's %d: %v %v", next.Seq, section.StateSeq, ok, err)
	}
}

// TestSettingsResetOnCommandFeed: a new generation of the platform resets
// the account and command state in one transaction: the results of the old
// generation not delivered are dropped and the wseq memory forgotten, the
// command feed is read from 0 under the new generation, and every section
// is sent again. The command that comes again from 0 (the platform holds
// no result of it) is a replay: its row moves to the new generation and
// its result is posted again.
func TestSettingsResetOnCommandFeed(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	var mu sync.Mutex
	var afters []string
	var hold chan struct{}
	w.fake.Before(contracttest.CallCommands, func(after string) {
		mu.Lock()
		afters = append(afters, after)
		held := hold
		mu.Unlock()
		if held != nil && after == "0" {
			<-held
		}
	})
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
	w.settleSection(t, w.team)
	old := w.state(t).Generation
	// A result that cannot be delivered before the reset.
	w.fake.RefuseAlways(contracttest.CallResults, kc.CodeRateLimited)
	w.offer(t, w.team, kc.OpItemRename)
	id := w.rename(t, w.team, w.device, w.sub)
	eventually(t, soon, "the command answered, not delivered", func() bool {
		r, ok := w.ledgerRow(t, id)
		return ok && r.outcome == store.CommandRefused
	})
	n := len(w.sectionsAccepted(w.team))
	mu.Lock()
	asked := len(afters)
	// The command feed's request from 0 waits, so the command does not come
	// again before the reset's own effects are looked at.
	release := make(chan struct{})
	hold = release
	mu.Unlock()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	gen := uuid.MustParse(w.fake.NewGeneration())
	eventually(t, soon, "the new generation", func() bool {
		s := w.state(t)
		return s.Generation != nil && *s.Generation == gen
	})
	eventually(t, soon, "the old result dropped", func() bool {
		r, _ := w.ledgerRow(t, id)
		return r.delivery == store.DeliveryDropped
	})
	if r, _ := w.ledgerRow(t, id); old == nil || r.generation != *old {
		t.Fatalf("the row's generation %s, the old %v", r.generation, old)
	}
	var wseqs int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM contract_command_wseq WHERE generation <> $1`, gen).Scan(&wseqs); err != nil {
		t.Fatal(err)
	}
	if wseqs != 0 {
		t.Fatalf("%d wseq memories of the old generation", wseqs)
	}
	eventually(t, soon, "every section sent again", func() bool { return len(w.sectionsAccepted(w.team)) > n })
	eventually(t, soon, "the command feed asked from 0", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, a := range afters[asked:] {
			if a == "0" {
				return true
			}
		}
		return false
	})
	w.fake.RefuseAlways(contracttest.CallResults, "")
	mu.Lock()
	hold = nil
	mu.Unlock()
	close(release)
	released = true
	eventually(t, soon, "the command again, a replay in the new generation, its result delivered", func() bool {
		r, _ := w.ledgerRow(t, id)
		return r.generation == gen && r.code == kc.CodeKindNotAccepted && r.delivery == store.DeliveryAccepted
	})
	if res, ok := w.fake.CommandResult("wappie", id); !ok || *res.Code != kc.CodeKindNotAccepted {
		t.Fatalf("the result kept: %+v %v", res, ok)
	}
}

// TestSettingsModeOffStops: settings off stops the settings part's loops
// (no command feed request goes) while the contract's go on; contract mode
// off turns settings off with it; and settings read is refused while the
// contract is off.
func TestSettingsModeOffStops(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	eventually(t, soon, "the command feed followed", func() bool { return w.fake.Count(contracttest.CallCommands) > 1 })
	w.settingsOn(t, store.SettingsOff)
	eventually(t, soon, "the settings stopped", func() bool { return len(logs.Lines("contract: settings stopped")) > 0 })
	quiet := func(what string) {
		t.Helper()
		eventually(t, soon, what+": no command feed request in flight", func() bool { return w.fake.InFlight(contracttest.CallCommands) == 0 })
		n := w.fake.Count(contracttest.CallCommands)
		time.Sleep(1500 * time.Millisecond)
		if got := w.fake.Count(contracttest.CallCommands); got != n {
			t.Fatalf("%s: %d command feed requests after the stop", what, got-n)
		}
	}
	quiet("settings off")
	reads := len(w.fake.Reads())
	eventually(t, soon, "the account feed still followed", func() bool { return len(w.fake.Reads()) > reads })

	w.settingsOn(t, store.SettingsRead)
	eventually(t, soon, "the settings started again", func() bool { return len(logs.Lines("contract: settings started")) > 1 })
	change, err := w.contract.SetMode(ctx, store.ContractOff)
	if err != nil || !change.SettingsOff {
		t.Fatalf("contract mode off: %+v %v", change, err)
	}
	quiet("contract off")
	if s, err := w.contract.SettingsState(ctx); err != nil || s.Mode != store.SettingsOff {
		t.Fatalf("the settings mode: %+v %v", s, err)
	}
	if _, err := w.contract.SetSettingsMode(ctx, store.SettingsRead, true); !errors.Is(err, store.ErrSettingsContractOff) {
		t.Fatalf("settings read while the contract is off: %v", err)
	}
}

// mutableLooks is a registry's view a test changes as it runs.
type mutableLooks struct {
	mu sync.Mutex
	l  looks
}

func (m *mutableLooks) PairingSince(id string) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.l.PairingSince(id)
}

func (m *mutableLooks) Holds(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.l.Holds(id)
}

func (m *mutableLooks) pair(id string, on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if on {
		m.l.pairing[id] = time.Now()
	} else {
		delete(m.l.pairing, id)
	}
}

// TestNumbersPendingPairing (DS8): a registration the registry pairs
// shows pairing true and can_retry false; one it does not, with a key,
// can_retry true; and the pairing look sends the change, with no row
// changed.
func TestNumbersPendingPairing(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	d, err := store.NewDevices(w.pool).Create(ctx, w.team.String(), "Novo", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET current_epoch = 1 WHERE id = $1`, d.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	reg := &mutableLooks{l: looks{pairing: map[string]time.Time{}, held: map[string]bool{}}}
	cfg := settingsTimes()
	cfg.Numbers = reg
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, cfg))
	pendingOf := func() (kc.PendingRegistration, bool) {
		sent := w.sectionsAccepted(w.team)
		if len(sent) == 0 {
			return kc.PendingRegistration{}, false
		}
		var doc kc.SettingsDoc
		if err := json.Unmarshal(sent[len(sent)-1].Body, &doc); err != nil {
			t.Fatal(err)
		}
		var data kc.NumbersSettings
		if err := json.Unmarshal(doc.Data, &data); err != nil || len(data.Pending) != 1 || data.Pending[0].ID != d.ID {
			t.Fatalf("the pending rows: %+v %v", data.Pending, err)
		}
		return data.Pending[0], true
	}
	eventually(t, soon, "the first section", func() bool { _, ok := pendingOf(); return ok })
	w.settleSection(t, w.team)
	if p, _ := pendingOf(); p.Pairing || !p.CanRetry {
		t.Fatalf("a registration nobody pairs: %+v", p)
	}
	updated := func() time.Time {
		t.Helper()
		var at time.Time
		if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT updated_at FROM devices WHERE id = $1`, d.ID).Scan(&at)
		}); err != nil {
			t.Fatal(err)
		}
		return at
	}
	before := updated()
	reg.pair(d.ID, true)
	eventually(t, soon, "the pairing sent", func() bool { p, _ := pendingOf(); return p.Pairing && !p.CanRetry })
	reg.pair(d.ID, false)
	eventually(t, soon, "the pairing's end sent", func() bool { p, _ := pendingOf(); return !p.Pairing && p.CanRetry })
	if !updated().Equal(before) {
		t.Fatal("the registration's row changed")
	}
}

// settingsCounting is counting with the command feed's long-poll left out,
// as the account feed's is: neither goes on the leader's turns.
type settingsCounting struct {
	*counting
	sections atomicCount
}

type atomicCount struct {
	mu sync.Mutex
	n  int
}

func (a *atomicCount) add() { a.mu.Lock(); a.n++; a.mu.Unlock() }

func (a *atomicCount) get() int { a.mu.Lock(); defer a.mu.Unlock(); return a.n }

func (c *settingsCounting) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/commands") {
		return http.DefaultTransport.RoundTrip(r)
	}
	if strings.Contains(r.URL.Path, "/settings/") {
		c.sections.add()
	}
	return c.counting.RoundTrip(r)
}

// TestSettingsPacing: with settings read, the leader's calls (the round's,
// the snapshots', the events', the sections' and the results') still take
// turns at one pace: no window of a second holds more than ten turns and
// the one call each of the five senders may still be sending on an
// earlier one.
func TestSettingsPacing(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	const pace = 100 * time.Millisecond
	w.settingsOn(t, store.SettingsRead)
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
	c := &settingsCounting{counting: &counting{}}
	client := NewClient(&http.Client{Transport: c}, w.fake.URL, nil)
	if err := client.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	m := &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: pace}
	c.pace(m)
	run(t, w.settingsLeader(m, logs, settingsTimes()))
	eventuallySteps(t, 30*time.Second, "the snapshots, the events and the sections", 18, func() int {
		return int(min(c.access.Load(), 6) + min(c.events.Load(), 6) + int64(min(c.sections.get(), 6)))
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
	if most > 15 {
		t.Fatalf("%d of the leader's calls within a second, at a pace of %v between any two (%d calls in all)", most, pace, len(c.all))
	}
}

// TestExecutorBacksOff (the plan's 3.2): a row whose answer fails with a
// store error that is no verdict (here a constraint a trigger of the
// test's raises) backs off, holding back neither another workspace's
// command, which is answered meanwhile; after 5 tries it is answered
// rate_limited, retry_after 60, with one ERROR recorded for --check.
func TestExecutorBacksOff(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	w.exec(ctx, t, `CREATE FUNCTION test_refuse_team() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.code = 'kind_not_accepted' AND NEW.workspace_id = '`+w.team.String()+`' THEN
				RAISE EXCEPTION 'the test refuses it' USING ERRCODE = '23514';
			END IF;
			RETURN NEW;
		END $$`)
	w.exec(ctx, t, `CREATE TRIGGER test_refuse_team BEFORE UPDATE ON contract_commands FOR EACH ROW EXECUTE FUNCTION test_refuse_team()`)
	logs := &membershiptest.Logs{}
	run(t, w.settingsLeader(w.members, logs, settingsTimes()))
	for _, ws := range []uuid.UUID{w.team, w.home} {
		eventually(t, soon, "the first sections", func() bool { return len(w.sectionsAccepted(ws)) > 0 })
		w.settleSection(t, ws)
		w.offer(t, ws, kc.OpItemRename)
	}
	stuck := w.rename(t, w.team, w.device, w.sub)
	home := w.number(t, w.home, "Casa", 77, w.owner)
	answered := w.rename(t, w.home, home, w.sub)
	eventually(t, soon, "the other workspace's command answered", func() bool {
		r, ok := w.ledgerRow(t, answered)
		return ok && r.code == kc.CodeKindNotAccepted
	})
	// Each wait cut short, the backoff's own bounds being the store's.
	eventually(t, soon, "five tries, then rate_limited", func() bool {
		var code string
		if err := w.pool.QueryRow(ctx, `UPDATE contract_commands SET run_after = CASE WHEN run_after > clock_timestamp()
			THEN clock_timestamp() ELSE run_after END WHERE id = $1 RETURNING coalesce(code, '')`, stuck).Scan(&code); err != nil {
			t.Fatal(err)
		}
		return code == kc.CodeRateLimited
	})
	var tries, retry int
	var class string
	if err := w.pool.QueryRow(ctx, `SELECT run_tries, retry_after, run_error FROM contract_commands WHERE id = $1`, stuck).
		Scan(&tries, &retry, &class); err != nil {
		t.Fatal(err)
	}
	if tries != store.CommandRunTries || retry != 60 || class != "sqlstate_23514" {
		t.Fatalf("tries %d, retry_after %d, class %q", tries, retry, class)
	}
	// The ERROR is logged and recorded once the answer is committed.
	eventually(t, soon, "the ERROR recorded", func() bool { return w.state(t).ErrorClass == store.ContractErrorCommandStuck })
	if len(logs.Lines("level=ERROR", "contract: a command was answered rate_limited after its runs kept failing")) != 1 ||
		len(logs.Lines("level=WARN", "contract: a command's run failed; it waits and is tried again")) != store.CommandRunTries {
		t.Fatalf("the log:\n%s", logs.String())
	}
	eventually(t, soon, "the stuck command's result kept", func() bool {
		res, ok := w.fake.CommandResult("wappie", stuck)
		return ok && res.Code != nil && *res.Code == kc.CodeRateLimited && res.RetryAfter != nil && *res.RetryAfter == 60
	})
}

// TestSettingsResetFloorAfterNoReset: a reset from the command feed that
// finds the generation moved under it (another reset came first) resets
// nothing and starts no floor: the next reset, a real one, goes at once,
// not a minute later with no command feed request meanwhile.
func TestSettingsResetFloorAfterNoReset(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	cfg := settingsTimes()
	cfg.ResetFloor = time.Minute
	var armed atomic.Bool
	var moved atomic.Pointer[uuid.UUID]
	cfg.stateRead = func(func()) {
		if !armed.CompareAndSwap(true, false) {
			return
		}
		// Between the follower's read of the state and its request, a reset
		// elsewhere commits (here the store's own, so nothing cuts the
		// request), and the platform answers gone.
		st, err := w.contract.State(ctx)
		if err != nil || st.Generation == nil {
			t.Errorf("the state: %+v %v", st, err)
			return
		}
		gen := uuid.New()
		if done, err := w.contract.Restart(ctx, st.Generation, st.FeedCursor, &gen, false); err != nil || !done {
			t.Errorf("the reset elsewhere: %v %v", done, err)
			return
		}
		w.fake.RefuseAlways(contracttest.CallCommands, kc.CodeGone)
		moved.Store(&gen)
	}
	run(t, w.settingsLeader(w.members, logs, cfg))
	eventually(t, soon, "the command feed followed", func() bool { return w.fake.Count(contracttest.CallCommands) > 1 })
	// The account follower resets nothing meanwhile: its feed is refused,
	// and its long-poll in flight has come back.
	w.fake.RefuseAlways(contracttest.CallFeed, kc.CodeRateLimited)
	time.Sleep(1500 * time.Millisecond)
	armed.Store(true)
	eventually(t, soon, "the reset elsewhere", func() bool { return moved.Load() != nil })
	gen := moved.Load()
	eventually(t, 5*time.Second, "the command feed's reset at once", func() bool {
		return len(logs.Lines("why=commands_gone", "old="+gen.String())) > 0
	})
	if lines := logs.Lines("a second reset from the command feed"); len(lines) > 0 {
		t.Fatalf("a reset that did not happen started the floor: %v", lines)
	}
}

// TestCommandFeedCutBeforeAsk: a reset of the account side between the
// command follower's read of the state and its request (its interrupt
// finds no long-poll to cut) is not lost: the follower reads the state
// again before it asks, never asking with the cursor of the generation
// gone.
func TestCommandFeedCutBeforeAsk(t *testing.T) {
	w := newSnapshotWorld(t)
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	cfg := settingsTimes()
	var mu sync.Mutex
	var asked []int
	var armed atomic.Bool
	cfg.stateRead = func(interrupt func()) {
		mu.Lock()
		defer mu.Unlock()
		if armed.Load() {
			asked = append(asked, w.fake.Count(contracttest.CallCommands))
			if len(asked) == 1 {
				interrupt()
			}
		}
	}
	run(t, w.settingsLeader(w.members, logs, cfg))
	eventually(t, soon, "the command feed followed", func() bool { return w.fake.Count(contracttest.CallCommands) > 1 })
	armed.Store(true)
	eventually(t, soon, "the state read twice", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(asked) >= 2
	})
	mu.Lock()
	defer mu.Unlock()
	if asked[1] != asked[0] {
		t.Fatalf("a command feed request went after an interrupt that came before it: %v", asked)
	}
}

// TestSettingsResetLoopRecorded: a second reset from the command feed
// within the floor is a fault of the platform's that resets everything
// once a minute while it lasts: an ERROR, recorded for --check.
func TestSettingsResetLoopRecorded(t *testing.T) {
	w := newSnapshotWorld(t)
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	cfg := settingsTimes()
	cfg.ResetFloor = 10 * time.Second
	run(t, w.settingsLeader(w.members, logs, cfg))
	eventually(t, soon, "the command feed followed", func() bool { return w.fake.Count(contracttest.CallCommands) > 1 })
	w.fake.RefuseAlways(contracttest.CallCommands, kc.CodeGone)
	eventually(t, soon, "the loop's ERROR", func() bool {
		return len(logs.Lines("level=ERROR", "a second reset from the command feed within a minute waits")) > 0
	})
	eventually(t, soon, "the loop's ERROR recorded", func() bool { return w.state(t).ErrorClass == store.ContractErrorCommandResetLoop })
	w.fake.RefuseAlways(contracttest.CallCommands, "")
}

// TestSectionsRecoverWithPlatform: after an outage the numbers sections
// come back with the platform, as the snapshots do: the command feed's
// first page after its failure makes every section that backs off due now,
// tries forgotten, and a change after that is sent within the debounce,
// not at the end of a backoff of up to an hour.
func TestSectionsRecoverWithPlatform(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	logs := &membershiptest.Logs{}
	cfg := settingsTimes()
	cfg.SectionBackoffMax = time.Hour
	run(t, w.settingsLeader(w.members, logs, cfg))
	eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
	w.settleSection(t, w.team)

	w.fake.SetDown(true)
	w.exec(ctx, t, `UPDATE contract_sections SET due_at = clock_timestamp() WHERE workspace_id = $1`, w.team)
	eventually(t, 10*time.Second, "a section and a command feed call failed", func() bool {
		var tries int
		if err := w.pool.QueryRow(ctx, `SELECT tries FROM contract_sections WHERE workspace_id = $1`, w.team).Scan(&tries); err != nil {
			t.Fatal(err)
		}
		sst, err := w.contract.SettingsState(ctx)
		return err == nil && tries > 0 && sst.FeedError != ""
	})
	// The backoff at its cap, as after an outage of an hour, once no send
	// in flight records its own over it.
	eventually(t, 10*time.Second, "the backoff at its cap", func() bool {
		w.exec(ctx, t, `UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour', tries = 12 WHERE workspace_id = $1`, w.team)
		time.Sleep(300 * time.Millisecond)
		var capped bool
		if err := w.pool.QueryRow(ctx, `SELECT due_at > clock_timestamp() + interval '30 minutes' AND tries = 12 FROM contract_sections
			WHERE workspace_id = $1`, w.team).Scan(&capped); err != nil {
			t.Fatal(err)
		}
		return capped
	})
	n := len(w.sectionsAccepted(w.team))
	w.fake.SetDown(false)
	eventually(t, 10*time.Second, "the section back with the platform", func() bool { return len(w.sectionsAccepted(w.team)) > n })
	if err := store.NewDevices(w.pool).SetStatus(ctx, w.team.String(), w.device.String(), wa.StatusLoggedOut,
		"unlinked (logged out from the phone)"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the logout sent within the debounce", func() bool {
		for _, s := range w.sectionsAccepted(w.team) {
			if strings.Contains(string(s.Body), `"connection":"logged_out_phone"`) {
				return true
			}
		}
		return false
	})
}

// TestResultsPauseAfterStoreFailure: a park, or the platform's answers,
// that the ledger cannot store makes the results poster wait, doubling to
// its backoff, before it reads the rows again: never a loop on the
// database, or on the platform with the same batch; and its WARNs are
// spaced.
func TestResultsPauseAfterStoreFailure(t *testing.T) {
	refuse := func(t *testing.T, w *snapshotWorld, when string) {
		t.Helper()
		ctx := context.Background()
		w.exec(ctx, t, `CREATE SEQUENCE test_refusals`)
		w.exec(ctx, t, `CREATE FUNCTION test_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF `+when+` THEN
					PERFORM nextval('test_refusals');
					RAISE EXCEPTION 'the test refuses it' USING ERRCODE = '23514';
				END IF;
				RETURN NEW;
			END $$`)
		w.exec(ctx, t, `CREATE TRIGGER test_refuse BEFORE UPDATE ON contract_commands FOR EACH ROW EXECUTE FUNCTION test_refuse()`)
	}
	refusals := func(t *testing.T, w *snapshotWorld) int {
		t.Helper()
		var n int
		if err := w.pool.QueryRow(context.Background(), `SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM test_refusals`).
			Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	cfg := settingsTimes()
	cfg.ResultsBackoffMin, cfg.ResultsBackoffMax = 400*time.Millisecond, 800*time.Millisecond

	t.Run("park", func(t *testing.T) {
		w := newSnapshotWorld(t)
		ctx := context.Background()
		w.settingsOn(t, store.SettingsRead)
		refuse(t, w, `NEW.reject_code = 'local_invalid'`)
		logs := &membershiptest.Logs{}
		run(t, w.settingsLeader(w.members, logs, cfg))
		eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
		// invalid_command with a state_seq: the kit's Validate refuses it.
		w.exec(ctx, t, `INSERT INTO contract_commands (id, generation, cseq, body, body_key, signed_at, outcome, code, state_seq, result_at)
			VALUES (gen_random_uuid(), (SELECT generation FROM contract_state), 1, '{}', decode(repeat('ab', 32), 'hex'),
			clock_timestamp(), 'refused', 'invalid_command', 5, clock_timestamp())`)
		eventually(t, soon, "a park refused", func() bool { return refusals(t, w) > 0 })
		before := refusals(t, w)
		time.Sleep(2 * time.Second)
		if n := refusals(t, w) - before; n > 6 {
			t.Fatalf("%d parks tried in 2 s", n)
		}
		if lines := logs.Lines("contract: could not park results"); len(lines) != 1 {
			t.Fatalf("%d WARNs of a park refused", len(lines))
		}
	})

	t.Run("answers", func(t *testing.T) {
		w := newSnapshotWorld(t)
		w.settingsOn(t, store.SettingsRead)
		refuse(t, w, `NEW.delivery IN ('accepted', 'duplicate')`)
		logs := &membershiptest.Logs{}
		run(t, w.settingsLeader(w.members, logs, cfg))
		eventually(t, soon, "the first section", func() bool { return len(w.sectionsAccepted(w.team)) > 0 })
		w.settleSection(t, w.team)
		w.offer(t, w.team, kc.OpItemRename)
		w.rename(t, w.team, w.device, w.sub)
		eventually(t, soon, "the answers refused", func() bool { return refusals(t, w) > 0 })
		before := w.fake.Count(contracttest.CallResults)
		time.Sleep(2 * time.Second)
		if n := w.fake.Count(contracttest.CallResults) - before; n > 6 {
			t.Fatalf("%d posts of one result in 2 s", n)
		}
		if lines := logs.Lines("contract: could not record the results' answers"); len(lines) != 1 {
			t.Fatalf("%d WARNs of answers refused", len(lines))
		}
	})
}
