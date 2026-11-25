package membership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/numberacts"
	"whatserver2/internal/pg"
	"whatserver2/internal/relink"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The console's item.relink through the executor (kit v0.11.0; the
// spec's 14.13): its checks in order, its in_progress, its QRs on the
// pairing route, its ends, the leader's sweep, and can_relink in the
// numbers section. WhatsApp's part is played by a scripted registry: a
// test pushes each QR and scans or ends the pairing by hand. Fictional
// accounts only.

// scriptPairer is the registry as a relink, a sync now and the numbers
// section ask it, with the pairings a test drives by hand.
type scriptPairer struct {
	mu      sync.Mutex
	since   map[string]time.Time
	held    map[string]bool
	live    map[string]*scriptPairing
	started chan *scriptPairing
	stops   int
	// fail is what the next StartPairing answers, once, instead of a
	// pairing.
	fail error
}

func newScriptPairer() *scriptPairer {
	return &scriptPairer{since: map[string]time.Time{}, held: map[string]bool{}, live: map[string]*scriptPairing{},
		started: make(chan *scriptPairing, 16)}
}

func (p *scriptPairer) PairingSince(id string) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.since[id]
	return t, ok
}

func (p *scriptPairer) Holds(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, pairing := p.since[id]
	return pairing || p.held[id]
}

func (p *scriptPairer) ReleaseStale(context.Context, string) bool { return false }

func (p *scriptPairer) StartPairing(_ context.Context, _, device string, _ wa.ReceiptPolicy, opts wa.PairOptions) (relink.Pairing, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.since[device]; ok {
		return nil, wa.ErrAlreadyRunning
	}
	if err := p.fail; err != nil {
		p.fail = nil
		return nil, err
	}
	sp := &scriptPairing{p: p, device: device, events: make(chan wa.PairEvent, 32), opts: opts}
	p.since[device] = time.Now()
	p.live[device] = sp
	p.started <- sp
	return sp, nil
}

// Stop ends the number's pairing, as the registry's stop does.
func (p *scriptPairer) Stop(_ context.Context, device string) {
	p.mu.Lock()
	sp := p.live[device]
	p.stops++
	p.mu.Unlock()
	if sp != nil {
		sp.Cancel()
	}
}

func (p *scriptPairer) StartExisting(context.Context, string, string, wa.ReceiptPolicy, ...types.JID) (*wa.Device, error) {
	return nil, nil
}

// next is the pairing started next, within soon.
func (p *scriptPairer) next(t *testing.T) *scriptPairing {
	t.Helper()
	select {
	case sp := <-p.started:
		return sp
	case <-time.After(soon):
		t.Fatal("no pairing started")
		return nil
	}
}

// scriptPairing is one pairing a test drives: it pushes QRs, then scans or
// ends it.
type scriptPairing struct {
	p      *scriptPairer
	device string
	opts   wa.PairOptions
	mu     sync.Mutex
	ended  bool
	events chan wa.PairEvent
}

func (s *scriptPairing) Events() <-chan wa.PairEvent { return s.events }
func (s *scriptPairing) Cancel() {
	s.end(wa.PairEvent{Kind: wa.PairEventError, Err: context.Canceled})
}

// qr pushes a QR expiring at expires; none once the pairing ended.
func (s *scriptPairing) qr(code string, expires time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ended {
		s.events <- wa.PairEvent{Kind: wa.PairEventQR, Code: code, Expires: expires}
	}
}

// end ends the pairing with e, once.
func (s *scriptPairing) end(e wa.PairEvent) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	s.events <- e
	close(s.events)
	s.mu.Unlock()
	s.p.mu.Lock()
	delete(s.p.since, s.device)
	delete(s.p.live, s.device)
	s.p.mu.Unlock()
}

// scan is the number's phone scanning: the relink's attach, then success,
// or the attach's error as WhatsApp's library ends a refused link.
func (s *scriptPairing) scan(linked wa.Identity) error {
	err := s.opts.Relink.Attach(context.Background(), linked)
	if err != nil {
		s.end(wa.PairEvent{Kind: wa.PairEventError, Err: err})
		return err
	}
	s.end(wa.PairEvent{Kind: wa.PairEventSuccess})
	return nil
}

// qrCode is a QR in the shape of whatsmeow's link code, of made-up parts.
func qrCode(n int) string {
	return fmt.Sprintf("https://wa.me/settings/linked_devices#2@NotReal%04d,QUJD%04d=,REVG%04d=,R0hJ%04d=,1", n, n, n, n)
}

// relinkRig is the settings part with the scripted registry: the relink
// service on it, the numbers section's looks, the runner's busy and
// its sync now.
type relinkRig struct {
	p       *scriptPairer
	cfg     SettingsConfig
	running *relink.Running
}

func (w *world) relinkRig(t *testing.T, logs *membershiptest.Logs) relinkRig {
	t.Helper()
	w.exec(context.Background(), t, `CREATE TABLE IF NOT EXISTS whatsmeow_device (jid text PRIMARY KEY, registration_id bigint NOT NULL)`)
	p := newScriptPairer()
	devices := store.NewDevices(w.pool)
	running := &relink.Running{}
	cfg := settingsTimes()
	cfg.Numbers = p
	cfg.Acts = &numberacts.Runner{Store: w.contract, Devices: devices, Registry: p, Log: logs.Logger(), Running: running,
		Relinker: &relink.Service{Devices: devices, Pairer: p, Log: logs.Logger()}}
	return relinkRig{p: p, cfg: cfg, running: running}
}

// loggedOut makes a number of ws its phone logged out, both halves of its
// identity stored (device 3), with a key at epoch 1 that each of readers
// holds, with Read.
func (w *world) loggedOut(t *testing.T, ws uuid.UUID, name string, n int, readers ...uuid.UUID) (uuid.UUID, wa.Identity) {
	t.Helper()
	ctx := context.Background()
	devices := store.NewDevices(w.pool)
	d, err := devices.Create(ctx, ws.String(), name, wa.ModeActive)
	if err != nil {
		t.Fatal(err)
	}
	id := wa.Identity{PN: types.JID{User: fmt.Sprintf("15550109%04d", n), Device: 3, Server: types.DefaultUserServer},
		LID: types.JID{User: fmt.Sprintf("10000000009%04d", n), Device: 3, Server: types.HiddenUserServer}}
	if err := devices.SetIdentity(ctx, ws.String(), d.ID, id); err != nil {
		t.Fatal(err)
	}
	for _, s := range []wa.Status{wa.StatusOnline, wa.StatusLoggedOut} {
		if err := devices.SetStatus(ctx, ws.String(), d.ID, s, "unlinked (logged out)"); err != nil {
			t.Fatal(err)
		}
	}
	device := uuid.MustParse(d.ID)
	w.inWorkspace(t, ws, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET current_epoch = 1 WHERE id = $1`, device); err != nil {
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
	})
	return device, id
}

func (w *world) inWorkspace(t *testing.T, ws uuid.UUID, fn func(pgx.Tx) error) {
	t.Helper()
	if err := pg.InTenantTx(context.Background(), w.pool, ws.String(), fn); err != nil {
		t.Fatal(err)
	}
}

// newLink is the number's own account under a new link.
func newLink(id wa.Identity) wa.Identity {
	return wa.Identity{PN: types.JID{User: id.PN.User, Device: 12, Server: types.DefaultUserServer},
		LID: types.JID{User: id.LID.User, Device: 12, Server: types.HiddenUserServer}}
}

// sessionFor stores whatsmeow's session row of a new link, as its library
// writes it before the attach.
func (w *world) sessionFor(t *testing.T, linked wa.Identity) {
	t.Helper()
	w.exec(context.Background(), t, `INSERT INTO whatsmeow_device (jid, registration_id) VALUES ($1, 1)`, linked.PN.String())
}

// numberRowSent is device's row in the last numbers section of ws the fake
// keeps, with the section's accepts.
func (w *world) numberRowSent(ws, device uuid.UUID) (kc.NumberRow, []string, bool) {
	doc, ok := w.fake.Settings("wappie", ws.String(), kc.SectionNumbers)
	if !ok {
		return kc.NumberRow{}, nil, false
	}
	var data kc.NumbersSettings
	if json.Unmarshal(doc.Data, &data) != nil {
		return kc.NumberRow{}, nil, false
	}
	for _, it := range data.Items {
		if it.ID == device.String() {
			return it, doc.Accepts, true
		}
	}
	return kc.NumberRow{}, doc.Accepts, false
}

// canRelinkSent waits for device's can_relink sent as want.
func (w *world) canRelinkSent(t *testing.T, ws, device uuid.UUID, want bool) {
	t.Helper()
	eventually(t, soon, fmt.Sprintf("can_relink %v sent", want), func() bool {
		row, accepts, ok := w.numberRowSent(ws, device)
		return ok && row.CanRelink != nil && *row.CanRelink == want && containsKind(accepts, kc.OpItemRelink)
	})
}

func containsKind(kinds []string, kind string) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// issueRelink issues an item.relink of device in ws by actor.
func (w *world) issueRelink(t *testing.T, ws, device, actor uuid.UUID) string {
	t.Helper()
	id, err := w.fake.IssueCommand("wappie", contracttest.CommandSpec{Kind: kc.OpItemRelink, Workspace: ws.String(), Actor: actor.String(),
		Target: kc.CommandTarget{Item: device.String()}})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// resultKept waits for the fake to keep id's result of outcome (and code,
// for a refusal).
func (w *world) resultKept(t *testing.T, id, outcome, code string) kc.CommandResult {
	t.Helper()
	var res kc.CommandResult
	eventually(t, soon, fmt.Sprintf("the result %s %s kept", outcome, code), func() bool {
		var ok bool
		res, ok = w.fake.CommandResult("wappie", id)
		return ok && res.Outcome == outcome && refusedCode(res) == code
	})
	return res
}

// TestRelinkFromTheConsole: the numbers section offers item.relink and
// says can_relink of a number its phone logged out; an admin's relink is
// in_progress at a seq at once, so the workspace's next command runs (a
// rename meanwhile runs); each QR goes to the pairing route as WhatsApp
// gives it, seq rising, expires_at its own capped at 90 s ahead, a stale
// one never sent; can_relink is false while it pairs; the scan by the
// number's own account attaches the new link and answers ran, at the seq
// the numbers section shows it at, capture on and the pause lifted; and no
// QR is ever logged.
func TestRelinkFromTheConsole(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	device, ident := w.loggedOut(t, w.team, "Loja", 1, w.owner)
	if _, err := store.NewDevices(w.pool).Pause(ctx, w.team, device, store.PauseActor{User: w.owner}); err != nil {
		t.Fatal(err)
	}
	rig := w.relinkRig(t, logs)
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	w.canRelinkSent(t, w.team, device, true)
	if _, accepts, _ := w.numberRowSent(w.team, device); len(accepts) != 9 {
		t.Fatalf("accepts %v", accepts)
	}

	id := w.issueRelink(t, w.team, device, w.sub)
	sp := rig.p.next(t)
	progress := w.resultKept(t, id, kc.OutcomeInProgress, "")
	if progress.StateSeq == nil {
		t.Fatal("in_progress names no state_seq")
	}
	// The workspace's next command runs while the relink pairs.
	rename := w.rename(t, w.team, w.device, w.sub)
	w.resultKept(t, rename, kc.OutcomeRan, "")
	w.canRelinkSent(t, w.team, device, false)

	held := func(seq int64) kc.PairingQR {
		t.Helper()
		var q kc.PairingQR
		eventually(t, soon, fmt.Sprintf("QR %d held", seq), func() bool {
			var ok bool
			q, ok = w.fake.Pairing("wappie", id)
			return ok && q.Seq == seq
		})
		return q
	}
	sp.qr(qrCode(1), time.Now().Add(60*time.Second))
	if q := held(1); q.QR != qrCode(1) || q.ExpiresAt.After(time.Now().Add(kc.MaxPairingAhead)) {
		t.Fatalf("QR 1 held: seq %d, expires %s", q.Seq, q.ExpiresAt)
	}
	// One WhatsApp says lasts longer is capped at 85 s ahead.
	sp.qr(qrCode(2), time.Now().Add(10*time.Minute))
	if q := held(2); q.ExpiresAt.After(time.Now().Add(numberacts.PairingAheadMax)) {
		t.Fatalf("QR 2 expires %s", q.ExpiresAt)
	}
	// Stale while it waited: never sent, its seq skipped.
	puts := w.fake.Count(contracttest.CallPairing)
	sp.qr(qrCode(3), time.Now().Add(-time.Second))
	sp.qr(qrCode(4), time.Now().Add(20*time.Second))
	held(4)
	if n := w.fake.Count(contracttest.CallPairing); n != puts+1 {
		t.Fatalf("%d PUTs for a stale QR and a fresh one", n-puts)
	}

	linked := newLink(ident)
	w.sessionFor(t, linked)
	if err := sp.scan(linked); err != nil {
		t.Fatal(err)
	}
	ran := w.resultKept(t, id, kc.OutcomeRan, "")
	if ran.StateSeq == nil || *ran.StateSeq <= *progress.StateSeq {
		t.Fatalf("ran at %v, in_progress at %d", ran.StateSeq, *progress.StateSeq)
	}
	eventually(t, soon, "the numbers section at ran's seq showing the link", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		row, _, found := w.numberRowSent(w.team, device)
		return ok && found && doc.StateSeq >= *ran.StateSeq && row.Connection == "offline" && row.Capture == "on" && row.PausedBy == nil
	})
	if _, ok := w.fake.Pairing("wappie", id); ok {
		t.Fatal("the platform still holds a QR after the final result")
	}
	eventually(t, soon, "the relink gone from the running ones", func() bool { return !rig.running.Has(device) })
	for i := 1; i <= 4; i++ {
		if strings.Contains(logs.String(), fmt.Sprintf("NotReal%04d", i)) {
			t.Fatalf("QR %d logged:\n%s", i, logs.String())
		}
	}
}

// TestRelinkQRPump: a seq the platform already holds a higher one of
// (accepted false) is delivered and never sent again; a signed not_found
// stops the PUTs while the pairing waits on, its QRs still drained, and
// the pairing's end still answers.
func TestRelinkQRPump(t *testing.T) {
	w := newEventWorld(t)
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	device, _ := w.loggedOut(t, w.team, "Loja", 2, w.owner)
	rig := w.relinkRig(t, logs)
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	w.canRelinkSent(t, w.team, device, true)
	id := w.issueRelink(t, w.team, device, w.sub)
	sp := rig.p.next(t)
	w.resultKept(t, id, kc.OutcomeInProgress, "")

	// The platform holds seq 100 already (another process's PUT).
	client := w.fake.Client("wappie")
	client.Base = w.fake.URL
	if ok, err := client.PutPairing(context.Background(), id, kc.PairingQR{Seq: 100, QR: qrCode(100),
		ExpiresAt: time.Now().Add(60 * time.Second)}); err != nil || !ok {
		t.Fatalf("seq 100: %v %v", ok, err)
	}
	puts := w.fake.Count(contracttest.CallPairing)
	sp.qr(qrCode(1), time.Now().Add(20*time.Second))
	eventually(t, soon, "QR 1 answered accepted false", func() bool { return w.fake.Count(contracttest.CallPairing) == puts+1 })
	if q, ok := w.fake.Pairing("wappie", id); !ok || q.Seq != 100 {
		t.Fatalf("held %d", q.Seq)
	}

	// QR 2 refused not_found: the PUT that follows QR 1's is QR 2's, so QR 1
	// was never sent again.
	w.fake.RefuseAlways(contracttest.CallPairing, kc.CodeNotFound)
	sp.qr(qrCode(2), time.Now().Add(20*time.Second))
	eventually(t, soon, "QR 2 refused not_found", func() bool {
		return len(logs.Lines("relink: the platform takes no more QRs for the command")) == 1
	})
	if n := w.fake.Count(contracttest.CallPairing); n != puts+2 {
		t.Fatalf("%d PUTs for QR 1 and QR 2", n-puts)
	}
	w.fake.RefuseAlways(contracttest.CallPairing, "")
	for i := 3; i < 12; i++ {
		sp.qr(qrCode(i), time.Now().Add(20*time.Second))
	}
	sp.end(wa.PairEvent{Kind: wa.PairEventTimeout, Err: wa.ErrLinkTimeout})
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeLinkTimeout)
	if n := w.fake.Count(contracttest.CallPairing); n != puts+2 {
		t.Fatalf("%d PUTs after the not_found", n-puts-2)
	}
	if len(logs.Lines("relink: the platform takes no more QRs for the command")) != 1 {
		t.Fatalf("the log:\n%s", logs.String())
	}
}

// TestRelinkEnds: each end of a pairing but ran is its final result over
// the in_progress, the number as it was: WhatsApp's window with no scan
// (link_timeout), another account (other_account), a link that did not
// finish (connect_failed), a sync stop while it pairs (it runs; the relink
// state_changed, the pause kept), a move's pause (item_busy, a retry), and
// the number deleted (state_changed).
// While it pairs, a second relink and a sync now are item_busy with the
// seconds left in the window.
func TestRelinkEnds(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	rig := w.relinkRig(t, logs)
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	n := 10
	start := func() (uuid.UUID, string, *scriptPairing) {
		t.Helper()
		n++
		device, _ := w.loggedOut(t, w.team, "Loja", n, w.owner)
		w.canRelinkSent(t, w.team, device, true)
		id := w.issueRelink(t, w.team, device, w.sub)
		sp := rig.p.next(t)
		w.resultKept(t, id, kc.OutcomeInProgress, "")
		return device, id, sp
	}
	row := func(device uuid.UUID) store.Device {
		t.Helper()
		d, err := store.NewDevices(w.pool).Get(ctx, w.team.String(), device.String())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	device, id, sp := start()
	second := w.issueRelink(t, w.team, device, w.sub)
	busy := w.resultKept(t, second, kc.OutcomeRefused, kc.CodeItemBusy)
	if busy.RetryAfter == nil || *busy.RetryAfter < 1 || *busy.RetryAfter > int64(wa.PairWindow/time.Second) {
		t.Fatalf("a second relink's wait %v", busy.RetryAfter)
	}
	syncNow, err := w.fake.IssueCommand("wappie", contracttest.CommandSpec{Kind: kc.OpItemSyncNow, Workspace: w.team.String(),
		Actor: w.sub.String(), Target: kc.CommandTarget{Item: device.String()}})
	if err != nil {
		t.Fatal(err)
	}
	// Logged out, a sync now would be read_only: while it pairs, item_busy.
	if res := w.resultKept(t, syncNow, kc.OutcomeRefused, kc.CodeItemBusy); res.RetryAfter == nil || *res.RetryAfter < 1 {
		t.Fatalf("a sync now's wait %v", res.RetryAfter)
	}
	sp.end(wa.PairEvent{Kind: wa.PairEventTimeout, Err: wa.ErrLinkTimeout})
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeLinkTimeout)
	if d := row(device); d.Status != wa.StatusLoggedOut {
		t.Fatalf("a link_timeout changed the number: %s", d.Status)
	}

	_, id, sp = start()
	sp.end(wa.PairEvent{Kind: wa.PairEventError, Err: &wa.OtherAccount{Half: "phone"}})
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeOtherAccount)

	_, id, sp = start()
	sp.end(wa.PairEvent{Kind: wa.PairEventError, Err: wa.ErrLinkFailed})
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeConnectFailed)

	device, id, _ = start()
	stop, err := w.fake.IssueCommand("wappie", contracttest.CommandSpec{Kind: kc.OpItemSyncStop, Workspace: w.team.String(),
		Actor: w.sub.String(), Target: kc.CommandTarget{Item: device.String()},
		Params: json.RawMessage(`{"before":{"capture":"on"},"after":{"capture":"paused"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	w.resultKept(t, stop, kc.OutcomeRan, "")
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeStateChanged)
	if d := row(device); !d.Paused || d.Status != wa.StatusLoggedOut {
		t.Fatalf("after the stop: paused %v, %s", d.Paused, d.Status)
	}

	// Wappie's own transfer while it pairs: its pause, then its cancel
	// (wsapi's cancelDevicePairing). A retry, item_busy with WhatsApp's
	// whole window, never the final state_changed (DS56).
	device, id, _ = start()
	if _, err := store.NewDevices(w.pool).PauseForMove(ctx, w.team, device); err != nil {
		t.Fatal(err)
	}
	rig.running.Cancel(device)
	if res := w.resultKept(t, id, kc.OutcomeRefused, kc.CodeItemBusy); res.RetryAfter == nil ||
		*res.RetryAfter != int64(wa.PairWindow/time.Second) {
		t.Fatalf("a move's wait %v", res.RetryAfter)
	}

	device, id, _ = start()
	if _, err := store.NewDevices(w.pool).Quarantine(ctx, w.team, w.owner, device, []uuid.UUID{w.owner}); err != nil {
		t.Fatal(err)
	}
	rig.running.Cancel(device) // wsapi's cancelDevicePairing, at the deletion
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeStateChanged)
	// Deleted, not recovered: not_found, can_relink false.
	w.canRelinkSent(t, w.team, device, false)
}

// TestRelinkLeftInProgressAtStart: a relink row a leader left in_progress
// (a restart, a takeover) is answered by the next leader's sweep before
// any row runs, once nothing pairs its number here: connect_failed, or
// state_changed for a number deleted or no longer logged out.
func TestRelinkLeftInProgressAtStart(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	orphan, _ := w.loggedOut(t, w.team, "Órfão", 31, w.owner)
	online, _ := w.loggedOut(t, w.team, "Online", 32, w.owner)
	gone, _ := w.loggedOut(t, w.team, "Apagado", 33, w.owner)
	pairing, _ := w.loggedOut(t, w.team, "Pareando", 34, w.owner)
	docs := map[uuid.UUID]int64{w.sub: w.version(t, w.sub)}
	expires := time.Now().Add(5 * time.Minute)
	ids := map[uuid.UUID]uuid.UUID{}
	for _, device := range []uuid.UUID{orphan, online, gone, pairing} {
		id := w.take(t, row{kind: kc.OpItemRelink, ws: &w.team, actor: w.sub, target: item(device), docs: docs, expires: &expires})
		w.exec(ctx, t, `UPDATE contract_commands SET outcome = 'in_progress', state_seq = 1, result_at = clock_timestamp() WHERE id = $1`, id)
		ids[device] = id
	}
	if err := store.NewDevices(w.pool).SetStatus(ctx, w.team.String(), online.String(), wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewDevices(w.pool).Quarantine(ctx, w.team, w.owner, gone, []uuid.UUID{w.owner}); err != nil {
		t.Fatal(err)
	}
	rig := w.relinkRig(t, logs)
	rig.p.since[pairing.String()] = time.Now()
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	for device, code := range map[uuid.UUID]string{orphan: kc.CodeConnectFailed, online: kc.CodeStateChanged, gone: kc.CodeStateChanged} {
		eventually(t, soon, "the sweep's "+code, func() bool {
			r, _ := w.ledgerRow(t, ids[device].String())
			return r.outcome == store.CommandRefused && r.code == code && r.stateSeq != nil
		})
	}
	if r, _ := w.ledgerRow(t, ids[pairing].String()); r.outcome != store.CommandInProgress {
		t.Fatalf("a relink whose number pairs here was answered: %+v", r)
	}
}

// TestRelinkOrder: item.relink's checks, each answered in the order of the
// spec's 14.6 and 14.13, every one before any QR: not_found, item_busy
// (before the role), not_authorized, expired (no state_seq), then the
// relink's own table (state_changed, item_busy for a hold, read_only,
// no_reader, number_held), then a pause later than based_on
// (state_changed); a number that passes them all starts a pairing.
func TestRelinkOrder(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	rig := w.relinkRig(t, logs)
	put := &putRecorder{}
	rig.cfg.Acts.PutPairing = put.put
	l := w.settingsLeader(w.members, logs, rig.cfg)
	sw := newSettingsWork(l, &follower{l: l, round: make(chan struct{}, 1)})
	on := store.SettingsOn
	sw.current.Store(&on)
	docs := func() map[uuid.UUID]int64 {
		return map[uuid.UUID]int64{w.sub: w.version(t, w.sub), w.secondSub: w.version(t, w.secondSub)}
	}
	later := time.Now().Add(5 * time.Minute)
	check := func(what string, device uuid.UUID, actor uuid.UUID, mutate func(r *row), code string, judged bool) {
		t.Helper()
		r := row{kind: kc.OpItemRelink, ws: &w.team, actor: actor, target: item(device), docs: docs(), expires: &later}
		if mutate != nil {
			mutate(&r)
		}
		id := w.take(t, r)
		w.runNext(t, sw)
		got, _ := w.ledgerRow(t, id.String())
		if got.outcome != store.CommandRefused || got.code != code || (got.stateSeq != nil) != judged {
			t.Fatalf("%s: %+v, want %s (judged on a seq: %v)", what, got, code, judged)
		}
	}

	device, ident := w.loggedOut(t, w.team, "Loja", 41, w.owner)
	gone, _ := w.loggedOut(t, w.team, "Apagado", 42, w.owner)
	if _, err := store.NewDevices(w.pool).Quarantine(ctx, w.team, w.owner, gone, []uuid.UUID{w.owner}); err != nil {
		t.Fatal(err)
	}
	check("a deleted number", gone, w.secondSub, nil, kc.CodeNotFound, true)
	rig.p.mu.Lock()
	rig.p.since[device.String()] = time.Now().Add(-100 * time.Second)
	rig.p.mu.Unlock()
	check("a pairing here, by a member", device, w.secondSub, nil, kc.CodeItemBusy, true)
	rig.p.mu.Lock()
	delete(rig.p.since, device.String())
	rig.p.mu.Unlock()
	w.inWorkspace(t, w.team, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET paused = true, pause_cause = 'move' WHERE id = $1`, device)
		return err
	})
	check("a move's pause, by a member", device, w.secondSub, nil, kc.CodeItemBusy, true)
	w.inWorkspace(t, w.team, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET paused = false WHERE id = $1`, device)
		return err
	})
	check("a member", device, w.secondSub, nil, kc.CodeNotAuthorized, true)
	past := time.Now().Add(-time.Second)
	check("past its expires_at", device, w.sub, func(r *row) { r.expires = &past }, kc.CodeExpired, false)

	online, _ := w.loggedOut(t, w.team, "Online", 43, w.owner)
	if err := store.NewDevices(w.pool).SetStatus(ctx, w.team.String(), online.String(), wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	check("a number online", online, w.sub, nil, kc.CodeStateChanged, true)
	rig.p.mu.Lock()
	rig.p.held[device.String()] = true
	rig.p.mu.Unlock()
	check("a hold that is not stale", device, w.sub, nil, kc.CodeItemBusy, true)
	rig.p.mu.Lock()
	delete(rig.p.held, device.String())
	rig.p.mu.Unlock()
	half, _ := w.loggedOut(t, w.team, "Meio", 44, w.owner)
	w.inWorkspace(t, w.team, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET lid = NULL WHERE id = $1`, half)
		return err
	})
	check("half an identity", half, w.sub, nil, kc.CodeReadOnly, true)
	keyless, _ := w.loggedOut(t, w.team, "Sem chave", 45)
	check("nobody holds the key", keyless, w.sub, nil, kc.CodeNoReader, true)
	twin, twinID := w.loggedOut(t, w.team, "Gêmeo", 46, w.owner)
	other, _ := w.loggedOut(t, w.team, "Outro", 47, w.owner)
	w.inWorkspace(t, w.team, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET lid = NULL, pn = $2, status = 'online', status_reason = '' WHERE id = $1`, other,
			types.JID{User: twinID.PN.User, Device: 9, Server: types.DefaultUserServer}.String())
		return err
	})
	check("the account linked as another number", twin, w.sub, nil, kc.CodeNumberHeld, true)

	if _, err := store.NewDevices(w.pool).Pause(ctx, w.team, device, store.PauseActor{User: w.owner}); err != nil {
		t.Fatal(err)
	}
	check("a pause later than based_on", device, w.sub, nil, kc.CodeStateChanged, true)

	// Drawn after the pause: it starts. based_on is the pause's own time,
	// on the database's clock that stamped it (Go's may run behind it).
	var pausedAt int64
	w.inWorkspace(t, w.team, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT floor(extract(epoch FROM paused_at) * 1000)::bigint FROM devices WHERE id = $1`,
			device).Scan(&pausedAt)
	})
	id := w.take(t, row{kind: kc.OpItemRelink, ws: &w.team, actor: w.sub, target: item(device), docs: docs(), expires: &later,
		basedOn: pausedAt})
	w.runNext(t, sw)
	if got, _ := w.ledgerRow(t, id.String()); got.outcome != store.CommandInProgress || got.stateSeq == nil {
		t.Fatalf("a relink that passes: %+v", got)
	}
	sp := rig.p.next(t)
	_ = ident
	sp.end(wa.PairEvent{Kind: wa.PairEventTimeout, Err: wa.ErrLinkTimeout})
	eventually(t, soon, "the relink's end", func() bool {
		r, _ := w.ledgerRow(t, id.String())
		return r.code == kc.CodeLinkTimeout
	})
	if put.count() != 0 {
		t.Fatalf("%d QRs sent with none given", put.count())
	}
}

// putRecorder is a pairing route that keeps what it is sent.
type putRecorder struct {
	mu  sync.Mutex
	got []kc.PairingQR
}

func (p *putRecorder) put(_ context.Context, _ uuid.UUID, q kc.PairingQR) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got = append(p.got, q)
	return true, nil
}

func (p *putRecorder) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.got)
}

// TestDeleteRecoverRelink: a number deleted is logged_out_deletion,
// can_relink false, and a relink of it not_found; recovered, it is still
// logged_out_deletion, now with can_relink true, and a console relink
// attaches the scan of its own account: ran, capture on, paused_by null,
// connection offline until its client connects.
func TestDeleteRecoverRelink(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	devices := store.NewDevices(w.pool)
	d, err := devices.Create(ctx, w.team.String(), "Loja", wa.ModeActive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(d.ID)
	ident := wa.Identity{PN: types.JID{User: "155501090051", Device: 3, Server: types.DefaultUserServer},
		LID: types.JID{User: "100000000090051", Device: 3, Server: types.HiddenUserServer}}
	if err := devices.SetIdentity(ctx, w.team.String(), d.ID, ident); err != nil {
		t.Fatal(err)
	}
	if err := devices.SetStatus(ctx, w.team.String(), d.ID, wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	w.inWorkspace(t, w.team, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET current_epoch = 1 WHERE id = $1`, device); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key)
			VALUES ($1, $2, 1, decode(repeat('ab', 32), 'hex'))`, w.team, device); err != nil {
			return err
		}
		return readsTx(ctx, tx, w.team, device, w.owner)
	})
	rig := w.relinkRig(t, logs)
	run(t, w.settingsLeader(w.members, logs, rig.cfg))

	// With no session stored, the deletion logs the number out at once
	// (its cause the deletion's), and keeps it paused, deleted.
	if _, err := devices.Quarantine(ctx, w.team, w.owner, device, []uuid.UUID{w.owner}); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "logged_out_deletion, can_relink false", func() bool {
		row, _, ok := w.numberRowSent(w.team, device)
		return ok && row.Connection == "logged_out_deletion" && row.CanRelink != nil && !*row.CanRelink
	})
	id := w.issueRelink(t, w.team, device, w.sub)
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeNotFound)

	if _, err := devices.Recover(ctx, w.team, w.owner, device); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "recovered: logged_out_deletion, can_relink true", func() bool {
		row, _, ok := w.numberRowSent(w.team, device)
		return ok && row.Connection == "logged_out_deletion" && row.CanRelink != nil && *row.CanRelink
	})
	id = w.issueRelink(t, w.team, device, w.sub)
	sp := rig.p.next(t)
	w.resultKept(t, id, kc.OutcomeInProgress, "")
	linked := newLink(ident)
	w.sessionFor(t, linked)
	if err := sp.scan(linked); err != nil {
		t.Fatal(err)
	}
	ran := w.resultKept(t, id, kc.OutcomeRan, "")
	eventually(t, soon, "the number linked again in the section", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		row, _, found := w.numberRowSent(w.team, device)
		return ok && found && doc.StateSeq >= *ran.StateSeq && row.Connection == "offline" && row.Capture == "on" &&
			row.PausedBy == nil && !row.ReadOnly
	})
}

// TestRelinkDeletedWhilePairing: a recovered number deleted again while its
// relink pairs ends it state_changed; the scan that comes after attaches
// nothing.
func TestRelinkDeletedWhilePairing(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	device, ident := w.loggedOut(t, w.team, "Loja", 61, w.owner)
	rig := w.relinkRig(t, logs)
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	w.canRelinkSent(t, w.team, device, true)
	id := w.issueRelink(t, w.team, device, w.sub)
	sp := rig.p.next(t)
	w.resultKept(t, id, kc.OutcomeInProgress, "")
	if _, err := store.NewDevices(w.pool).Quarantine(ctx, w.team, w.owner, device, []uuid.UUID{w.owner}); err != nil {
		t.Fatal(err)
	}
	linked := newLink(ident)
	w.sessionFor(t, linked)
	if err := sp.scan(linked); !errors.Is(err, store.ErrRelinkStateChanged) {
		t.Fatalf("a scan after the deletion = %v", err)
	}
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeStateChanged)
}

// TestRelinkFirstQRAfterInProgress: the in_progress goes first, then the
// first PUT (the platform's question 5's default): while the results
// cannot be posted, the first QR is held, never sent; once the in_progress
// is posted, the newest QR held goes, after it.
func TestRelinkFirstQRAfterInProgress(t *testing.T) {
	w := newEventWorld(t)
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	device, _ := w.loggedOut(t, w.team, "Loja", 71, w.owner)
	rig := w.relinkRig(t, logs)
	rig.cfg.Acts.PostedPoll = 20 * time.Millisecond
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	w.canRelinkSent(t, w.team, device, true)

	w.fake.RefuseAlways(contracttest.CallResults, kc.CodeRateLimited)
	results := w.fake.Count(contracttest.CallResults)
	id := w.issueRelink(t, w.team, device, w.sub)
	sp := rig.p.next(t)
	// Every PUT finds the in_progress kept already.
	var early sync.Once
	var first error
	w.fake.Before(contracttest.CallPairing, func(string) {
		if _, ok := w.fake.CommandResult("wappie", id); !ok {
			early.Do(func() { first = errors.New("a QR went before the in_progress") })
		}
	})
	sp.qr(qrCode(1), time.Now().Add(60*time.Second))
	eventually(t, soon, "the in_progress refused twice", func() bool { return w.fake.Count(contracttest.CallResults) >= results+2 })
	if n := w.fake.Count(contracttest.CallPairing); n != 0 {
		t.Fatalf("%d PUTs before the in_progress was posted", n)
	}
	w.fake.RefuseAlways(contracttest.CallResults, "")
	w.resultKept(t, id, kc.OutcomeInProgress, "")
	eventually(t, soon, "QR 1 held after the in_progress", func() bool {
		q, ok := w.fake.Pairing("wappie", id)
		return ok && q.Seq == 1
	})
	w.fake.Before(contracttest.CallPairing, nil)
	if first != nil {
		t.Fatal(first)
	}
	sp.end(wa.PairEvent{Kind: wa.PairEventTimeout, Err: wa.ErrLinkTimeout})
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeLinkTimeout)
}

// TestRelinkPumpRechecks: a change no process's cancel reached (a stop
// another process ran, a storage stop) ends the pairing at the next QR,
// which is never sent, and the end names it: state_changed for a pause,
// storage_paused for the storage.
func TestRelinkPumpRechecks(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	rig := w.relinkRig(t, logs)
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	for i, c := range []struct {
		what   string
		change func(device uuid.UUID)
		undo   func()
		code   string
	}{
		{"a pause no cancel reached", func(device uuid.UUID) {
			if _, err := store.NewDevices(w.pool).Pause(ctx, w.team, device, store.PauseActor{User: w.owner}); err != nil {
				t.Fatal(err)
			}
		}, nil, kc.CodeStateChanged},
		{"the storage stopped", func(uuid.UUID) {
			w.exec(ctx, t, `UPDATE tenants SET storage_paused_at = clock_timestamp() WHERE id = $1`, w.team)
		}, func() { w.exec(ctx, t, `UPDATE tenants SET storage_paused_at = NULL WHERE id = $1`, w.team) }, kc.CodeStoragePaused},
	} {
		device, _ := w.loggedOut(t, w.team, "Loja", 80+i, w.owner)
		w.canRelinkSent(t, w.team, device, true)
		id := w.issueRelink(t, w.team, device, w.sub)
		sp := rig.p.next(t)
		w.resultKept(t, id, kc.OutcomeInProgress, "")
		puts := w.fake.Count(contracttest.CallPairing)
		c.change(device)
		sp.qr(qrCode(80+i), time.Now().Add(20*time.Second))
		w.resultKept(t, id, kc.OutcomeRefused, c.code)
		if n := w.fake.Count(contracttest.CallPairing); n != puts {
			t.Fatalf("%s: %d QRs sent", c.what, n-puts)
		}
		if c.undo != nil {
			c.undo()
		}
	}
}

// TestRelinkEndsAtStartAndAttach: the ends the start and the attach give,
// each a final result over the in_progress, the number as it was: a
// pairing that cannot start (connect_failed; storage_paused for a storage
// stop), the account taken by another number before the scan
// (number_held), and a scan whose session was not stored (connect_failed).
func TestRelinkEndsAtStartAndAttach(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	rig := w.relinkRig(t, logs)
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	n := 90
	number := func() (uuid.UUID, wa.Identity) {
		t.Helper()
		n++
		device, ident := w.loggedOut(t, w.team, "Loja", n, w.owner)
		w.canRelinkSent(t, w.team, device, true)
		return device, ident
	}
	ledgerOf := func(id string) ledgerRow {
		t.Helper()
		r, _ := w.ledgerRow(t, id)
		return r
	}

	for _, c := range []struct {
		fail error
		code string
	}{
		{errors.New("the pairing could not start"), kc.CodeConnectFailed},
		{store.ErrStoragePaused, kc.CodeStoragePaused},
	} {
		device, _ := number()
		rig.p.mu.Lock()
		rig.p.fail = c.fail
		rig.p.mu.Unlock()
		id := w.issueRelink(t, w.team, device, w.sub)
		w.resultKept(t, id, kc.OutcomeRefused, c.code)
		if r := ledgerOf(id); r.outcome != store.CommandRefused || r.stateSeq == nil {
			t.Fatalf("a start that failed %s: %+v", c.code, r)
		}
		if rig.running.Has(device) {
			t.Fatalf("a start that failed %s is still running", c.code)
		}
	}

	// Another number takes the account between the start and the scan.
	device, ident := number()
	id := w.issueRelink(t, w.team, device, w.sub)
	sp := rig.p.next(t)
	w.resultKept(t, id, kc.OutcomeInProgress, "")
	other, _ := number()
	w.inWorkspace(t, w.team, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET lid = NULL, pn = $2, status = 'online', status_reason = '' WHERE id = $1`, other,
			types.JID{User: ident.PN.User, Device: 9, Server: types.DefaultUserServer}.String())
		return err
	})
	linked := newLink(ident)
	w.sessionFor(t, linked)
	if err := sp.scan(linked); !errors.Is(err, store.ErrRelinkNumberHeld) {
		t.Fatalf("a scan of an account another number holds = %v", err)
	}
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeNumberHeld)
	if d, err := store.NewDevices(w.pool).Get(ctx, w.team.String(), device.String()); err != nil || d.Status != wa.StatusLoggedOut {
		t.Fatalf("a number_held changed the number: %+v %v", d.Status, err)
	}

	// A scan whose new link's session was not stored.
	device, ident = number()
	id = w.issueRelink(t, w.team, device, w.sub)
	sp = rig.p.next(t)
	w.resultKept(t, id, kc.OutcomeInProgress, "")
	if err := sp.scan(newLink(ident)); !errors.Is(err, store.ErrRelinkNoSession) {
		t.Fatalf("a scan with no session stored = %v", err)
	}
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeConnectFailed)
}

// TestRelinkLeaderStops: a leader that stops leading cancels its console
// relinks, whose ends are written at once (connect_failed), and the next
// leader posts them.
func TestRelinkLeaderStops(t *testing.T) {
	w := newEventWorld(t)
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	device, _ := w.loggedOut(t, w.team, "Loja", 101, w.owner)
	rig := w.relinkRig(t, logs)
	stop := run(t, w.settingsLeader(w.members, logs, rig.cfg))
	w.canRelinkSent(t, w.team, device, true)
	id := w.issueRelink(t, w.team, device, w.sub)
	rig.p.next(t)
	w.resultKept(t, id, kc.OutcomeInProgress, "")

	stop()
	eventually(t, soon, "the end written as the leader stopped", func() bool {
		r, _ := w.ledgerRow(t, id)
		return r.outcome == store.CommandRefused && r.code == kc.CodeConnectFailed && r.stateSeq != nil
	})
	if rig.running.Has(device) {
		t.Fatal("a relink outlived its leader")
	}
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	w.resultKept(t, id, kc.OutcomeRefused, kc.CodeConnectFailed)
}

// TestRelinkSweepWaitsForTheNumber: the sweep answers a relink row left
// in_progress only once nothing holds its number: not while this process
// pairs it, nor while another process's registry holds its lock (an old
// leader still pairing it); a later sweep, at a ledger trim, answers it
// then.
func TestRelinkSweepWaitsForTheNumber(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	pairing, _ := w.loggedOut(t, w.team, "Pareando", 111, w.owner)
	elsewhere, _ := w.loggedOut(t, w.team, "Noutro", 112, w.owner)
	docs := map[uuid.UUID]int64{w.sub: w.version(t, w.sub)}
	expires := time.Now().Add(5 * time.Minute)
	ids := map[uuid.UUID]uuid.UUID{}
	for _, device := range []uuid.UUID{pairing, elsewhere} {
		id := w.take(t, row{kind: kc.OpItemRelink, ws: &w.team, actor: w.sub, target: item(device), docs: docs, expires: &expires})
		w.exec(ctx, t, `UPDATE contract_commands SET outcome = 'in_progress', state_seq = 1, result_at = clock_timestamp() WHERE id = $1`, id)
		ids[device] = id
	}
	// The other process's registry: the number's lock, on a connection of
	// its own.
	release, ok, err := pg.NewLocker(w.pool).TryLock(ctx, wa.DeviceLockKey(elsewhere.String()))
	if err != nil || !ok {
		t.Fatalf("the other process's lock: %v %v", ok, err)
	}
	defer release()
	rig := w.relinkRig(t, logs)
	rig.cfg.TrimEvery = 100 * time.Millisecond
	rig.p.mu.Lock()
	rig.p.since[pairing.String()] = time.Now()
	rig.p.mu.Unlock()
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	// Several sweeps pass, the trim's notice in the log.
	eventually(t, soon, "the leader's executor running", func() bool {
		return w.fake.Count(contracttest.CallCommands) >= 3
	})
	time.Sleep(5 * rig.cfg.TrimEvery)
	for device, id := range ids {
		if r, _ := w.ledgerRow(t, id.String()); r.outcome != store.CommandInProgress {
			t.Fatalf("a relink whose number is held (%s) was answered: %+v", device, r)
		}
	}
	rig.p.mu.Lock()
	delete(rig.p.since, pairing.String())
	rig.p.mu.Unlock()
	release()
	for _, id := range ids {
		eventually(t, soon, "a later sweep's connect_failed", func() bool {
			r, _ := w.ledgerRow(t, id.String())
			return r.outcome == store.CommandRefused && r.code == kc.CodeConnectFailed && r.stateSeq != nil
		})
	}
}

// TestNumbersCanRelinkLearnsTheMap: a logged-out number with half its
// identity stored is can_relink false while whatsmeow's map knows no other
// half; once the map learns it, the section goes again with can_relink
// true, with no change of the number's row, as the relink's Check would
// then pass.
func TestNumbersCanRelinkLearnsTheMap(t *testing.T) {
	w := newEventWorld(t)
	logs := &membershiptest.Logs{}
	w.settingsOn(t, store.SettingsOn)
	device, ident := w.loggedOut(t, w.team, "Meio", 121, w.owner)
	w.inWorkspace(t, w.team, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE devices SET lid = NULL WHERE id = $1`, device)
		return err
	})
	book := &learningBook{}
	rig := w.relinkRig(t, logs)
	rig.cfg.Identities = book
	run(t, w.settingsLeader(w.members, logs, rig.cfg))
	w.canRelinkSent(t, w.team, device, false)
	book.learn(ident.LID.ToNonAD())
	w.canRelinkSent(t, w.team, device, true)
}

// learningBook is whatsmeow's map of LIDs and phone numbers, which learns
// a LID while a test runs.
type learningBook struct {
	mu  sync.Mutex
	lid types.JID
}

func (b *learningBook) learn(lid types.JID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lid = lid
}

func (b *learningBook) PhoneFor(context.Context, types.JID) (types.JID, bool) {
	return types.JID{}, false
}

func (b *learningBook) LIDFor(context.Context, types.JID) (types.JID, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lid, !b.lid.IsEmpty()
}
