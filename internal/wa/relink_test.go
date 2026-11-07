package wa_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"

	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

// Fictional accounts only.
var (
	relinkPN  = types.JID{User: "155501000011", Device: 3, Server: types.DefaultUserServer}
	relinkLID = types.JID{User: "100000000000011", Device: 3, Server: types.HiddenUserServer}
	linkPN    = types.JID{User: relinkPN.User, Device: 9, Server: types.DefaultUserServer}
	linkLID   = types.JID{User: relinkLID.User, Device: 9, Server: types.HiddenUserServer}
	strangePN = types.JID{User: "155501000012", Device: 9, Server: types.DefaultUserServer}
)

const (
	relinkTenant = "22222222-2222-2222-2222-222222222222"
	relinkDevice = "33333333-3333-3333-3333-333333333333"
	fakeQR       = "https://wa.me/settings/linked_devices#2@test-ref-not-real,AAAA,BBBB,CCCC,9"
)

// countingContainer is the session store under a relink's account check.
type countingContainer struct {
	mu      sync.Mutex
	puts    int
	deletes int
}

func (c *countingContainer) PutDevice(context.Context, *store.Device) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts++
	return nil
}

func (c *countingContainer) DeleteDevice(context.Context, *store.Device) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deletes++
	return nil
}

func (c *countingContainer) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.puts, c.deletes
}

// eventSink records what reaches the archive.
type eventSink struct {
	mu     sync.Mutex
	events []any
}

func (s *eventSink) Handle(_ context.Context, _ string, evt any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *eventSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// syncBuffer is a log destination safe from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// relinkRig is a registry whose pairing client is the fake: a test plays
// whatsmeow's part on the device the pairing built.
type relinkRig struct {
	r       *wa.Registry
	fake    *fakewa.Client
	inner   *countingContainer
	st      *memStore
	sink    *eventSink
	locker  *lockStub
	log     *syncBuffer
	statusN int

	mu sync.Mutex
	ds *store.Device

	attachMu sync.Mutex
	attached []wa.Identity
	attachFn func(wa.Identity) error
	dropped  []types.JID
}

func newRelinkRig(t *testing.T) *relinkRig {
	t.Helper()
	rig := &relinkRig{
		fake: fakewa.New(), inner: &countingContainer{}, st: &memStore{}, sink: &eventSink{},
		locker: &lockStub{}, log: &syncBuffer{},
	}
	rig.r = wa.NewRegistryForTest(wa.RegistryConfig{
		Store: rig.st, Sink: rig.sink, Locker: rig.locker,
		Log: slog.New(slog.NewTextHandler(rig.log, &slog.HandlerOptions{Level: slog.LevelInfo})),
		OnStatus: func(string, string, wa.Status, string) {
			rig.mu.Lock()
			rig.statusN++
			rig.mu.Unlock()
		},
		NewPairingDevice: func() *store.Device { return &store.Device{Container: rig.inner} },
		NewPairingClient: func(ds *store.Device, _ waLog.Logger) wa.Client {
			rig.mu.Lock()
			rig.ds = ds
			rig.mu.Unlock()
			return rig.fake
		},
	}, func(context.Context, types.JID) (*store.Device, error) { return nil, nil })
	return rig
}

func (rig *relinkRig) start(t *testing.T) *wa.PairSession {
	t.Helper()
	s, err := rig.r.StartPairing(context.Background(), relinkTenant, relinkDevice, wa.ReceiptPolicy{Mode: wa.ModePassive},
		wa.PairOptions{Method: wa.PairByQR, Relink: &wa.Relink{
			Expect: wa.Identity{PN: relinkPN, LID: relinkLID},
			Attach: func(_ context.Context, linked wa.Identity) error {
				rig.attachMu.Lock()
				defer rig.attachMu.Unlock()
				rig.attached = append(rig.attached, linked)
				if rig.attachFn != nil {
					return rig.attachFn(linked)
				}
				return nil
			},
			Discarded: func(_ context.Context, jid types.JID) {
				rig.attachMu.Lock()
				defer rig.attachMu.Unlock()
				rig.dropped = append(rig.dropped, jid)
			},
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Cancel(); rig.r.StopAll(context.Background()) })
	return s
}

// scan plays whatsmeow's order on the pairing's device: the new link's JIDs
// in memory, then the first write, which the account check guards.
func (rig *relinkRig) scan(pn, lid types.JID) error {
	rig.mu.Lock()
	ds := rig.ds
	rig.mu.Unlock()
	ds.ID, ds.LID = &pn, lid
	return ds.Save(context.Background())
}

func (rig *relinkRig) attaches() int {
	rig.attachMu.Lock()
	defer rig.attachMu.Unlock()
	return len(rig.attached)
}

func (rig *relinkRig) statuses() int {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	return rig.statusN
}

func next(t *testing.T, s *wa.PairSession) wa.PairEvent {
	t.Helper()
	select {
	case e, ok := <-s.Events():
		if !ok {
			t.Fatal("the pairing ended with no event")
		}
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no pairing event")
	}
	return wa.PairEvent{}
}

func ended(t *testing.T, s *wa.PairSession) {
	t.Helper()
	select {
	case _, ok := <-s.Events():
		if ok {
			t.Fatal("an event after the pairing's last")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pairing's events did not close")
	}
}

// While the QR shows and until the attach, the number's row is untouched:
// whatever the pairing's client says writes no status and no identity,
// reaches no sink and tells nobody. After the attach the gate opens, the
// client reconnects once WhatsApp asked it to, and the number goes online.
func TestRelinkGateHoldsTheRow(t *testing.T) {
	rig := newRelinkRig(t)
	s := rig.start(t)
	rig.fake.PushQR(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventCode, Code: fakeQR, Timeout: time.Minute})
	if e := next(t, s); e.Kind != wa.PairEventQR || e.Code != fakeQR {
		t.Fatalf("first event %+v, want the QR", e)
	}
	held := rig.r.Held()
	if len(held) != 1 || !held[0].Relinking {
		t.Fatalf("held %+v, want one relinking entry", held)
	}
	if _, ok := rig.r.PairingSince(relinkDevice); !ok {
		t.Fatal("PairingSince has no pairing")
	}

	rig.fake.Emit(&events.PairSuccess{ID: linkPN, LID: linkLID})
	rig.fake.Emit(&events.Disconnected{})
	rig.fake.Emit(&events.Message{})
	if err := rig.scan(linkPN, linkLID); err != nil {
		t.Fatal(err)
	}
	if puts, _ := rig.inner.counts(); puts != 1 {
		t.Fatalf("the session store got %d writes of the number's own link, want 1", puts)
	}
	connectsBefore := rig.fake.Connects()
	rig.fake.Emit(&events.ManualLoginReconnect{})
	if len(rig.st.seen()) != 0 || rig.sink.count() != 0 || rig.statuses() != 0 {
		t.Fatalf("before the attach: statuses %v, %d sink events, %d broadcasts", rig.st.seen(), rig.sink.count(), rig.statuses())
	}

	rig.fake.PushQR(whatsmeow.QRChannelSuccess)
	if e := next(t, s); e.Kind != wa.PairEventSuccess {
		t.Fatalf("end %+v, want success", e)
	}
	ended(t, s)
	if rig.attaches() != 1 || rig.attached[0].PN != linkPN || rig.attached[0].LID != linkLID {
		t.Fatalf("attached %+v, want the new link once", rig.attached)
	}
	if rig.fake.Connects() != connectsBefore+1 {
		t.Fatalf("connects %d, want one reconnect after the attach", rig.fake.Connects()-connectsBefore)
	}
	if held := rig.r.Held(); len(held) != 1 || held[0].Relinking {
		t.Fatalf("held %+v after the attach, want the number held and no longer pairing", held)
	}
	rig.fake.Emit(&events.Connected{})
	if got := rig.st.seen(); len(got) != 1 || got[0] != wa.StatusOnline {
		t.Fatalf("statuses after the attach %v, want online", got)
	}
	if rig.sink.count() == 0 {
		t.Fatal("the sink got nothing after the attach")
	}
}

// Another account is refused at the first write: nothing reaches the
// session store, nothing is attached, and the pairing's hold goes.
func TestRelinkOtherAccountAttachesNothing(t *testing.T) {
	rig := newRelinkRig(t)
	s := rig.start(t)
	refused := rig.scan(strangePN, linkLID)
	if !errors.Is(refused, wa.ErrOtherAccount) {
		t.Fatalf("scan = %v, want other_account", refused)
	}
	// whatsmeow then disconnects and reports the pair error.
	rig.fake.PushQR(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventError, Error: refused})
	e := next(t, s)
	var other *wa.OtherAccount
	if e.Kind != wa.PairEventError || !errors.As(e.Err, &other) || other.Half != "phone" {
		t.Fatalf("end %+v, want other_account on the phone", e)
	}
	ended(t, s)
	if puts, _ := rig.inner.counts(); puts != 0 || rig.attaches() != 0 {
		t.Fatalf("a refused scan wrote %d sessions and %d attaches", puts, rig.attaches())
	}
	if len(rig.r.Held()) != 0 || rig.locker.isHeld() {
		t.Fatal("the refused pairing still holds the number")
	}
}

// A refused attach logs the new link out while connected, says which JID
// went, and lets the number go. When WhatsApp does not confirm, the session
// is deleted anyway.
func TestRelinkAttachFailureLogsTheLinkOut(t *testing.T) {
	stale := errors.New("the number changed during the relink")
	for name, logoutErr := range map[string]error{"confirmed": nil, "unconfirmed": errors.New("no answer")} {
		t.Run(name, func(t *testing.T) {
			rig := newRelinkRig(t)
			rig.attachFn = func(wa.Identity) error { return stale }
			rig.fake.LogoutErr = logoutErr
			s := rig.start(t)
			if err := rig.scan(linkPN, linkLID); err != nil {
				t.Fatal(err)
			}
			rig.fake.SetLoggedIn(true)
			rig.fake.PushQR(whatsmeow.QRChannelSuccess)
			if e := next(t, s); e.Kind != wa.PairEventError || !errors.Is(e.Err, stale) {
				t.Fatalf("end %+v, want the attach's refusal", e)
			}
			ended(t, s)
			if rig.fake.Logouts() != 1 {
				t.Fatalf("logouts %d, want 1", rig.fake.Logouts())
			}
			if len(rig.dropped) != 1 || rig.dropped[0] != linkPN {
				t.Fatalf("discarded %v, want the new link", rig.dropped)
			}
			_, deletes := rig.inner.counts()
			if want := map[bool]int{true: 0, false: 1}[logoutErr == nil]; deletes != want {
				t.Fatalf("session deletes %d, want %d", deletes, want)
			}
			if len(rig.r.Held()) != 0 || rig.locker.isHeld() {
				t.Fatal("the refused link still holds the number")
			}
			if len(rig.st.seen()) != 0 || rig.sink.count() != 0 {
				t.Fatal("a refused link reached the row or the sink")
			}
		})
	}
}

// WhatsApp sends timeout when its codes run out and also when the socket
// drops mid-window: the first is link_timeout, the second a failed link.
func TestRelinkTimeoutOrDrop(t *testing.T) {
	for name, tc := range map[string]struct {
		qrLife time.Duration
		want   error
	}{
		"the window closed":  {qrLife: time.Millisecond, want: wa.ErrLinkTimeout},
		"the socket dropped": {qrLife: time.Minute, want: wa.ErrLinkFailed},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newRelinkRig(t)
			s := rig.start(t)
			rig.fake.PushQR(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventCode, Code: fakeQR, Timeout: tc.qrLife})
			next(t, s)
			rig.fake.PushQR(whatsmeow.QRChannelTimeout)
			if e := next(t, s); e.Kind != wa.PairEventError || !errors.Is(e.Err, tc.want) {
				t.Fatalf("end %+v, want %v", e, tc.want)
			}
			ended(t, s)
			if len(rig.r.Held()) != 0 {
				t.Fatal("the ended pairing still holds the number")
			}
		})
	}
}

// The first QR of a pairing is logged by its length only; no QR's text
// reaches the log.
func TestFirstQRLogsItsLengthOnly(t *testing.T) {
	rig := newRelinkRig(t)
	s := rig.start(t)
	for range 2 {
		rig.fake.PushQR(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventCode, Code: fakeQR, Timeout: time.Minute})
		next(t, s)
	}
	out := rig.log.String()
	if n := strings.Count(out, "pairing QR"); n != 1 || !strings.Contains(out, "qr_length=") {
		t.Fatalf("%d pairing QR lines, want one with its length: %s", n, out)
	}
	if strings.Contains(out, "test-ref-not-real") {
		t.Fatal("a QR's text reached the log")
	}
}

// A deletion during a relink's QR stops the pairing and logs out as for a
// number this process does not hold, never on the pairing's client, which
// never logged in.
func TestUnlinkStopsAPairingEntry(t *testing.T) {
	rig := newRelinkRig(t)
	s := rig.start(t)
	err := rig.r.Unlink(context.Background(), relinkTenant, relinkDevice, relinkPN, nil, nil)
	if !errors.Is(err, wa.ErrNoSession) {
		t.Fatalf("Unlink = %v, want no session under the old link", err)
	}
	if rig.fake.Logouts() != 0 {
		t.Fatal("the logout ran on the pairing's client")
	}
	if len(rig.r.Held()) != 0 {
		t.Fatal("the pairing still holds the number")
	}
	s.Cancel()
}

// A number logged out while this process held it keeps its entry, its
// client and its lock until something stops it: ReleaseStale is that.
func TestReleaseStaleDropsAStoppedTerminalEntry(t *testing.T) {
	locker := &lockStub{}
	fake := fakewa.New()
	r := wa.NewRegistryForTest(wa.RegistryConfig{Locker: locker, Log: slog.New(slog.DiscardHandler)}, nil)
	dev, err := r.AdoptForTest(context.Background(), relinkTenant, relinkDevice, fake)
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.ReleaseStale(context.Background(), relinkDevice) {
		t.Fatal("released a live number")
	}
	fake.Emit(&events.LoggedOut{Reason: events.ConnectFailureLoggedOut})
	select {
	case <-dev.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the logged-out device did not stop")
	}
	if !r.Holds(relinkDevice) || !locker.isHeld() {
		t.Fatal("the stopped number should still be held before the release")
	}
	if !r.ReleaseStale(context.Background(), relinkDevice) {
		t.Fatal("ReleaseStale left the stopped number held")
	}
	if r.Holds(relinkDevice) || locker.isHeld() {
		t.Fatal("the stale hold or its lock remains")
	}
}

// A cancel or the window's end may land after the account passed the check,
// while whatsmeow stores the link and sends pair-device-sign on its own
// goroutine. The pairing then waits for whatsmeow's end: a link WhatsApp
// confirmed is attached as on success, never left stored with no number
// naming it; a link whatsmeow gave up on ends as a failed link.
func TestRelinkEndAfterAnAcceptedScan(t *testing.T) {
	for name, tc := range map[string]struct {
		end    func(rig *relinkRig, s *wa.PairSession)
		linked bool
	}{
		"a cancel, then the success": {end: func(rig *relinkRig, s *wa.PairSession) {
			s.Cancel()
			time.Sleep(50 * time.Millisecond)
			rig.fake.Emit(&events.PairSuccess{ID: linkPN, LID: linkLID})
		}, linked: true},
		"the codes ran out as the success came": {end: func(rig *relinkRig, _ *wa.PairSession) {
			rig.fake.PushQR(whatsmeow.QRChannelTimeout)
			time.Sleep(50 * time.Millisecond)
			rig.fake.Emit(&events.PairSuccess{ID: linkPN, LID: linkLID})
		}, linked: true},
		"a cancel, then whatsmeow's pair error": {end: func(rig *relinkRig, s *wa.PairSession) {
			s.Cancel()
			time.Sleep(50 * time.Millisecond)
			rig.fake.Emit(&events.PairError{ID: linkPN, LID: linkLID, Error: errors.New("failed to send pairing confirmation")})
		}},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newRelinkRig(t)
			s := rig.start(t)
			rig.fake.PushQR(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventCode, Code: fakeQR, Timeout: time.Minute})
			next(t, s)
			if err := rig.scan(linkPN, linkLID); err != nil {
				t.Fatal(err)
			}
			rig.fake.Emit(&events.ManualLoginReconnect{})
			tc.end(rig, s)
			e := next(t, s)
			ended(t, s)
			if !tc.linked {
				if e.Kind != wa.PairEventError || !errors.Is(e.Err, wa.ErrLinkFailed) || rig.attaches() != 0 {
					t.Fatalf("end %+v with %d attaches, want a failed link and none", e, rig.attaches())
				}
				if len(rig.r.Held()) != 0 || rig.locker.isHeld() {
					t.Fatal("the failed link still holds the number")
				}
				return
			}
			if e.Kind != wa.PairEventSuccess {
				t.Fatalf("end %+v, want success", e)
			}
			if rig.attaches() != 1 || rig.attached[0].PN != linkPN {
				t.Fatalf("attached %+v, want the new link once", rig.attached)
			}
			if held := rig.r.Held(); len(held) != 1 || held[0].Relinking {
				t.Fatalf("held %+v, want the number held and linked", held)
			}
		})
	}
}

// A pairing that ends stops its own entry only: a later pairing of the
// number, which a stop by a deletion or the supervisor let in, keeps
// running.
func TestRelinkEndStopsItsOwnEntryOnly(t *testing.T) {
	rig := newRelinkRig(t)
	first := rig.start(t)
	rig.r.Stop(context.Background(), relinkDevice)
	second := rig.start(t)
	first.Cancel()
	if e := next(t, first); e.Kind != wa.PairEventError {
		t.Fatalf("the first pairing ended with %+v", e)
	}
	ended(t, first)
	if _, ok := rig.r.PairingSince(relinkDevice); !ok || !rig.locker.isHeld() {
		t.Fatal("the first pairing's end stopped the second")
	}
	second.Cancel()
}

// The supervisor decides on a snapshot of what this process holds, then
// releases: StopHeld stops the entry the snapshot saw, never one that
// replaced it since.
func TestStopHeldStopsTheSnapshotsEntryOnly(t *testing.T) {
	ctx := context.Background()
	locker := &lockStub{}
	r := wa.NewRegistryForTest(wa.RegistryConfig{Locker: locker, Log: slog.New(slog.DiscardHandler)}, nil)
	if _, err := r.AdoptForTest(ctx, relinkTenant, relinkDevice, fakewa.New()); err != nil {
		t.Fatal(err)
	}
	stale := r.Held()
	r.Stop(ctx, relinkDevice)
	if _, err := r.AdoptForTest(ctx, relinkTenant, relinkDevice, fakewa.New()); err != nil {
		t.Fatal(err)
	}
	if r.StopHeld(ctx, stale[0]) {
		t.Fatal("StopHeld stopped an entry the snapshot never saw")
	}
	if !r.Holds(relinkDevice) || !locker.isHeld() {
		t.Fatal("the later entry went")
	}
	if !r.StopHeld(ctx, r.Held()[0]) || r.Holds(relinkDevice) || locker.isHeld() {
		t.Fatal("StopHeld left the snapshot's own entry held")
	}
	if r.StopHeld(ctx, wa.HeldDevice{ID: relinkDevice}) {
		t.Fatal("StopHeld stopped with no snapshot entry")
	}
}
