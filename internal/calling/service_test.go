package calling

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/purpshell/meowcaller"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

type fakeEngine struct {
	place     func(context.Context, string, bool) (liveCall, error)
	connected bool
	own       []types.JID
	handler   func(liveCall)
	calls     atomic.Int32
}

func (e *fakeEngine) call(ctx context.Context, target string, video bool) (liveCall, error) {
	e.calls.Add(1)
	return e.place(ctx, target, video)
}
func (e *fakeEngine) online() bool               { return e.connected }
func (e *fakeEngine) self() []types.JID          { return e.own }
func (e *fakeEngine) incoming(fn func(liveCall)) { e.handler = fn }

type fakeCall struct {
	mu                        sync.Mutex
	id                        string
	video, group              bool
	phase                     meowcaller.CallPhase
	onState                   func(meowcaller.CallPhase)
	onEnd                     func(string)
	onGroup                   func(meowcaller.GroupCallState)
	onPeerAccept              func()
	onVideoState              func(meowcaller.VideoState)
	source                    meowcaller.AudioSource
	sink                      meowcaller.AudioSink
	videoSink                 meowcaller.VideoSink
	answers, rejects, hangups atomic.Int32
}

func newFakeCall(id string) *fakeCall           { return &fakeCall{id: id, phase: meowcaller.CallPhaseRinging} }
func (c *fakeCall) ID() string                  { return c.id }
func (c *fakeCall) Peer() types.JID             { return types.NewJID("5511999990000", types.DefaultUserServer) }
func (c *fakeCall) State() meowcaller.CallPhase { c.mu.Lock(); defer c.mu.Unlock(); return c.phase }
func (c *fakeCall) IsVideo() bool               { return c.video }
func (c *fakeCall) GroupState() (meowcaller.GroupCallState, bool) {
	return meowcaller.GroupCallState{}, c.group
}
func (c *fakeCall) Answer() error {
	c.answers.Add(1)
	c.transition(meowcaller.CallPhaseConnecting)
	return nil
}
func (c *fakeCall) Reject() error { c.rejects.Add(1); c.finish("rejected"); return nil }
func (c *fakeCall) Hangup() error { c.hangups.Add(1); c.finish("hangup"); return nil }
func (c *fakeCall) Play(source meowcaller.AudioSource) *meowcaller.Player {
	c.mu.Lock()
	c.source = source
	c.mu.Unlock()
	p := meowcaller.NewPlayer()
	p.Play(source)
	return p
}
func (c *fakeCall) Receive(sink meowcaller.AudioSink) { c.mu.Lock(); c.sink = sink; c.mu.Unlock() }
func (c *fakeCall) ReceiveVideo(sink meowcaller.VideoSink) {
	c.mu.Lock()
	c.videoSink = sink
	c.mu.Unlock()
}
func (c *fakeCall) SendVideoWithDuration([]byte, time.Duration) error { return nil }
func (c *fakeCall) OnStateChange(fn func(meowcaller.CallPhase)) {
	c.mu.Lock()
	c.onState = fn
	c.mu.Unlock()
}
func (c *fakeCall) OnEnd(fn func(string)) { c.mu.Lock(); c.onEnd = fn; c.mu.Unlock() }
func (c *fakeCall) OnGroupState(fn func(meowcaller.GroupCallState)) {
	c.mu.Lock()
	c.onGroup = fn
	c.mu.Unlock()
}
func (c *fakeCall) OnPeerAccept(fn func()) { c.mu.Lock(); c.onPeerAccept = fn; c.mu.Unlock() }
func (c *fakeCall) OnVideoState(fn func(meowcaller.VideoState)) {
	c.mu.Lock()
	c.onVideoState = fn
	c.mu.Unlock()
}
func (c *fakeCall) transition(phase meowcaller.CallPhase) {
	c.mu.Lock()
	c.phase = phase
	fn := c.onState
	c.mu.Unlock()
	if fn != nil {
		fn(phase)
	}
}
func (c *fakeCall) finish(reason string) {
	c.transition(meowcaller.CallPhaseEnded)
	c.mu.Lock()
	fn := c.onEnd
	c.mu.Unlock()
	if fn != nil {
		fn(reason)
	}
}

func fixture(t *testing.T) (*Service, *device, *fakeEngine) {
	t.Helper()
	s := New()
	s.RegisterOwner("alice")
	s.RegisterOwner("bob")
	e := &fakeEngine{connected: true, own: []types.JID{types.NewJID("5511000000000", types.DefaultUserServer)}}
	e.place = func(context.Context, string, bool) (liveCall, error) { return newFakeCall("outgoing"), nil }
	d := &device{key: deviceKey{"tenant-a", "device-a"}, engine: e}
	s.devices[d.key] = d
	e.incoming(func(c liveCall) { s.incoming(d, c) })
	t.Cleanup(func() { s.ReleaseOwner("alice"); s.ReleaseOwner("bob"); s.detach(d) })
	return s, d, e
}

func TestIncomingClaimIsolationAndReadOnlyList(t *testing.T) {
	s, _, e := fixture(t)
	c := newFakeCall("incoming")
	e.handler(c)
	for i := 0; i < 10; i++ {
		snapshots := s.List("tenant-a", "device-a", "alice")
		if len(snapshots) != 1 || snapshots[0].Owned || snapshots[0].State != "ringing" {
			t.Fatalf("unclaimed incoming: %+v", snapshots)
		}
	}
	if c.answers.Load() != 0 || c.rejects.Load() != 0 || c.hangups.Load() != 0 || e.calls.Load() != 0 {
		t.Fatal("listing performed signaling")
	}
	if len(s.List("other", "device-a", "alice")) != 0 || len(s.List("tenant-a", "other", "alice")) != 0 {
		t.Fatal("cross-tenant/device data exposure")
	}
	if _, err := s.Answer(context.Background(), "other", "device-a", "alice", c.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
	if _, err := s.MediaTicket("tenant-a", "device-a", "alice", c.ID()); !errors.Is(err, ErrConflict) {
		t.Fatalf("unclaimed media: %v", err)
	}
	snap, err := s.Answer(context.Background(), "tenant-a", "device-a", "alice", c.ID())
	if err != nil || !snap.Owned || snap.State != "connecting" {
		t.Fatalf("answer: %+v %v", snap, err)
	}
	if _, err := s.Answer(context.Background(), "tenant-a", "device-a", "bob", c.ID()); !errors.Is(err, ErrConflict) {
		t.Fatalf("second answer: %v", err)
	}
	if err := s.Hangup(context.Background(), "tenant-a", "device-a", "bob", c.ID()); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign hangup: %v", err)
	}
	if _, err := s.MediaTicket("tenant-a", "device-a", "bob", c.ID()); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign media: %v", err)
	}
	if s.List("tenant-a", "device-a", "bob")[0].Owned {
		t.Fatal("foreign list claimed ownership")
	}
	if c.answers.Load() != 1 {
		t.Fatalf("answers=%d", c.answers.Load())
	}
}

func TestConcurrentAnswerHasOneOwner(t *testing.T) {
	s, _, e := fixture(t)
	c := newFakeCall("incoming")
	e.handler(c)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for _, owner := range []string{"alice", "bob"} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			if _, err := s.Answer(context.Background(), "tenant-a", "device-a", owner, c.ID()); err == nil {
				successes.Add(1)
			}
		}(owner)
	}
	wg.Wait()
	if successes.Load() != 1 || c.answers.Load() != 1 {
		t.Fatalf("successes=%d answers=%d", successes.Load(), c.answers.Load())
	}
}

func TestStartValidatesAndReservesDevice(t *testing.T) {
	s, _, e := fixture(t)
	for _, target := range []string{"", "x", "123@g.us", "123@broadcast", "123:2@s.whatsapp.net", "5511000000000"} {
		if _, err := s.Start(context.Background(), "tenant-a", "device-a", "alice", target, false); !errors.Is(err, ErrInvalid) {
			t.Errorf("target %q: %v", target, err)
		}
	}
	e.connected = false
	if _, err := s.Start(context.Background(), "tenant-a", "device-a", "alice", "5511888888888", false); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	e.connected = true
	snap, err := s.Start(context.Background(), "tenant-a", "device-a", "alice", "5511888888888", false)
	if err != nil || !snap.Owned {
		t.Fatalf("start: %+v %v", snap, err)
	}
	if _, err := s.Start(context.Background(), "tenant-a", "device-a", "bob", "123@lid", true); !errors.Is(err, ErrConflict) {
		t.Fatalf("second outgoing: %v", err)
	}
	if e.calls.Load() != 1 {
		t.Fatalf("place calls=%d", e.calls.Load())
	}
}

func TestReleaseOwnerCancelsInFlightStart(t *testing.T) {
	s, d, e := fixture(t)
	started := make(chan struct{})
	resume := make(chan struct{})
	c := newFakeCall("late")
	e.place = func(ctx context.Context, _ string, _ bool) (liveCall, error) {
		close(started)
		<-ctx.Done()
		<-resume
		return c, nil
	}
	result := make(chan error, 1)
	go func() {
		_, err := s.Start(context.Background(), "tenant-a", "device-a", "alice", "5511888888888", false)
		result <- err
	}()
	<-started
	s.mu.Lock()
	bridge := d.active.bridge
	s.mu.Unlock()
	s.ReleaseOwner("alice")
	if _, err := bridge.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("released source not closed: %v", err)
	}
	close(resume)
	if err := <-result; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("late start: %v", err)
	}
	eventually(t, func() bool { return c.hangups.Load() == 1 })
	if _, err := s.Start(context.Background(), "tenant-a", "device-a", "alice", "123@lid", false); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("released owner: %v", err)
	}
	s.mu.Lock()
	active := d.active
	s.mu.Unlock()
	if active != nil {
		t.Fatal("ended pending call reserved device forever")
	}
}

func TestTicketsSingleUseExpiredAndRevoked(t *testing.T) {
	s, d, e := fixture(t)
	c := newFakeCall("incoming")
	e.handler(c)
	if _, err := s.Answer(context.Background(), "tenant-a", "device-a", "alice", c.ID()); err != nil {
		t.Fatal(err)
	}
	token, err := s.MediaTicket("tenant-a", "device-a", "alice", c.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.consumeTicket(token); err != nil || got != d.active {
		t.Fatalf("consume: %v", err)
	}
	if _, err := s.consumeTicket(token); !errors.Is(err, ErrNotFound) {
		t.Fatal("ticket reused")
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	expired, _ := s.MediaTicket("tenant-a", "device-a", "alice", c.ID())
	now = now.Add(ticketLifetime)
	if _, err := s.consumeTicket(expired); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired ticket accepted")
	}
	revoked, _ := s.MediaTicket("tenant-a", "device-a", "alice", c.ID())
	source := d.active.bridge
	s.ReleaseOwner("alice")
	if _, err := s.consumeTicket(revoked); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked ticket accepted")
	}
	if _, err := source.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("microphone source still open: %v", err)
	}
}

func TestUnsupportedGroupAndConversion(t *testing.T) {
	s, _, e := fixture(t)
	group := newFakeCall("group")
	group.group = true
	e.handler(group)
	if len(s.List("tenant-a", "device-a", "alice")) != 0 || group.rejects.Load() != 0 || group.answers.Load() != 0 {
		t.Fatal("unsupported incoming group was handled")
	}
	c := newFakeCall("direct")
	e.handler(c)
	c.mu.Lock()
	fn := c.onGroup
	c.mu.Unlock()
	fn(meowcaller.GroupCallState{})
	if got := s.List("tenant-a", "device-a", "alice")[0]; got.State != "ended" || got.Reason != "group_unsupported" {
		t.Fatalf("converted group: %+v", got)
	}
}

func TestAttachInstallsPinnedWhatsmeowHooksAndOldCleanupPreservesReplacement(t *testing.T) {
	s := New()
	first := whatsmeow.NewClient(&store.Device{}, waLog.Noop)
	before := reflect.ValueOf(first).Elem().FieldByName("nodeHandlers").MapIndex(reflect.ValueOf("call")).Pointer()
	cleanupFirst := s.Attach("tenant", "device", first)
	handlers := reflect.ValueOf(first).Elem().FieldByName("nodeHandlers")
	if !handlers.MapIndex(reflect.ValueOf("ack")).IsValid() || before == handlers.MapIndex(reflect.ValueOf("call")).Pointer() {
		t.Fatal("meowcaller raw hooks did not install against pinned whatsmeow")
	}
	s.Attach("tenant", "device", first)
	if len(s.devices) != 1 {
		t.Fatal("duplicate Attach")
	}
	second := whatsmeow.NewClient(&store.Device{}, waLog.Noop)
	cleanupSecond := s.Attach("tenant", "device", second)
	defer cleanupSecond()
	cleanupFirst()
	if !s.Attached("tenant", "device") || s.devices[deviceKey{"tenant", "device"}].client != second {
		t.Fatal("old cleanup removed replacement")
	}
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func TestIncomingRelayPreparationDoesNotAnswerOrHideRinging(t *testing.T) {
	s, d, e := fixture(t)
	c := newFakeCall("incoming")
	e.handler(c)
	for _, phase := range []meowcaller.CallPhase{meowcaller.CallPhaseConnecting, meowcaller.CallPhaseActive} {
		c.transition(phase)
		snap := s.List("tenant-a", "device-a", "alice")[0]
		if snap.State != "ringing" || snap.Owned {
			t.Fatalf("relay preparation answered incoming call: %+v", snap)
		}
	}
	if c.answers.Load() != 0 || d.active.ring == nil {
		t.Fatal("unanswered call lost its timeout")
	}
	frame := make([]byte, 1+audioBytes)
	frame[0] = audioKind
	frame[1] = 0xff
	if err := d.active.bridge.receive(frame, false); err != nil {
		t.Fatal(err)
	}
	if len(d.active.bridge.audioIn) != 0 {
		t.Fatal("unaccepted incoming microphone was queued")
	}
	snap, err := s.Answer(context.Background(), "tenant-a", "device-a", "alice", c.ID())
	if err != nil || snap.State != "active" || c.answers.Load() != 1 {
		t.Fatalf("answer after relay ready: %+v %v", snap, err)
	}
	if !d.active.bridge.audioAllowed() {
		t.Fatal("explicit answer did not open audio")
	}
}

func TestOutgoingAudioWaitsForPeerAcceptAndDropsEarlierSamples(t *testing.T) {
	s, d, e := fixture(t)
	c := newFakeCall("outgoing")
	e.place = func(context.Context, string, bool) (liveCall, error) { return c, nil }
	if _, err := s.Start(context.Background(), "tenant-a", "device-a", "alice", "123@lid", false); err != nil {
		t.Fatal(err)
	}
	c.transition(meowcaller.CallPhaseActive)
	if snap := s.List("tenant-a", "device-a", "alice")[0]; snap.State != "ringing" {
		t.Fatalf("relay marked unanswered call active: %+v", snap)
	}
	b := d.active.bridge
	audio := make([]byte, 1+audioBytes)
	audio[0] = audioKind
	audio[2] = 0x40
	if err := b.receive(audio, false); err != nil {
		t.Fatal(err)
	}
	pcm, err := b.ReadFrame()
	if err != nil || pcm[0] != 0 || len(b.audioIn) != 0 {
		t.Fatal("microphone transmitted before peer accepted")
	}
	c.mu.Lock()
	accepted := c.onPeerAccept
	c.mu.Unlock()
	accepted()
	if snap := s.List("tenant-a", "device-a", "alice")[0]; snap.State != "active" {
		t.Fatalf("peer accept: %+v", snap)
	}
	pcm, _ = b.ReadFrame()
	if pcm[0] != 0 {
		t.Fatal("pre-accept microphone history leaked")
	}
	if err := b.receive(audio, false); err != nil {
		t.Fatal(err)
	}
	pcm, _ = b.ReadFrame()
	if pcm[0] != 0.5 {
		t.Fatalf("accepted microphone=%v", pcm[0])
	}
}

func TestMissingMediaDeadlineSurvivesEarlyActiveState(t *testing.T) {
	s, d, e := fixture(t)
	c := newFakeCall("incoming")
	e.handler(c)
	if _, err := s.Answer(context.Background(), "tenant-a", "device-a", "alice", c.ID()); err != nil {
		t.Fatal(err)
	}
	r := d.active
	c.transition(meowcaller.CallPhaseActive)
	s.mu.Lock()
	timer := r.mediaWait
	s.mu.Unlock()
	if timer == nil {
		t.Fatal("active call without media has no deadline")
	}
	s.expireMedia(r)
	if snap := s.List("tenant-a", "device-a", "alice")[0]; snap.State != "ended" || snap.Reason != "media_timeout" {
		t.Fatalf("missing media not ended: %+v", snap)
	}
}

func TestExplicitRelayFailureEndsMatchingCallWithoutForwardingDiagnostics(t *testing.T) {
	s, d, e := fixture(t)
	c := newFakeCall("incoming")
	e.handler(c)
	if _, err := s.Answer(context.Background(), "tenant-a", "device-a", "alice", c.ID()); err != nil {
		t.Fatal(err)
	}
	logger := s.failureLogger(d)
	logger.Warn().Str("call_id", "different").Msg("media ended")
	logger.Warn().Str("call_id", c.ID()).Msg("unrelated warning")
	logger.Info().Str("call_id", c.ID()).Msg("media ended")
	if snap := s.List("tenant-a", "device-a", "alice")[0]; snap.State == "ended" {
		t.Fatal("unrelated diagnostic ended call")
	}
	logger.Warn().Str("call_id", c.ID()).Str("error", "discarded transport detail").Msg("media ended")
	eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return d.active == nil })
	if snap := s.List("tenant-a", "device-a", "alice")[0]; snap.State != "ended" || snap.Reason != "media_failed" {
		t.Fatalf("relay failure: %+v", snap)
	}
}

func TestOldAdapterFailureCannotEndReplacement(t *testing.T) {
	s, d, e := fixture(t)
	_ = s.failureLogger(d)
	replacement := &device{key: d.key, engine: e}
	s.mu.Lock()
	s.devices[d.key] = replacement
	s.mu.Unlock()
	c := newFakeCall("reused-id")
	s.incoming(replacement, c)
	s.mediaFailed(d, c.ID())
	// Exercise the async writer separately with a synchronization barrier.
	completed := make(chan string, 1)
	writer := failureWriter{failed: func(id string) { completed <- id }}
	data := []byte(`{"level":"warn","message":"media ended","call_id":"expected","error":"discarded"}`)
	if n, err := writer.Write(data); err != nil || n != len(data) {
		t.Fatal(err)
	}
	select {
	case id := <-completed:
		if id != "expected" {
			t.Fatal(id)
		}
	case <-time.After(time.Second):
		t.Fatal("failure writer callback missing")
	}
	s.mu.Lock()
	active := replacement.active
	s.mu.Unlock()
	if active == nil {
		t.Fatal("retired adapter ended replacement")
	}
	s.detach(replacement)
}
