package calling

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/purpshell/meowcaller"
	"go.mau.fi/whatsmeow/types"
)

type groupFakeCall struct {
	*fakeCall
	add              func(context.Context, string) error
	participantVideo func(meowcaller.ParticipantVideoFrame)
	latest           meowcaller.GroupCallState
	ring             func(context.Context, string) error
}

func (c *groupFakeCall) AddParticipant(ctx context.Context, target string) error {
	if c.add != nil {
		return c.add(ctx, target)
	}
	return nil
}
func (c *groupFakeCall) OnParticipantVideoFrame(fn func(meowcaller.ParticipantVideoFrame)) {
	c.participantVideo = fn
}

type groupFakeEngine struct {
	*fakeEngine
	aliases map[string]string
}

func (e *groupFakeEngine) resolve(ctx context.Context, jid types.JID) (types.JID, types.JID, error) {
	if err := ctx.Err(); err != nil {
		return types.EmptyJID, types.EmptyJID, err
	}
	if id, ok := e.aliases[jid.String()]; ok {
		out, _ := types.ParseJID(id)
		if jid.Server == types.DefaultUserServer {
			return out, jid, nil
		}
		return out, types.EmptyJID, nil
	}
	if jid.Server == types.DefaultUserServer {
		return jid, jid, nil
	}
	return jid, types.EmptyJID, nil
}
func groupFixture(t *testing.T) (*Service, *record, *groupFakeCall, *groupFakeEngine) {
	t.Helper()
	s, d, e := fixture(t)
	c := &groupFakeCall{fakeCall: newFakeCall("outgoing-group")}
	c.video = true
	ge := &groupFakeEngine{fakeEngine: e, aliases: map[string]string{}}
	d.engine = ge
	e.place = func(context.Context, string, bool) (liveCall, error) { return c, nil }
	if _, err := s.Start(context.Background(), "tenant-a", "device-a", "alice", "5511999990000", true); err != nil {
		t.Fatal(err)
	}
	c.onPeerAccept()
	c.transition(meowcaller.CallPhaseActive)
	r := d.active
	r.bridge.mu.Lock()
	r.bridge.used = true
	r.bridge.participants = true
	r.bridge.mu.Unlock()
	return s, r, c, ge
}
func invite(t *testing.T, s *Service, targets ...string) InviteResult {
	t.Helper()
	result, err := s.Invite(context.Background(), "tenant-a", "device-a", "alice", "outgoing-group", targets)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestInviteRequiresActiveOutgoingOwnerAndNegotiatedMedia(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Service, *record)
		owner  string
		want   error
	}{
		{"other owner", func(*Service, *record) {}, "bob", ErrConflict},
		{"inactive", func(s *Service, r *record) { r.snapshot.State = "ringing" }, "alice", ErrConflict},
		{"incoming", func(s *Service, r *record) { r.snapshot.Direction = "incoming" }, "alice", ErrConflict},
		{"legacy media", func(s *Service, r *record) { r.bridge.participants = false }, "alice", ErrUnavailable},
		{"ended", func(s *Service, r *record) { s.end(r, "hangup", false) }, "alice", ErrNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, r, c, _ := groupFixture(t)
			n := 0
			c.add = func(context.Context, string) error { n++; return nil }
			test.mutate(s, r)
			_, err := s.Invite(context.Background(), "tenant-a", "device-a", test.owner, c.ID(), []string{"5522"})
			if !errors.Is(err, test.want) || n != 0 {
				t.Fatalf("err=%v signals=%d", err, n)
			}
		})
	}
}
func TestInviteValidatesWholeBatchBeforeSignaling(t *testing.T) {
	s, _, c, _ := groupFixture(t)
	n := 0
	c.add = func(context.Context, string) error { n++; return nil }
	for _, targets := range [][]string{nil, {"5522", "group@g.us"}, {"1", "2", "3", "4", "5", "6", "7", "8"}} {
		if _, err := s.Invite(context.Background(), "tenant-a", "device-a", "alice", c.ID(), targets); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid batch accepted: %v", err)
		}
	}
	if n != 0 {
		t.Fatal("partially signaled malformed batch")
	}
}
func TestInviteResolvesAliasesAndReportsPartialResults(t *testing.T) {
	s, _, c, e := groupFixture(t)
	e.aliases["5511000000000@s.whatsapp.net"] = "100@lid"
	e.own = append(e.own, types.NewJID("100", types.HiddenUserServer))
	e.aliases["5522@s.whatsapp.net"] = "200@lid"
	e.aliases["5511999990000@s.whatsapp.net"] = "300@lid"
	var got []string
	c.add = func(ctx context.Context, target string) error {
		got = append(got, target)
		if target == "5533@s.whatsapp.net" {
			return errors.New("private upstream details")
		}
		return nil
	}
	result := invite(t, s, "5522", "200@lid", "5511000000000", "100@lid", "5511999990000", "5533")
	want := []string{"", "duplicate", "self", "self", "duplicate", "unavailable"}
	for i, x := range result.Results {
		if x.Error != want[i] || x.OK != (i == 0) {
			t.Fatalf("result[%d]=%+v", i, x)
		}
	}
	if fmt.Sprint(got) != "[200@lid 5533@s.whatsapp.net]" {
		t.Fatalf("signals=%v", got)
	}
	if result.Call.State != "active" {
		t.Fatal("partial error ended call")
	}
	for _, p := range result.Call.Participants {
		if p.ID == "200@lid" && p.State != "invited" {
			t.Fatal("optimistic connection")
		}
	}
	result.Call.Participants[0].ID = "changed"
	if s.List("tenant-a", "device-a", "alice")[0].Participants[0].ID == "changed" {
		t.Fatal("snapshot aliases mutable roster")
	}
}
func TestConcurrentInviteEnforcesCapacity(t *testing.T) {
	s, _, c, _ := groupFixture(t)
	var mu sync.Mutex
	count := 0
	c.add = func(context.Context, string) error { mu.Lock(); count++; mu.Unlock(); return nil }
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = s.Invite(context.Background(), "tenant-a", "device-a", "alice", c.ID(), []string{fmt.Sprint(6000 + i)})
		}(i)
	}
	wg.Wait()
	if count != 6 {
		t.Fatalf("invites=%d; expected six available slots", count)
	}
}
func TestInviteOwnerReleaseCancelsCurrentAndRemainingTargets(t *testing.T) {
	s, _, c, _ := groupFixture(t)
	entered := make(chan struct{})
	count := 0
	c.add = func(ctx context.Context, target string) error {
		count++
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	done := make(chan InviteResult)
	go func() {
		result, _ := s.Invite(context.Background(), "tenant-a", "device-a", "alice", c.ID(), []string{"5522", "5533"})
		done <- result
	}()
	<-entered
	s.ReleaseOwner("alice")
	result := <-done
	if count != 1 || len(result.Results) != 2 || result.Results[0].Error != "interrupted" || result.Results[1].Error != "interrupted" {
		t.Fatalf("count=%d result=%+v", count, result)
	}
}
func selectedParticipant(id string, pid uint32) meowcaller.GroupCallParticipant {
	jid, _ := types.ParseJID(id)
	device := jid
	device.Device = 1
	return meowcaller.GroupCallParticipant{JID: jid, State: "connected", Devices: []meowcaller.GroupCallDevice{{JID: device, PID: pid, HasPID: true}}}
}
func TestGroupRosterRequiresAuthoritativePIDAndVideoMatchesSelectedDevice(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	invite(t, s, "5522")
	peer := selectedParticipant("5511999990000@s.whatsapp.net", 8)
	p := selectedParticipant("5522@s.whatsapp.net", 9)
	c.onGroup(meowcaller.GroupCallState{Participants: []meowcaller.GroupCallParticipant{peer, p}})
	for _, x := range s.snapshot(r, "alice").Participants {
		if !x.Self && x.State == "connected" {
			t.Fatal("seed roster marked connected")
		}
	}
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{peer, p}})
	frame := meowcaller.ParticipantVideoFrame{Sender: p.JID, Device: p.Devices[0].JID, PID: 9, HasPID: true, SSRC: 42, Orientation: 3, AccessUnit: []byte{0, 0, 0, 1, 0x65, 7}}
	bad := frame
	bad.PID = 10
	c.participantVideo(bad)
	if groupQueued(r.bridge) != 0 {
		t.Fatal("unselected PID accepted")
	}
	c.participantVideo(frame)
	_ = r.bridge.WriteVideo(frame.AccessUnit)
	if groupQueued(r.bridge) != 1 {
		t.Fatal("group frame dropped or duplicate direct output")
	}
	out, _ := r.bridge.nextParticipantVideo()
	packet := encodeVideoFrame(out, true)
	if packet[0] != 4 || packet[1] != 3 || binary.LittleEndian.Uint32(packet[6:10]) != 42 || string(packet[12:12+binary.LittleEndian.Uint16(packet[10:12])]) != "5522@s.whatsapp.net" {
		t.Fatalf("bad attribution packet: %x", packet)
	}
	c.onGroup(meowcaller.GroupCallState{TransactionID: 2, Participants: []meowcaller.GroupCallParticipant{peer}})
	c.participantVideo(frame)
	if groupQueued(r.bridge) != 0 {
		t.Fatal("departed member video accepted")
	}
	found := false
	for _, x := range s.snapshot(r, "alice").Participants {
		if x.ID == p.JID.String() {
			found = x.State == "left"
		}
	}
	if !found {
		t.Fatal("departure not shown")
	}
}

func TestInviteDoesNotRetryFailedAliasWithinBatch(t *testing.T) {
	s, _, c, e := groupFixture(t)
	e.aliases["5522@s.whatsapp.net"] = "200@lid"
	signals := 0
	c.add = func(context.Context, string) error { signals++; return errors.New("failed") }
	result := invite(t, s, "5522", "200@lid", "5522")
	if signals != 1 || result.Results[1].Error != "duplicate" || result.Results[2].Error != "duplicate" {
		t.Fatalf("signals=%d results=%+v", signals, result.Results)
	}
}
func TestGroupRosterFullCapacityAllowsReplacementAndLeftHistory(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	roster := make([]meowcaller.GroupCallParticipant, 7)
	for i := range roster {
		roster[i] = selectedParticipant(fmt.Sprintf("%d@s.whatsapp.net", 7000+i), uint32(i+1))
	}
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: roster})
	if s.snapshot(r, "alice").State != "active" {
		t.Fatal("initial roster rejected")
	}
	old := roster[0]
	old.State = "left"
	roster[0] = selectedParticipant("8000@s.whatsapp.net", 9)
	roster = append(roster, old)
	c.onGroup(meowcaller.GroupCallState{TransactionID: 2, Participants: roster})
	if got := s.snapshot(r, "alice"); got.State != "active" || got.CanInvite {
		t.Fatalf("replacement: %+v", got)
	}
}
func TestGroupRosterReactivatedHistoryCannotExceedCapacity(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	left := selectedParticipant("8000@s.whatsapp.net", 9)
	left.State = "left"
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{left}})
	roster := make([]meowcaller.GroupCallParticipant, 7)
	for i := range roster {
		roster[i] = selectedParticipant(fmt.Sprintf("%d@s.whatsapp.net", 7000+i), uint32(i+1))
	}
	c.onGroup(meowcaller.GroupCallState{TransactionID: 2, Participants: roster})
	left.State = "connected"
	roster = append(roster, left)
	c.onGroup(meowcaller.GroupCallState{TransactionID: 3, Participants: roster})
	if got := s.snapshot(r, "alice"); got.State != "ended" || got.Reason != "group_limit" {
		t.Fatalf("limit bypass: %+v", got)
	}
}
func TestPendingInviteExpiresWithoutAutomaticRetry(t *testing.T) {
	s, _, c, _ := groupFixture(t)
	now := s.now()
	s.now = func() time.Time { return now }
	signals := 0
	c.add = func(context.Context, string) error { signals++; return nil }
	invite(t, s, "5522")
	now = now.Add(61 * time.Second)
	got := s.List("tenant-a", "device-a", "alice")[0]
	found := false
	for _, p := range got.Participants {
		if p.ID == "5522@s.whatsapp.net" {
			found = p.State == "failed"
		}
	}
	if !found || signals != 1 {
		t.Fatalf("roster=%+v signals=%d", got.Participants, signals)
	}
}
func TestGroupVideoChoosesOneSelectedDevice(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	p := selectedParticipant("5522@s.whatsapp.net", 9)
	second := p.Devices[0]
	second.JID.Device = 2
	second.PID = 10
	p.Devices = append(p.Devices, second)
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{p}})
	frame := meowcaller.ParticipantVideoFrame{Sender: p.JID, Device: second.JID, PID: 10, HasPID: true, SSRC: 42, AccessUnit: []byte{0, 0, 0, 1, 0x65}}
	c.participantVideo(frame)
	if groupQueued(r.bridge) != 0 {
		t.Fatal("second device can corrupt participant stream")
	}
	frame.Device = p.Devices[0].JID
	frame.PID = 9
	c.participantVideo(frame)
	if groupQueued(r.bridge) != 1 {
		t.Fatal("selected device missing")
	}
	_ = s
}

func (c *groupFakeCall) GroupState() (meowcaller.GroupCallState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latest, c.latest.TransactionID != 0
}
func (c *groupFakeCall) OnGroupState(fn func(meowcaller.GroupCallState)) {
	c.fakeCall.OnGroupState(func(state meowcaller.GroupCallState) { c.mu.Lock(); c.latest = state; c.mu.Unlock(); fn(state) })
}
func (c *groupFakeCall) RingParticipant(ctx context.Context, target string) error {
	if c.ring != nil {
		return c.ring(ctx, target)
	}
	return nil
}
func TestReinviteDepartedNativeMemberUsesRing(t *testing.T) {
	s, _, c, _ := groupFixture(t)
	p := selectedParticipant("5522@s.whatsapp.net", 9)
	p.State = "disconnected"
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{p}})
	adds, rings := 0, 0
	c.add = func(context.Context, string) error { adds++; return nil }
	c.ring = func(ctx context.Context, target string) error {
		if target != "5522@s.whatsapp.net" {
			t.Fatalf("target=%s", target)
		}
		rings++
		return nil
	}
	result := invite(t, s, "5522")
	if adds != 0 || rings != 1 || !result.Results[0].OK {
		t.Fatalf("adds=%d rings=%d results=%+v", adds, rings, result.Results)
	}
}
func TestFailedInviteAfterSynchronousRosterDoesNotStayPending(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	c.add = func(ctx context.Context, target string) error {
		p := selectedParticipant(target, 9)
		p.State = "ringing"
		c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{p}})
		return errors.New("failed")
	}
	invite(t, s, "5522")
	for _, p := range s.snapshot(r, "alice").Participants {
		if p.ID == "5522@s.whatsapp.net" && p.State != "failed" {
			t.Fatalf("stale local invitation: %+v", p)
		}
	}
}
func TestGroupMediaNegotiationAndAttributedFrameRoundtrip(t *testing.T) {
	for _, oriented := range []bool{false, true} {
		t.Run(fmt.Sprint(oriented), func(t *testing.T) {
			s, r, c, _ := groupFixture(t)
			r.bridge.mu.Lock()
			r.bridge.used = false
			r.bridge.participants = false
			r.bridge.mu.Unlock()
			token, err := s.MediaTicket("tenant-a", "device-a", "alice", c.ID())
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(s)
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil) //nolint:bodyclose // coder/websocket Dial owns and closes the HTTP response body
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseNow()
			hello, _ := json.Marshal(map[string]any{"ticket": token, "participants": true, "video_orientation": oriented})
			if err = conn.Write(ctx, websocket.MessageText, hello); err != nil {
				t.Fatal(err)
			}
			_, ready, err := conn.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var response map[string]bool
			if json.Unmarshal(ready, &response) != nil || !response["ready"] || !response["participants"] || response["video_orientation"] != oriented {
				t.Fatalf("ready=%s", ready)
			}
			p := selectedParticipant("5522@s.whatsapp.net", 9)
			c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{p}})
			au := []byte{0, 0, 0, 1, 0x65, 99}
			frame := meowcaller.ParticipantVideoFrame{Sender: p.JID, Device: p.Devices[0].JID, PID: 9, HasPID: true, SSRC: 0x01020304, Orientation: -1, AccessUnit: au}
			c.participantVideo(frame)
			au[5] = 0
			kind, packet, err := conn.Read(ctx)
			if err != nil || kind != websocket.MessageBinary {
				t.Fatalf("kind=%v err=%v", kind, err)
			}
			wantID := "5522@s.whatsapp.net"
			if packet[0] != 4 || packet[1] != 0 || binary.LittleEndian.Uint32(packet[2:6]) != 33333 || binary.LittleEndian.Uint32(packet[6:10]) != 0x01020304 || int(binary.LittleEndian.Uint16(packet[10:12])) != len(wantID) || string(packet[12:12+len(wantID)]) != wantID || !bytes.Equal(packet[12+len(wantID):], []byte{0, 0, 0, 1, 0x65, 99}) {
				t.Fatalf("packet=%x", packet)
			}
			if !errors.Is(r.bridge.receive(packet, true), ErrInvalid) {
				t.Fatal("browser accepted server-only kind4")
			}
		})
	}
}
func TestGroupTransitionDropsQueuedDirectFrames(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	_ = r.bridge.WriteVideo([]byte{0, 0, 0, 1, 0x65})
	if groupQueued(r.bridge) != 1 {
		t.Fatal("individual video broken")
	}
	p := selectedParticipant("5522@s.whatsapp.net", 9)
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{p}})
	if groupQueued(r.bridge) != 0 {
		t.Fatal("direct frame leaked across conversion")
	}
	_ = s
}
func TestGroupVideoBurstPreservesOtherParticipantsKeyframes(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	roster := make([]meowcaller.GroupCallParticipant, 7)
	for i := range roster {
		roster[i] = selectedParticipant(fmt.Sprintf("%d@s.whatsapp.net", 7000+i), uint32(i+1))
	}
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: roster})
	for _, p := range roster {
		c.participantVideo(meowcaller.ParticipantVideoFrame{Sender: p.JID, Device: p.Devices[0].JID, PID: p.Devices[0].PID, HasPID: true, SSRC: 42, AccessUnit: []byte{0, 0, 0, 1, 0x65}})
	}
	for i := 0; i < 20; i++ {
		p := roster[0]
		c.participantVideo(meowcaller.ParticipantVideoFrame{Sender: p.JID, Device: p.Devices[0].JID, PID: p.Devices[0].PID, HasPID: true, SSRC: 42, AccessUnit: []byte{0, 0, 0, 1, 0x41}})
	}
	seen := map[string]bool{}
	for {
		frame, ok := r.bridge.nextParticipantVideo()
		if !ok {
			break
		}
		seen[frame.participant] = true
	}
	if len(seen) != 7 {
		t.Fatalf("one sender starved others: %v", seen)
	}
	_ = s
}

func groupQueued(b *mediaBridge) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := len(b.videoOut)
	for _, queue := range b.participantOut {
		count += len(queue)
	}
	return count
}
func TestGroupRosterCanonicalizesAliasesAndBoundsHistory(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	entries := []meowcaller.GroupCallParticipant{}
	for i := 0; i < 80; i++ {
		p := selectedParticipant(fmt.Sprintf("%d@lid", 9000+i), uint32(i))
		p.State = "left"
		entries = append(entries, p)
	}
	peer := selectedParticipant("300@lid", 9)
	peer.PN = c.Peer()
	entries = append(entries, peer)
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: entries})
	got := s.snapshot(r, "alice")
	if len(got.Participants) > 32 || got.State != "active" {
		t.Fatalf("unbounded roster: %+v", got)
	}
	peerRows := 0
	for _, p := range got.Participants {
		if p.ID == "300@lid" {
			peerRows++
			if p.PN != c.Peer().String() || p.State != "connected" {
				t.Fatalf("lost canonical peer: %+v", p)
			}
		}
		if p.ID == c.Peer().String() {
			t.Fatal("phone and LID duplicate row")
		}
	}
	if peerRows != 1 {
		t.Fatal("missing canonical peer")
	}
}
func TestGroupRosterMissingSelectedPIDNeverStreams(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	p := selectedParticipant("5522@s.whatsapp.net", 9)
	p.Devices[0].HasPID = false
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{p}})
	for _, row := range s.snapshot(r, "alice").Participants {
		if row.ID == p.JID.String() && row.State != "invited" {
			t.Fatal("connected without PID")
		}
	}
	c.participantVideo(meowcaller.ParticipantVideoFrame{Sender: p.JID, Device: p.Devices[0].JID, PID: 9, HasPID: true, AccessUnit: []byte{0, 0, 0, 1, 0x65}})
	if groupQueued(r.bridge) != 0 {
		t.Fatal("video accepted without authoritative PID")
	}
}
func TestParticipantIDRUsesCachedRosterBeforeDelayedNotification(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	p := selectedParticipant("5522@s.whatsapp.net", 9)
	cached := meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{p}}
	c.mu.Lock()
	c.latest = cached
	c.mu.Unlock()
	c.participantVideo(meowcaller.ParticipantVideoFrame{Sender: p.JID, Device: p.Devices[0].JID, PID: 9, HasPID: true, SSRC: 42, AccessUnit: []byte{0, 0, 0, 1, 0x65}})
	_ = r.bridge.WriteVideo([]byte{0, 0, 0, 1, 0x65})
	frame, ok := r.bridge.nextParticipantVideo()
	if !ok || frame.participant != p.JID.String() || len(r.bridge.videoOut) != 0 || !s.snapshot(r, "alice").Group {
		t.Fatal("IDR lost or misattributed before queued group notification")
	}
	invite(t, s, "5533")
	c.onGroup(cached)
	for _, row := range s.snapshot(r, "alice").Participants {
		if row.ID == "5533@s.whatsapp.net" && row.State != "invited" {
			t.Fatal("delayed equal transaction changed newer invitation")
		}
	}
}
func TestParticipantVideoAcceptsSelectedPhoneDeviceForLIDSender(t *testing.T) {
	s, r, c, _ := groupFixture(t)
	p := selectedParticipant("200@lid", 9)
	p.PN = types.NewJID("5522", types.DefaultUserServer)
	p.Devices[0].JID = p.PN
	p.Devices[0].JID.Device = 1
	c.onGroup(meowcaller.GroupCallState{TransactionID: 1, Participants: []meowcaller.GroupCallParticipant{p}})
	frame := meowcaller.ParticipantVideoFrame{Sender: p.JID, Device: p.Devices[0].JID, PID: 9, HasPID: true, SSRC: 42, AccessUnit: []byte{0, 0, 0, 1, 0x65}}
	c.participantVideo(frame)
	out, ok := r.bridge.nextParticipantVideo()
	if !ok || out.participant != "200@lid" {
		t.Fatal("valid selected PN device dropped for canonical LID sender")
	}
	frame.Sender = types.NewJID("999", types.HiddenUserServer)
	c.participantVideo(frame)
	if groupQueued(r.bridge) != 0 {
		t.Fatal("unrelated sender accepted for selected PN device")
	}
	_ = s
}
