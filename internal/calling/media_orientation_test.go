package calling

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/purpshell/meowcaller"
)

func videoCallFixture(t *testing.T) (*Service, *mediaBridge, *fakeCall) {
	t.Helper()
	s, d, e := fixture(t)
	c := newFakeCall("incoming-video")
	c.video = true
	e.handler(c)
	if _, err := s.Answer(context.Background(), "tenant-a", "device-a", "alice", c.ID()); err != nil {
		t.Fatal(err)
	}
	return s, d.active.bridge, c
}

func openVideoMedia(t *testing.T, s *Service, callID string, orientation *bool) (context.Context, *websocket.Conn) {
	t.Helper()
	token, err := s.MediaTicket("tenant-a", "device-a", "alice", callID)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s)
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil) //nolint:bodyclose // coder/websocket Dial owns and closes the HTTP response body
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	hello := map[string]any{"ticket": token}
	wantReady := `{"ready":true}`
	if orientation != nil {
		hello["video_orientation"] = *orientation
		if *orientation {
			wantReady = `{"ready":true,"video_orientation":true}`
		}
	}
	data, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	kind, ready, err := conn.Read(ctx)
	if err != nil || kind != websocket.MessageText || string(ready) != wantReady {
		t.Fatalf("ready handshake: got %s (%v), want %s: %v", ready, kind, wantReady, err)
	}
	return ctx, conn
}

func readVideoPacket(t *testing.T, ctx context.Context, conn *websocket.Conn, orientation *byte, accessUnit []byte) {
	t.Helper()
	kind, packet, err := conn.Read(ctx)
	if err != nil || kind != websocket.MessageBinary {
		t.Fatalf("video packet: kind=%v err=%v", kind, err)
	}
	wantKind, headerBytes := byte(2), 5
	if orientation != nil {
		wantKind, headerBytes = 3, 6
	}
	if len(packet) != headerBytes+len(accessUnit) || packet[0] != wantKind {
		t.Fatalf("video packet header: packet=%x length=%d, want kind=%d length=%d", packet, len(packet), wantKind, headerBytes+len(accessUnit))
	}
	if orientation != nil && packet[1] != *orientation {
		t.Fatalf("frame orientation=%d, want %d", packet[1], *orientation)
	}
	if duration := binary.LittleEndian.Uint32(packet[headerBytes-4 : headerBytes]); duration != 33333 {
		t.Fatalf("video duration=%d, want 33333 microseconds", duration)
	}
	if !bytes.Equal(packet[headerBytes:], accessUnit) {
		t.Fatalf("video data changed: got %x, want %x", packet[headerBytes:], accessUnit)
	}
}

func TestVideoSinkPreservesUpstreamOrientationContract(t *testing.T) {
	_, _, c := videoCallFixture(t)
	c.mu.Lock()
	sink := c.videoSink
	c.mu.Unlock()
	if _, ok := sink.(meowcaller.VideoOrientationSink); !ok {
		t.Fatal("attached receive sink discards upstream RTP orientation")
	}
}

func TestMediaVideoOrientationNegotiation(t *testing.T) {
	for _, mode := range []string{"omitted", "false", "true"} {
		t.Run(mode, func(t *testing.T) {
			s, bridge, c := videoCallFixture(t)
			bridge.SetOrientation(2)
			accessUnit := []byte{0, 0, 0, 1, 0x65, 0x11}
			// Received frames may already be queued before the browser hello arrives.
			if err := bridge.WriteVideo(accessUnit); err != nil {
				t.Fatal(err)
			}
			var capability *bool
			if mode != "omitted" {
				capability = new(bool)
				*capability = mode == "true"
			}
			ctx, conn := openVideoMedia(t, s, c.ID(), capability)
			var orientation *byte
			if mode == "true" {
				orientation = new(byte)
				*orientation = 2
			}
			readVideoPacket(t, ctx, conn, orientation, accessUnit)
		})
	}
}

func TestMediaVideoOrientationMaximumFrame(t *testing.T) {
	s, bridge, c := videoCallFixture(t)
	bridge.SetOrientation(3)
	capability := true
	ctx, conn := openVideoMedia(t, s, c.ID(), &capability)
	conn.SetReadLimit(512*1024 + 6)
	accessUnit := make([]byte, 512*1024)
	copy(accessUnit, []byte{0, 0, 0, 1, 0x65})
	if err := bridge.WriteVideo(accessUnit); err != nil {
		t.Fatal(err)
	}
	orientation := byte(3)
	readVideoPacket(t, ctx, conn, &orientation, accessUnit)
	if err := bridge.WriteVideo(append(accessUnit, 0)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized H264 accepted: %v", err)
	}
	// Kind 3 is receive-only; browser pixels are already encoded upright.
	if err := bridge.receive([]byte{3, 1, 0x35, 0x82, 0, 0, 0, 0, 0, 1, 0x65}, true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("browser orientation packet accepted: %v", err)
	}
}

func TestMediaVideoOrientationCapturedBeforeQueueAndCopied(t *testing.T) {
	s, bridge, c := videoCallFixture(t)
	sink, ok := any(bridge).(meowcaller.VideoOrientationSink)
	if !ok {
		t.Fatal("bridge discards upstream RTP orientation")
	}
	for index, orientation := range []int{1, 3, 0} {
		sink.SetOrientation(orientation)
		accessUnit := []byte{0, 0, 0, 1, 0x65, byte(index)}
		if err := bridge.WriteVideo(accessUnit); err != nil {
			t.Fatal(err)
		}
		accessUnit[5] = 0xff
	}
	// A later rotation must not change any already queued frame.
	sink.SetOrientation(2)
	capability := true
	ctx, conn := openVideoMedia(t, s, c.ID(), &capability)
	for index, orientation := range []byte{1, 3, 0} {
		readVideoPacket(t, ctx, conn, &orientation, []byte{0, 0, 0, 1, 0x65, byte(index)})
	}
}

func TestMediaVideoOrientationStateFallbackAndRTPPrecedence(t *testing.T) {
	s, bridge, c := videoCallFixture(t)
	c.mu.Lock()
	state := c.onVideoState
	c.mu.Unlock()
	if state == nil {
		t.Fatal("video signaling orientation fallback was not registered")
	}
	sink, ok := any(bridge).(meowcaller.VideoOrientationSink)
	if !ok {
		t.Fatal("bridge discards upstream RTP orientation")
	}
	capability := true
	ctx, conn := openVideoMedia(t, s, c.ID(), &capability)
	for _, step := range []struct {
		name           string
		rtp, signaling []int
		want           byte
	}{
		{name: "default upright", want: 0},
		{name: "signaling fallback", signaling: []int{1}, want: 1},
		{name: "invalid RTP does not suppress fallback", rtp: []int{-1, 4, 256}, signaling: []int{3}, want: 3},
		{name: "invalid signaling ignored", signaling: []int{-1, 4, 257}, want: 3},
		{name: "RTP replaces signaling", rtp: []int{2}, signaling: []int{0}, want: 2},
		{name: "invalid RTP preserves latest", rtp: []int{-1, 4, 256}, want: 2},
		{name: "latest RTP wins", rtp: []int{3}, signaling: []int{1}, want: 3},
		{name: "zero RTP overrides stale signaling", rtp: []int{0}, signaling: []int{2}, want: 0},
	} {
		t.Run(step.name, func(t *testing.T) {
			for _, value := range step.rtp {
				sink.SetOrientation(value)
			}
			for _, value := range step.signaling {
				state(meowcaller.VideoState{Active: true, Orientation: value, Raw: 1})
			}
			accessUnit := []byte{0, 0, 0, 1, 0x65, 0x42}
			if err := bridge.WriteVideo(accessUnit); err != nil {
				t.Fatal(err)
			}
			readVideoPacket(t, ctx, conn, &step.want, accessUnit)
		})
	}
}

func TestMediaVideoOrientationConcurrentSignalingAndRTPFrames(t *testing.T) {
	s, bridge, c := videoCallFixture(t)
	c.mu.Lock()
	state := c.onVideoState
	c.mu.Unlock()
	sink, ok := any(bridge).(meowcaller.VideoOrientationSink)
	if !ok || state == nil {
		t.Fatal("RTP or signaling orientation path is missing")
	}
	capability := true
	ctx, conn := openVideoMedia(t, s, c.ID(), &capability)
	start := make(chan struct{})
	errors := make(chan error, 1)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for index := 0; index < 2000; index++ {
			state(meowcaller.VideoState{Active: true, Orientation: index % 4, Raw: 1})
			sink.SetOrientation(256)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for index := 0; index < 2000; index++ {
			orientation := index % 4
			sink.SetOrientation(orientation)
			if err := bridge.WriteVideo([]byte{0, 0, 0, 1, 0x65, byte(orientation)}); err != nil {
				errors <- err
				return
			}
		}
	}()
	close(start)
	workers.Wait()
	select {
	case err := <-errors:
		t.Fatal(err)
	default:
	}
	// The newest frame remains deliverable even when the bounded queue drops frames.
	sink.SetOrientation(2)
	if err := bridge.WriteVideo([]byte{0, 0, 0, 1, 0x65, 0xfe}); err != nil {
		t.Fatal(err)
	}
	for {
		kind, packet, err := conn.Read(ctx)
		if err != nil || kind != websocket.MessageBinary || len(packet) != 12 || packet[0] != 3 {
			t.Fatalf("concurrent video packet: %x kind=%v err=%v", packet, kind, err)
		}
		if packet[11] == 0xfe {
			if packet[1] != 2 {
				t.Fatalf("latest frame lost orientation: %d", packet[1])
			}
			break
		}
		if packet[1] != packet[11] {
			t.Fatalf("frame orientation crossed queue boundary: got %d, want %d", packet[1], packet[11])
		}
	}
}
