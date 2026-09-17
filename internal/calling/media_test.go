package calling

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/purpshell/meowcaller"
)

func TestMediaFrameValidationBoundsAndPCM(t *testing.T) {
	b := newMediaBridge()
	b.allowAudio()
	defer b.Close()
	audio := make([]byte, 1+audioBytes)
	audio[0] = audioKind
	binary.LittleEndian.PutUint16(audio[1:], uint16(0x8000))
	binary.LittleEndian.PutUint16(audio[3:], uint16(0x7fff))
	for i := 0; i < 100; i++ {
		if err := b.receive(audio, false); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.audioIn) > audioQueueSize {
		t.Fatal("audio input queue grew")
	}
	decoded, err := b.ReadFrame()
	if err != nil || decoded[0] != -1 || decoded[1] != float32(32767)/32768 {
		t.Fatalf("PCM decode: %v %v", decoded[:2], err)
	}
	for i := 0; i < 100; i++ {
		if err := b.WriteFrame(decoded); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.audioOut) > audioQueueSize {
		t.Fatal("audio output queue grew")
	}
	encoded := <-b.audioOut
	if encoded[0] != audioKind || len(encoded) != audioBytes+1 || binary.LittleEndian.Uint16(encoded[1:]) != 0x8000 {
		t.Fatal("PCM output format")
	}
	video := []byte{videoKind, 0, 0, 0, 0, 0, 0, 0, 1, 0x65, 1, 2}
	binary.LittleEndian.PutUint32(video[1:5], 33333)
	for i := 0; i < 100; i++ {
		if err := b.receive(video, true); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteVideo(video[5:]); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.videoIn) > videoQueueSize || len(b.videoOut) > videoQueueSize {
		t.Fatal("video queue grew")
	}
	out := <-b.videoOut
	if out.duration != 33333*time.Microsecond || !validAnnexB(out.data) {
		t.Fatal("video output format")
	}
	for _, invalid := range [][]byte{nil, {9}, {audioKind}, audio[:len(audio)-1], append(append([]byte{}, audio...), 0), {videoKind}, make([]byte, maxMediaBytes+1)} {
		if err := b.receive(invalid, true); !errors.Is(err, ErrInvalid) {
			t.Fatalf("malformed media accepted (%d bytes): %v", len(invalid), err)
		}
	}
	if err := b.receive(video, false); !errors.Is(err, ErrInvalid) {
		t.Fatal("video accepted on audio call")
	}
	binary.LittleEndian.PutUint32(video[1:5], 0)
	if err := b.receive(video, true); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid duration accepted")
	}
	decoded[0] = float32(math.NaN())
	if err := b.WriteFrame(decoded); !errors.Is(err, ErrInvalid) {
		t.Fatal("NaN accepted")
	}
	decoded[0] = float32(math.Inf(1))
	if err := b.WriteFrame(decoded); !errors.Is(err, ErrInvalid) {
		t.Fatal("infinite sample accepted")
	}
	if err := b.WriteVideo([]byte{0, 0, 0, 1, 0xff}); !errors.Is(err, ErrInvalid) {
		t.Fatal("malformed H264 accepted")
	}
	b.Close()
	if _, err := b.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("closed source: %v", err)
	}
	if err := b.receive(audio, false); !errors.Is(err, io.EOF) {
		t.Fatalf("closed input: %v", err)
	}
}

func TestMediaWebsocketSingleUseOwnerTeardownAndFrames(t *testing.T) {
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
	server := httptest.NewServer(s)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil) //nolint:bodyclose // coder/websocket Dial owns and closes the HTTP response body
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	data, _ := json.Marshal(map[string]string{"ticket": token})
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	kind, ready, err := conn.Read(ctx)
	if err != nil || kind != websocket.MessageText || string(ready) != `{"ready":true}` {
		t.Fatalf("ready: %v %s %v", kind, ready, err)
	}
	if _, err := s.consumeTicket(token); !errors.Is(err, ErrNotFound) {
		t.Fatal("media handshake did not consume ticket")
	}
	if _, err := s.MediaTicket("tenant-a", "device-a", "alice", c.ID()); !errors.Is(err, ErrConflict) {
		t.Fatalf("second media connection ticket: %v", err)
	}
	audio := make([]byte, 1+audioBytes)
	audio[0] = audioKind
	binary.LittleEndian.PutUint16(audio[1:], 0x4000)
	if err := conn.Write(ctx, websocket.MessageBinary, audio); err != nil {
		t.Fatal(err)
	}
	bridge := d.active.bridge
	eventually(t, func() bool { return len(bridge.audioIn) > 0 })
	frame, err := bridge.ReadFrame()
	if err != nil || frame[0] != 0.5 {
		t.Fatalf("socket input: %v", err)
	}
	if err := bridge.WriteFrame(frame); err != nil {
		t.Fatal(err)
	}
	kind, out, err := conn.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || len(out) != audioBytes+1 || binary.LittleEndian.Uint16(out[1:]) != 0x4000 {
		t.Fatalf("socket output: %v %d %v", kind, len(out), err)
	}
	s.ReleaseOwner("alice")
	if _, err := bridge.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatal("release did not immediately stop PCM")
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("released media socket stayed open")
	}
	eventually(t, func() bool { return c.hangups.Load() == 1 })
}

func TestMediaRejectsCrossOriginAndMalformedHandshake(t *testing.T) {
	s, _, _ := fixture(t)
	server := httptest.NewServer(s)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	address := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, response, err := websocket.Dial(ctx, address, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{"https://unrelated.example"}}}) //nolint:bodyclose // coder/websocket Dial owns and closes the HTTP response body
	if conn != nil {
		conn.CloseNow()
	}
	if err == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin handshake: response=%v err=%v", response, err)
	}
	for _, hello := range []string{`{}`, `{"ticket":"bad"}`, `{"ticket":"` + strings.Repeat("x", 43) + `","unexpected":true}`, `{"ticket":"` + strings.Repeat("x", 43) + `"} {}`} {
		conn, _, err := websocket.Dial(ctx, address, nil) //nolint:bodyclose // coder/websocket Dial owns and closes the HTTP response body
		if err != nil {
			t.Fatal(err)
		}
		if err = conn.Write(ctx, websocket.MessageText, []byte(hello)); err != nil {
			t.Fatal(err)
		}
		_, _, err = conn.Read(ctx)
		conn.CloseNow()
		if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("handshake %s: %v", hello, err)
		}
	}
}

func TestMalformedMediaEndsOwnedCall(t *testing.T) {
	s, _, e := fixture(t)
	c := newFakeCall("incoming")
	e.handler(c)
	if _, err := s.Answer(context.Background(), "tenant-a", "device-a", "alice", c.ID()); err != nil {
		t.Fatal(err)
	}
	token, _ := s.MediaTicket("tenant-a", "device-a", "alice", c.ID())
	server := httptest.NewServer(s)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil) //nolint:bodyclose // coder/websocket Dial owns and closes the HTTP response body
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	data, _ := json.Marshal(map[string]string{"ticket": token})
	if err = conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	if _, _, err = conn.Read(ctx); err != nil {
		t.Fatal(err)
	}
	if err = conn.Write(ctx, websocket.MessageBinary, []byte{audioKind, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = conn.Read(ctx); err == nil {
		t.Fatal("malformed media was accepted")
	}
	eventually(t, func() bool { return c.hangups.Load() == 1 })
	if got := s.List("tenant-a", "device-a", "alice")[0]; got.State != "ended" {
		t.Fatalf("malformed media left live call: %+v", got)
	}
}

func TestRemoteTerminationPreservesReasonAndClosesMedia(t *testing.T) {
	s, d, e := fixture(t)
	c := newFakeCall("incoming")
	e.handler(c)
	source := d.active.bridge
	c.transition(meowcaller.CallPhaseActive)
	c.finish("busy")
	got := s.List("tenant-a", "device-a", "alice")[0]
	if got.State != "ended" || got.Reason != "busy" {
		t.Fatalf("remote end: %+v", got)
	}
	if _, err := source.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatal("remote end left source open")
	}
}

func TestAudioSinkReframesVariableDecoderChunks(t *testing.T) {
	b := newMediaBridge()
	defer b.Close()
	b.allowAudio()
	first := make([]float32, 320)
	first[0] = 0.5
	second := make([]float32, 640)
	second[len(second)-1] = -0.5
	if err := b.WriteFrame(first); err != nil {
		t.Fatal(err)
	}
	if len(b.audioOut) != 0 {
		t.Fatal("partial 20ms frame escaped")
	}
	if err := b.WriteFrame(second); err != nil {
		t.Fatal(err)
	}
	if len(b.audioOut) != 1 {
		t.Fatal("20ms+40ms did not become one frame")
	}
	frame := <-b.audioOut
	if len(frame) != audioBytes+1 || binary.LittleEndian.Uint16(frame[1:]) != 0x4000 || binary.LittleEndian.Uint16(frame[len(frame)-2:]) != 0xc000 {
		t.Fatal("reframing lost boundary samples")
	}
	if err := b.WriteFrame(make([]float32, 1920)); err != nil {
		t.Fatal(err)
	}
	if len(b.audioOut) != 2 {
		t.Fatal("120ms did not produce two frames")
	}
	if len(b.audioPending) != 0 || cap(b.audioPending) > audioBytes {
		t.Fatal("unbounded PCM accumulator")
	}
}

// Every signed 16-bit value must retain its exact two's-complement wire bits.
// This protects negative amplitudes when replacing narrowing integer casts.
func TestPCMRoundTripPreservesEverySignedWord(t *testing.T) {
	b := newMediaBridge()
	b.allowAudio()
	defer b.Close()
	for first := 0; first <= math.MaxUint16; first += meowcaller.FrameSamples {
		packet := make([]byte, 1+audioBytes)
		packet[0] = audioKind
		for i := 0; i < meowcaller.FrameSamples; i++ {
			binary.LittleEndian.PutUint16(packet[1+2*i:], uint16((first+i)&math.MaxUint16))
		}
		if err := b.receive(packet, false); err != nil {
			t.Fatal(err)
		}
		decoded, err := b.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if err = b.WriteFrame(decoded); err != nil {
			t.Fatal(err)
		}
		encoded := <-b.audioOut
		for i := range packet {
			if encoded[i] != packet[i] {
				t.Fatalf("PCM bits changed near word %d byte %d", first, i)
			}
		}
	}
}
