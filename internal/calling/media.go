package calling

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/purpshell/meowcaller"
)

const (
	audioKind            byte = 1
	videoKind            byte = 2
	orientedVideoKind    byte = 3
	participantVideoKind byte = 4
	audioBytes                = 2 * meowcaller.FrameSamples
	maxVideoBytes             = 512 * 1024
	maxMediaBytes             = maxVideoBytes + 5 // Browser-to-server video remains kind 2.
	audioQueueSize            = 5
	videoQueueSize            = 3
)

type videoFrame struct {
	data        []byte
	duration    time.Duration
	orientation byte
	participant string
	ssrc        uint32
}

// mediaBridge is both the library's PCM source and receive sink. All queues have
// fixed bounds; network or browser stalls never block the WhatsApp media loop.
type mediaBridge struct {
	mu                sync.Mutex
	audioMu           sync.Mutex
	audioPending      []byte
	done              chan struct{}
	audioIn           chan []float32
	audioOut          chan []byte
	videoIn           chan videoFrame
	videoOut          chan videoFrame
	participantOut    map[string][]videoFrame
	participantOrder  []string
	participantReady  chan struct{}
	participantCursor int
	conn              *websocket.Conn
	cancel            context.CancelFunc
	closed            bool
	used              bool
	participants      bool
	group             bool
	audioEnabled      bool
	// RTP orientation takes precedence over potentially delayed signaling updates.
	videoOrientation byte
	rtpOrientation   bool
}

func newMediaBridge() *mediaBridge {
	return &mediaBridge{done: make(chan struct{}), audioIn: make(chan []float32, audioQueueSize), audioOut: make(chan []byte, audioQueueSize), videoIn: make(chan videoFrame, videoQueueSize), videoOut: make(chan videoFrame, videoQueueSize), participantOut: make(map[string][]videoFrame), participantReady: make(chan struct{}, 1)}
}

var _ meowcaller.VideoOrientationSink = (*mediaBridge)(nil)

func (b *mediaBridge) connected() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.used }

func (b *mediaBridge) bind(conn *websocket.Conn, cancel context.CancelFunc) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.used {
		return false
	}
	b.conn = conn
	b.cancel = cancel
	b.used = true
	return true
}

func (b *mediaBridge) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	close(b.done)
	conn, cancel := b.conn, b.cancel
	b.conn, b.cancel = nil, nil
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		return conn.CloseNow()
	}
	return nil
}

func (b *mediaBridge) allowAudio() {
	b.audioMu.Lock()
	defer b.audioMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	// No microphone history crosses the explicit acceptance boundary.
	drain(b.audioIn)
	drain(b.audioOut)
	b.audioPending = nil
	b.audioEnabled = true
}

func (b *mediaBridge) audioAllowed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.audioEnabled && !b.closed
}

func (b *mediaBridge) ReadFrame() ([]float32, error) {
	select {
	case <-b.done:
		return nil, io.EOF
	default:
	}
	if !b.audioAllowed() {
		return make([]float32, meowcaller.FrameSamples), nil
	}
	select {
	case <-b.done:
		return nil, io.EOF
	case frame := <-b.audioIn:
		return frame, nil
	default:
		// The library clocks ReadFrame every 60 ms; silence keeps the relay alive
		// when the browser is muted, ringing, or temporarily late.
		return make([]float32, meowcaller.FrameSamples), nil
	}
}

func (b *mediaBridge) WriteFrame(frame []float32) error {
	select {
	case <-b.done:
		return io.EOF
	default:
	}
	// The receive decoder can emit 20/60/120 ms chunks. Reframe them into the
	// browser protocol's exact 60 ms packets without accumulating unbounded PCM.
	if len(frame) == 0 || len(frame) > meowcaller.SampleRate*2 {
		return ErrInvalid
	}
	for _, sample := range frame {
		if math.IsNaN(float64(sample)) || math.IsInf(float64(sample), 0) {
			return ErrInvalid
		}
	}
	b.audioMu.Lock()
	defer b.audioMu.Unlock()
	if !b.audioAllowed() {
		b.audioPending = nil
		return nil
	}
	if b.audioPending == nil {
		b.audioPending = make([]byte, 0, audioBytes)
	}
	for _, sample := range frame {
		// Mask each byte of the signed PCM word explicitly. Negative samples
		// retain their two's-complement bit pattern without narrowing overflow.
		value := int32(math.Max(-32768, math.Min(32767, float64(sample)*32768)))
		b.audioPending = append(b.audioPending, byte(value&0xff), byte((value>>8)&0xff))
		if len(b.audioPending) == audioBytes {
			encoded := make([]byte, 1+audioBytes)
			encoded[0] = audioKind
			copy(encoded[1:], b.audioPending)
			offerLatest(b.audioOut, encoded)
			b.audioPending = b.audioPending[:0]
		}
	}
	return nil
}

// SetOrientation receives clockwise quarter turns from the RTP receive loop,
// immediately before its next WriteVideo call.
func (b *mediaBridge) SetOrientation(orientation int) {
	if orientation < 0 || orientation > 3 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.videoOrientation = byte(orientation)
		b.rtpOrientation = true
	}
}

func (b *mediaBridge) setVideoState(state meowcaller.VideoState) {
	if state.Orientation < 0 || state.Orientation > 3 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed && !b.rtpOrientation {
		b.videoOrientation = byte(state.Orientation)
	}
}

func (b *mediaBridge) WriteVideo(accessUnit []byte) error {
	select {
	case <-b.done:
		return io.EOF
	default:
	}
	if !validAnnexB(accessUnit) {
		return ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return io.EOF
	}
	if b.audioEnabled && !b.group {
		// Capture orientation together with owned bytes before the async queue;
		// a later rotation must never change an already received frame.
		offerLatest(b.videoOut, videoFrame{
			data: bytes.Clone(accessUnit), duration: 33333 * time.Microsecond,
			orientation: b.videoOrientation,
		})
	}
	return nil
}

func encodeVideoFrame(frame videoFrame, orientation bool) []byte {
	if frame.participant != "" {
		packet := make([]byte, 12+len(frame.participant)+len(frame.data))
		packet[0] = participantVideoKind
		packet[1] = frame.orientation
		binary.LittleEndian.PutUint32(packet[2:6], uint32((frame.duration/time.Microsecond)&math.MaxUint32))
		binary.LittleEndian.PutUint32(packet[6:10], frame.ssrc)
		binary.LittleEndian.PutUint16(packet[10:12], uint16(len(frame.participant)&math.MaxUint16))
		copy(packet[12:], frame.participant)
		copy(packet[12+len(frame.participant):], frame.data)
		return packet
	}
	headerBytes := 5
	if orientation {
		headerBytes = 6
	}
	packet := make([]byte, headerBytes+len(frame.data))
	packet[0] = videoKind
	if orientation {
		packet[0], packet[1] = orientedVideoKind, frame.orientation
	}
	binary.LittleEndian.PutUint32(packet[headerBytes-4:headerBytes], uint32((frame.duration/time.Microsecond)&math.MaxUint32))
	copy(packet[headerBytes:], frame.data)
	return packet
}

// receive validates every frame before decoding or queueing it. Integer PCM has
// no nonfinite values; library-provided floating point samples are checked above.
func (b *mediaBridge) receive(frame []byte, video bool) error {
	select {
	case <-b.done:
		return io.EOF
	default:
	}
	if len(frame) == 0 || len(frame) > maxMediaBytes {
		return ErrInvalid
	}
	switch frame[0] {
	case audioKind:
		if len(frame) != 1+audioBytes {
			return ErrInvalid
		}
		if !b.audioAllowed() {
			return nil
		}
		decoded := make([]float32, meowcaller.FrameSamples)
		for i := range decoded {
			value := int32(binary.LittleEndian.Uint16(frame[1+2*i:]))
			if value >= 0x8000 {
				value -= 0x10000
			}
			decoded[i] = float32(value) / 32768
		}
		offerLatest(b.audioIn, decoded)
	case videoKind:
		if !video || len(frame) < 9 {
			return ErrInvalid
		}
		duration := binary.LittleEndian.Uint32(frame[1:5])
		if duration < 1000 || duration > 1000000 || !validAnnexB(frame[5:]) {
			return ErrInvalid
		}
		if !b.audioAllowed() {
			return nil
		}
		offerLatest(b.videoIn, videoFrame{data: bytes.Clone(frame[5:]), duration: time.Duration(duration) * time.Microsecond})
	default:
		return ErrInvalid
	}
	return nil
}

func drain[T any](queue chan T) {
	for {
		select {
		case <-queue:
		default:
			return
		}
	}
}

func offerLatest[T any](queue chan T, value T) {
	select {
	case queue <- value:
		return
	default:
	}
	select {
	case <-queue:
	default:
	}
	select {
	case queue <- value:
	default:
	}
}

func validAnnexB(data []byte) bool {
	if len(data) < 4 || len(data) > maxVideoBytes {
		return false
	}
	var offset int
	if len(data) >= 5 && bytes.Equal(data[:4], []byte{0, 0, 0, 1}) {
		offset = 4
	} else if bytes.Equal(data[:3], []byte{0, 0, 1}) {
		offset = 3
	} else {
		return false
	}
	// H.264 NAL forbidden_zero_bit must be clear and the unit type nonzero.
	return data[offset]&0x80 == 0 && data[offset]&0x1f != 0
}

// ServeHTTP accepts same-origin and explicitly permitted websocket upgrades. A short-lived ticket
// travels in the first frame, never in URLs, referrers, or access logs.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s == nil {
		http.Error(w, "calling unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.BrowserOrigins.Allows(r) {
		http.Error(w, "browser origin is not allowed", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled, InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.CloseNow() //nolint:errcheck // final transport cleanup; the handler is already returning
	conn.SetReadLimit(1024)
	handshakeCtx, handshakeCancel := context.WithTimeout(r.Context(), 5*time.Second)
	kind, data, err := conn.Read(handshakeCtx)
	handshakeCancel()
	if err != nil {
		return
	}
	var hello struct {
		Ticket           string `json:"ticket"`
		VideoOrientation bool   `json:"video_orientation"`
		Participants     bool   `json:"participants"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if kind != websocket.MessageText || decoder.Decode(&hello) != nil || len(hello.Ticket) != 43 || decoder.Decode(new(any)) != io.EOF {
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid media handshake") //nolint:errcheck // best-effort rejection; deferred CloseNow guarantees local cleanup
		return
	}
	record, err := s.consumeTicket(hello.Ticket)
	if err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid media ticket") //nolint:errcheck // best-effort rejection; deferred CloseNow guarantees local cleanup
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if !record.bridge.bind(conn, cancel) {
		_ = conn.Close(websocket.StatusPolicyViolation, "media unavailable") //nolint:errcheck // best-effort rejection; deferred CloseNow guarantees local cleanup
		return
	}
	record.bridge.mu.Lock()
	record.bridge.participants = hello.Participants
	record.bridge.mu.Unlock()
	// From this point any browser/media transport failure ends the owned call.
	defer s.end(record, "media_disconnected", true)
	s.mu.Lock()
	valid := s.ownerAlive(record.owner) && record.snapshot.State != "ended"
	video, call := record.snapshot.Video, record.call
	if record.mediaWait != nil {
		record.mediaWait.Stop()
		record.mediaWait = nil
	}
	s.mu.Unlock()
	if !valid || call == nil {
		return
	}
	conn.SetReadLimit(maxMediaBytes)
	ready := []byte(`{"ready":true}`)
	if hello.VideoOrientation {
		ready = []byte(`{"ready":true,"video_orientation":true}`)
	}
	if hello.Participants {
		ready = []byte(`{"ready":true,"participants":true}`)
		if hello.VideoOrientation {
			ready = []byte(`{"ready":true,"video_orientation":true,"participants":true}`)
		}
	}
	writeCtx, writeCancel := context.WithTimeout(ctx, 5*time.Second)
	err = conn.Write(writeCtx, websocket.MessageText, ready)
	writeCancel()
	if err != nil {
		return
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		s.mediaWriter(ctx, conn, record.bridge, hello.VideoOrientation)
		cancel()
	}()
	go func() {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case frame := <-record.bridge.videoIn:
				// Frames arrive while an outgoing call is ringing. No video sender exists
				// until the WhatsApp peer answers, so those early frames are discarded.
				s.mu.Lock()
				active := record.snapshot.State == "active"
				s.mu.Unlock()
				if active {
					_ = call.SendVideoWithDuration(frame.data, frame.duration) //nolint:errcheck // transient video-frame loss is tolerated; call lifecycle owns disconnection
				}
			}
		}
	}()
	for {
		kind, frame, readErr := conn.Read(ctx)
		if readErr != nil || kind != websocket.MessageBinary || record.bridge.receive(frame, video) != nil {
			break
		}
	}
	cancel()
	_ = record.bridge.Close() //nolint:errcheck // local teardown is complete even if the peer socket already closed
	s.end(record, "media_disconnected", true)
	workers.Wait()
}

func (s *Service) mediaWriter(ctx context.Context, conn *websocket.Conn, b *mediaBridge, orientation bool) {
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		var frame []byte
		select {
		case <-ctx.Done():
			return
		case <-b.done:
			return
		case frame = <-b.audioOut:
		case <-b.participantReady:
			video, ok := b.nextParticipantVideo()
			if !ok {
				continue
			}
			frame = encodeVideoFrame(video, orientation)
		case video := <-b.videoOut:
			b.mu.Lock()
			valid := !b.group || video.participant != ""
			valid = valid && (video.participant == "" || b.participants)
			b.mu.Unlock()
			if !valid {
				continue
			}
			frame = encodeVideoFrame(video, orientation)
		case <-ping.C:
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return
			}
			continue
		}
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := conn.Write(writeCtx, websocket.MessageBinary, frame)
		cancel()
		if err != nil {
			return
		}
	}
}

func (b *mediaBridge) groupCapable() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used && !b.closed && b.participants
}
func (b *mediaBridge) enableGroup() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.group {
		b.group = true
		drain(b.videoOut)
	}
}
func (b *mediaBridge) writeParticipantVideo(frame videoFrame) {
	if !validAnnexB(frame.data) || len(frame.participant) == 0 || len(frame.participant) > 100 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || !b.audioEnabled || !b.group || !b.participants {
		return
	}
	queue, ok := b.participantOut[frame.participant]
	if !ok {
		return
	}
	frame.data = bytes.Clone(frame.data)
	if len(queue) == videoQueueSize {
		copy(queue, queue[1:])
		queue = queue[:len(queue)-1]
	}
	b.participantOut[frame.participant] = append(queue, frame)
	select {
	case b.participantReady <- struct{}{}:
	default:
	}
}

// Each connected person owns a bounded queue; a fast sender cannot evict another
// person's initial keyframe. The writer drains the queues in round-robin order.
func (b *mediaBridge) syncGroupParticipants(ids []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	next := make(map[string][]videoFrame, len(ids))
	for _, id := range ids {
		next[id] = b.participantOut[id]
	}
	b.participantOut = next
	b.participantOrder = append([]string(nil), ids...)
	b.participantCursor = 0
}
func (b *mediaBridge) nextParticipantVideo() (videoFrame, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || !b.group || !b.participants {
		return videoFrame{}, false
	}
	for i := 0; i < len(b.participantOrder); i++ {
		index := b.participantCursor % len(b.participantOrder)
		b.participantCursor = (index + 1) % len(b.participantOrder)
		id := b.participantOrder[index]
		queue := b.participantOut[id]
		if len(queue) == 0 {
			continue
		}
		frame := queue[0]
		queue[0] = videoFrame{}
		b.participantOut[id] = queue[1:]
		for _, remaining := range b.participantOut {
			if len(remaining) > 0 {
				select {
				case b.participantReady <- struct{}{}:
				default:
				}
				break
			}
		}
		return frame, true
	}
	return videoFrame{}, false
}
