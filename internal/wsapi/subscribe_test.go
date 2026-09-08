package wsapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/bus"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// The subscription, end to end over a real websocket.
//
// The pieces were tested apart: the bus covers the replay race and the lag
// path, and mergeReplay covers the ordering of two streams. What none of them
// covers is the handover as a client actually experiences it — the frames, in
// order, with nothing missing and nothing twice. That is the contract every
// client depends on and the one most likely to break in a refactor that looks
// harmless.

type stream struct {
	srv      *httptest.Server
	key      string
	pool     *pgxpool.Pool
	tenant   uuid.UUID
	device   uuid.UUID
	messages *store.Messages
	receipts *store.Receipts
	bus      *bus.Bus
}

func newStream(t *testing.T) *stream {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(pool)
	apiKey, err := keys.Issue(ctx, tenantID, "test")
	if err != nil {
		t.Fatal(err)
	}
	devices := store.NewDevices(pool)
	dev, err := devices.Create(ctx, tenantID, "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}

	b := bus.New()
	messages := store.NewMessages(pool)
	receipts := store.NewReceipts(pool)

	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: keys, Devices: devices, Messages: messages, Receipts: receipts,
		Bus: b, Log: slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(srv.Close)

	return &stream{
		srv: srv, key: apiKey, pool: pool,
		tenant: uuid.MustParse(tenantID), device: uuid.MustParse(dev.ID),
		messages: messages, receipts: receipts, bus: b,
	}
}

const streamChat = "5511999999999@s.whatsapp.net"

// put stores a message and returns its sequence, without publishing it.
func (s *stream) put(t *testing.T, waID string) int64 {
	t.Helper()
	res, err := s.messages.Insert(context.Background(), store.InsertMessage{
		UID: uuid.New(), TenantID: s.tenant, DeviceID: s.device,
		WAID: waID, ChatKey: streamChat,
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: time.Now(),
		BodySealed: []byte("sealed " + waID),
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Seq
}

// live stores a message and publishes it, the way ingest does.
func (s *stream) live(t *testing.T, waID string) int64 {
	t.Helper()
	res, err := s.messages.Insert(context.Background(), store.InsertMessage{
		UID: uuid.New(), TenantID: s.tenant, DeviceID: s.device,
		WAID: waID, ChatKey: streamChat,
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: time.Now(),
		BodySealed: []byte("sealed " + waID),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.bus.Publish(s.tenant, ingest.Event{
		Class: ingest.ClassMessage, Seq: res.Seq,
		TenantID: s.tenant, DeviceID: s.device, ChatKey: streamChat,
		Kind: domain.KindMessage, Type: domain.TypeText, UID: res.UID,
	})
	return res.Seq
}

// ack stores a receipt and publishes it.
func (s *stream) ack(t *testing.T, waIDs ...string) int64 {
	t.Helper()
	res, err := s.receipts.Insert(context.Background(), store.InsertReceipt{
		TenantID: s.tenant, DeviceID: s.device,
		ChatKey: streamChat, ReaderKey: streamChat,
		WAIDs: waIDs, Kind: domain.ReceiptRead, TS: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Duplicate {
		t.Fatal("the receipt was already known")
	}
	s.bus.Publish(s.tenant, ingest.Event{
		Class: ingest.ClassReceipt, Seq: res.Seq,
		TenantID: s.tenant, DeviceID: s.device, ChatKey: streamChat,
	})
	return res.Seq
}

// subscribe authenticates and starts a subscription.
func (s *stream) subscribe(t *testing.T, since int64) *websocket.Conn {
	t.Helper()
	conn := dial(t, s.srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: s.key, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("handshake answered %q", f.Type)
	}
	send(t, conn, wsapi.TypeSubscribe, wsapi.Subscribe{SinceSeq: since})
	return conn
}

// event is one frame reduced to what the ordering contract is about.
type event struct {
	kind string // "message" or "receipt"
	seq  int64
	waID string
}

// decode turns a data frame into the shape the ordering contract is about,
// reporting false for the frames that are not one.
func decode(t *testing.T, f wsapi.Frame) (event, bool) {
	t.Helper()
	switch f.Type {
	case wsapi.TypeMessage:
		var m wsapi.SealedMessage
		if err := json.Unmarshal(f.Payload, &m); err != nil {
			t.Fatal(err)
		}
		return event{kind: "message", seq: m.Seq, waID: m.WAID}, true
	case wsapi.TypeReceipt:
		var r wsapi.ReceiptEvent
		if err := json.Unmarshal(f.Payload, &r); err != nil {
			t.Fatal(err)
		}
		ev := event{kind: "receipt", seq: r.Seq}
		if len(r.WAIDs) > 0 {
			ev.waID = r.WAIDs[0]
		}
		return ev, true
	case wsapi.TypeError:
		t.Fatalf("server answered with an error: %s", f.Payload)
	}
	return event{}, false
}

// drainReplay reads until the handover, returning what the replay delivered
// and the watermark it stopped at.
func drainReplay(t *testing.T, conn *websocket.Conn) (replay []event, endSeq int64) {
	t.Helper()
	for {
		f := read(t, conn)
		if f.Type == wsapi.TypeReplayEnd {
			var p wsapi.ReplayEnd
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				t.Fatal(err)
			}
			return replay, p.LastSeq
		}
		if ev, ok := decode(t, f); ok {
			replay = append(replay, ev)
		}
	}
}

// readEvents reads n more data frames, after the handover.
func readEvents(t *testing.T, conn *websocket.Conn, n int) []event {
	t.Helper()
	var out []event
	for len(out) < n {
		if ev, ok := decode(t, read(t, conn)); ok {
			out = append(out, ev)
		}
	}
	return out
}

// assertOrdered checks that sequences strictly increase and nothing repeats.
func assertOrdered(t *testing.T, what string, events []event) {
	t.Helper()
	seen := map[int64]bool{}
	var last int64
	for i, ev := range events {
		if seen[ev.seq] {
			t.Fatalf("%s: sequence %d was delivered twice", what, ev.seq)
		}
		seen[ev.seq] = true
		if i > 0 && ev.seq <= last {
			t.Fatalf("%s: sequence %d arrived after %d", what, ev.seq, last)
		}
		last = ev.seq
	}
}

// TestReplayThenLiveIsContinuous is the contract every client rests on: what
// was stored before subscribing arrives first, in order, and live traffic
// follows without repeating any of it.
func TestReplayThenLiveIsContinuous(t *testing.T) {
	s := newStream(t)
	for i := range 5 {
		s.put(t, fmt.Sprintf("OLD%d", i))
	}

	conn := s.subscribe(t, 0)
	// Wait for the handover before publishing, so this test is about
	// continuity rather than about the race, which has its own test below.
	replay, endSeq := drainReplay(t, conn)
	if len(replay) != 5 {
		t.Fatalf("replayed %d messages, want 5", len(replay))
	}
	assertOrdered(t, "replay", replay)
	if endSeq != replay[len(replay)-1].seq {
		t.Fatalf("replay ended at %d but the last message was %d", endSeq, replay[4].seq)
	}

	for i := range 3 {
		s.live(t, fmt.Sprintf("NEW%d", i))
	}
	liveEvents := readEvents(t, conn, 3)
	assertOrdered(t, "live", liveEvents)
	for _, ev := range liveEvents {
		if ev.seq <= endSeq {
			t.Fatalf("live delivered sequence %d, at or below the replay watermark %d",
				ev.seq, endSeq)
		}
	}
}

// TestResumeSendsOnlyWhatIsNewer. A client that reconnects with a cursor must
// not be handed its whole history again.
func TestResumeSendsOnlyWhatIsNewer(t *testing.T) {
	s := newStream(t)
	var cursor int64
	for i := range 4 {
		cursor = s.put(t, fmt.Sprintf("OLD%d", i))
	}
	// Two messages exist above this point.
	resumeFrom := cursor - 2

	conn := s.subscribe(t, resumeFrom)
	replay, _ := drainReplay(t, conn)
	if len(replay) != 2 {
		t.Fatalf("replayed %d messages from a cursor, want the 2 above it", len(replay))
	}
	for _, ev := range replay {
		if ev.seq <= resumeFrom {
			t.Fatalf("sequence %d was replayed although the client already had it", ev.seq)
		}
	}
}

// TestMessagesAndReceiptsArriveInOneOrder.
//
// They share the tenant cursor, so a client has one position covering both. A
// receipt delivered before the message it acknowledges is a client drawing a
// tick on something it has not been told about.
func TestMessagesAndReceiptsArriveInOneOrder(t *testing.T) {
	s := newStream(t)
	s.put(t, "M1")
	s.ack(t, "M1")
	s.put(t, "M2")
	s.ack(t, "M2")

	conn := s.subscribe(t, 0)
	replay, _ := drainReplay(t, conn)
	if len(replay) != 4 {
		t.Fatalf("replayed %d frames, want 2 messages and 2 receipts", len(replay))
	}
	assertOrdered(t, "replay", replay)
	want := []string{"message", "receipt", "message", "receipt"}
	for i, ev := range replay {
		if ev.kind != want[i] {
			t.Fatalf("frame %d was a %s, want %s; order was %+v", i, ev.kind, want[i], replay)
		}
	}

	// And live, through the same cursor.
	s.live(t, "M3")
	s.ack(t, "M3")
	liveEvents := readEvents(t, conn, 2)
	assertOrdered(t, "live", liveEvents)
	if liveEvents[0].kind != "message" || liveEvents[1].kind != "receipt" {
		t.Fatalf("live order was %+v", liveEvents)
	}
}

// TestNothingIsLostOrRepeatedAcrossTheHandover is the race, as a client meets
// it.
//
// Messages are published while the replay is still running. Each one is either
// caught by the history read or buffered by the subscription, and the handover
// has to deliver every sequence exactly once — the failure it guards against is
// silent, because a client that never hears about a message has nothing to
// notice.
func TestNothingIsLostOrRepeatedAcrossTheHandover(t *testing.T) {
	s := newStream(t)
	const before, during = 40, 20
	for i := range before {
		s.put(t, fmt.Sprintf("OLD%d", i))
	}

	conn := s.subscribe(t, 0)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range during {
			s.live(t, fmt.Sprintf("RACE%d", i))
		}
	}()
	wg.Wait()

	seen := map[string]int{}
	deadline := time.Now().Add(20 * time.Second)
	for len(seen) < before+during && time.Now().Before(deadline) {
		f := read(t, conn)
		if f.Type != wsapi.TypeMessage {
			continue
		}
		var m wsapi.SealedMessage
		if err := json.Unmarshal(f.Payload, &m); err != nil {
			t.Fatal(err)
		}
		seen[m.WAID]++
	}

	if len(seen) != before+during {
		t.Fatalf("saw %d distinct messages, want %d: something was lost across the "+
			"handover", len(seen), before+during)
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("%s was delivered %d times", id, count)
		}
	}
}

// TestASecondSubscriptionOnOneConnectionIsRefused. Two subscriptions would
// interleave two cursors down one socket, and the client would have no way to
// tell which position a frame belonged to.
func TestASecondSubscriptionOnOneConnectionIsRefused(t *testing.T) {
	s := newStream(t)
	s.put(t, "M1")
	conn := s.subscribe(t, 0)
	drainReplay(t, conn)

	send(t, conn, wsapi.TypeSubscribe, wsapi.Subscribe{SinceSeq: 0})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		f := read(t, conn)
		if f.Type != wsapi.TypeError {
			continue
		}
		var e wsapi.Error
		if err := json.Unmarshal(f.Payload, &e); err != nil {
			t.Fatal(err)
		}
		if e.Code != wsapi.ErrCodeConflict {
			t.Fatalf("code = %q, want conflict", e.Code)
		}
		return
	}
	t.Fatal("a second subscription was accepted on the same connection")
}
