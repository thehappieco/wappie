package wsapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// A replay of any length, to a client that reads it.
//
// The writer used to check access once per frame, a database round trip or
// two each, while the replay queued a page of five hundred frames at memory
// speed. The queue holds 256, so it filled behind the checks and a client
// doing nothing wrong was closed as a "slow consumer" — with code 1008, which
// the SDK reports as access having changed. Nothing larger than about 256
// frames could be replayed in one go.

// TestALongReplayReachesAHealthyClient replays thousands of messages with
// their receipts from the start of the archive, and every one arrives, in
// order, on a connection that is still open afterwards.
func TestALongReplayReachesAHealthyClient(t *testing.T) {
	s := newStream(t)
	const messages, ackEvery = 3000, 50
	acks := 0
	for i := 0; i < messages; i += ackEvery {
		prefix := fmt.Sprintf("M%d-", i)
		s.bulk(t, prefix, ackEvery, []byte("sealed"))
		s.ack(t, prefix+"1")
		acks++
	}
	watermark, err := s.messages.MaxSeq(context.Background(), s.tenant)
	if err != nil {
		t.Fatal(err)
	}

	conn := s.subscribe(t, 0)
	// A command in the middle of the replay: its answer must neither trip
	// the guard nor wait behind thousands of frames.
	send(t, conn, wsapi.TypePing, nil)

	var replay []event
	var end wsapi.ReplayEnd
	pongAt := -1
	for done := false; !done; {
		f := read(t, conn)
		switch f.Type {
		case wsapi.TypeReplayBegin:
		case wsapi.TypePong:
			pongAt = len(replay)
		case wsapi.TypeReplayEnd:
			if err := json.Unmarshal(f.Payload, &end); err != nil {
				t.Fatal(err)
			}
			done = true
		default:
			if ev, ok := decode(t, f); ok {
				replay = append(replay, ev)
			}
		}
	}

	if len(replay) != messages+acks {
		t.Fatalf("replayed %d frames, want %d messages and %d receipts", len(replay), messages, acks)
	}
	assertOrdered(t, "replay", replay)
	if end.Count != len(replay) || end.LastSeq != watermark {
		t.Fatalf("replay.end = %+v, want count %d through %d", end, len(replay), watermark)
	}
	if pongAt < 0 {
		t.Fatal("the ping sent during the replay was never answered")
	}
	if pongAt > len(replay)/2 {
		t.Errorf("the pong came after %d of %d replayed frames: replies wait behind the replay", pongAt, len(replay))
	}

	// Still connected, and live delivery carries on from the watermark.
	seq := s.live(t, "AFTER")
	if got := readEvents(t, conn, 1); got[0].seq != seq {
		t.Fatalf("live delivered %+v, want sequence %d", got, seq)
	}
}

// TestRevocationMidReplayStopsDelivery revokes the connection's key while a
// long replay is under way, from outside this process, which nothing wakes
// the connection for.
//
// The writer now checks access once per batch of frames already queued, not
// once per frame. What that must not weaken is when a revoked connection
// stops: at its next batch while it is still writing, so at most one batch
// goes out after the revocation commits, and never the end of the replay.
func TestRevocationMidReplayStopsDelivery(t *testing.T) {
	s := newStream(t)
	// Large enough that the socket buffers between the two ends cannot hold
	// the whole replay: the server is blocked writing it, mid-replay, when
	// the client pauses.
	const messages = 2000
	s.bulk(t, "BIG", messages, bytes.Repeat([]byte("x"), 8<<10))

	metrics := obs.NewMetrics()
	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: store.NewAPIKeys(s.pool), Devices: store.NewDevices(s.pool),
		Messages: s.messages, Receipts: s.receipts, Bus: s.bus,
		Metrics: metrics, Log: slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(srv.Close)
	written := func() int {
		return int(testutil.ToFloat64(metrics.WSFramesSent.WithLabelValues(wsapi.TypeMessage)))
	}

	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: s.key, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("handshake answered %q", f.Type)
	}
	send(t, conn, wsapi.TypeSubscribe, wsapi.Subscribe{SinceSeq: 0})
	received := 0
	for received < 100 {
		if f := read(t, conn); f.Type == wsapi.TypeMessage {
			received++
		}
	}

	// Stop reading until the server is blocked on the socket, so the count
	// of frames written is still when the revocation commits.
	before := stalled(t, written)
	if before >= messages {
		t.Fatalf("all %d frames were written before the pause; the replay must still be under way", before)
	}

	prefix, _, _ := strings.Cut(s.key, ".")
	if err := store.NewAPIKeys(s.pool).Revoke(context.Background(), s.tenant.String(), prefix); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			// A slow consumer is closed with the same code; the reason
			// tells the two apart.
			var closed websocket.CloseError
			if !errors.As(err, &closed) || closed.Code != websocket.StatusPolicyViolation ||
				!strings.Contains(closed.Reason, "access changed") {
				t.Fatalf("the replay ended with %v, want the close for changed access", err)
			}
			break
		}
		var f wsapi.Frame
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		switch f.Type {
		case wsapi.TypeMessage:
			received++
		case wsapi.TypeReplayEnd:
			t.Fatalf("the replay ran to its end after the key was revoked, %d frames in", received)
		}
	}
	if took := time.Since(revoked); took > 3*time.Second {
		t.Errorf("the revoked connection closed %v after the revocation", took)
	}
	if received >= messages {
		t.Fatalf("received all %d messages despite the revocation", received)
	}
	// At most the batch already authorised before the commit, which the
	// writer was in the middle of. A writer that stopped checking would run
	// on until the periodic check, a second later.
	after := written() - before
	t.Logf("%d frames written before the revocation, %d after; %d received", before, after, received)
	if after > 64 {
		t.Fatalf("%d frames were written after the revocation committed, want at most one batch of 64", after)
	}
}

// stalled waits until a client that stopped reading has the server blocked
// on the socket, and returns the count of frames written then, which holds
// still from there until the client reads again.
func stalled(t *testing.T, written func() int) int {
	t.Helper()
	before := written()
	for deadline := time.Now().Add(10 * time.Second); ; {
		time.Sleep(200 * time.Millisecond)
		now := written()
		if now == before {
			return now
		}
		if time.Now().After(deadline) {
			t.Fatal("the server never stopped writing to a client that stopped reading")
		}
		before = now
	}
}

// TestADeletionStopsFramesAlreadyQueued drops a number from the bus while
// its replay waits on a client that stopped reading: a batch the writer
// holds, the stream's hand-off full behind it, and a row the replay is
// waiting to queue, all checked against the subscription before the drop.
// None of them is written after it, and the subscription goes on with the
// other number.
func TestADeletionStopsFramesAlreadyQueued(t *testing.T) {
	s := newStream(t)
	ctx := context.Background()
	const messages = 2000
	s.bulk(t, "BIG", messages, bytes.Repeat([]byte("x"), 8<<10))
	kept, err := store.NewDevices(s.pool).Create(ctx, s.tenant.String(), "kept", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}

	metrics := obs.NewMetrics()
	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: store.NewAPIKeys(s.pool), Devices: store.NewDevices(s.pool),
		Messages: s.messages, Receipts: s.receipts, Bus: s.bus,
		Metrics: metrics, Log: slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(srv.Close)
	written := func() int {
		return int(testutil.ToFloat64(metrics.WSFramesSent.WithLabelValues(wsapi.TypeMessage)))
	}

	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: s.key, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("handshake answered %q", f.Type)
	}
	send(t, conn, wsapi.TypeSubscribe, wsapi.Subscribe{SinceSeq: 0})
	for received := 0; received < 100; {
		if f := read(t, conn); f.Type == wsapi.TypeMessage {
			received++
		}
	}
	before := stalled(t, written)
	if before >= messages {
		t.Fatalf("all %d frames were written before the pause; the replay must still be under way", before)
	}

	// What a deletion does right after its commit.
	s.bus.DropDevice(s.tenant, s.device)

	// The socket's buffers hold frames written before the drop; then the
	// replay ends, the rest of its rows skipped.
	for f := read(t, conn); f.Type != wsapi.TypeReplayEnd; f = read(t, conn) {
		if f.Type == wsapi.TypeSubscriptionEnded || f.Type == wsapi.TypeError {
			t.Fatalf("the replay answered %s %s", f.Type, f.Payload)
		}
	}
	// At most the one frame the writer was blocked on when the drop came.
	after := written() - before
	t.Logf("%d frames written before the drop, %d after", before, after)
	if after > 1 {
		t.Fatalf("%d of the dropped number's frames were written after the drop, want at most the one in flight", after)
	}

	// Still subscribed to the other number, and live from the watermark.
	res, err := s.messages.Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: s.tenant, DeviceID: uuid.MustParse(kept.ID),
		WAID: "KEPT", ChatKey: streamChat, Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte("sealed KEPT"),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.bus.Publish(s.tenant, ingest.Event{
		Class: ingest.ClassMessage, Seq: res.Seq,
		TenantID: s.tenant, DeviceID: uuid.MustParse(kept.ID), ChatKey: streamChat,
		Kind: domain.KindMessage, Type: domain.TypeText, UID: res.UID,
	})
	if got := readEvents(t, conn, 1); got[0].waID != "KEPT" {
		t.Fatalf("live delivered %+v, want the kept number's message", got)
	}
}

// TestALiveBurstDuringASlowReplayLags: live traffic while a client is slow to
// read its replay is held back up to what the handover can deliver, and the
// rest is a lag frame telling it where to resume, not a closed connection.
func TestALiveBurstDuringASlowReplayLags(t *testing.T) {
	s := newStream(t)
	// Far more than the socket buffers hold, so the replay is still under
	// way while the client is not reading.
	const history, burst, held = 1000, 600, 512
	s.bulk(t, "OLD", history, bytes.Repeat([]byte("x"), 8<<10))

	conn := s.subscribe(t, 0)
	if f := read(t, conn); f.Type != wsapi.TypeReplayBegin {
		t.Fatalf("subscribe answered %q", f.Type)
	}
	s.bulk(t, "LIVE", burst, []byte("sealed"))
	live := s.publishAll(t, "LIVE")
	if len(live) != burst {
		t.Fatalf("published %d live events, want %d", len(live), burst)
	}

	replay, endSeq := drainReplay(t, conn)
	if len(replay) != history {
		t.Fatalf("replayed %d messages, want %d", len(replay), history)
	}
	if endSeq >= live[0] {
		t.Fatalf("the replay reached %d, past the first live event %d", endSeq, live[0])
	}
	f := read(t, conn)
	if f.Type != wsapi.TypeLag {
		t.Fatalf("after the replay came %q, want a lag", f.Type)
	}
	var lag wsapi.Lag
	if err := json.Unmarshal(f.Payload, &lag); err != nil {
		t.Fatal(err)
	}
	if lag.FromSeq != live[held] || lag.Dropped != burst-held {
		t.Fatalf("lag = %+v, want from %d with %d dropped", lag, live[held], burst-held)
	}
	got := readEvents(t, conn, held)
	for i, ev := range got {
		if ev.seq != live[i] {
			t.Fatalf("live event %d was sequence %d, want %d", i, ev.seq, live[i])
		}
	}
}

// publishAll publishes every stored message whose wa id starts with prefix,
// in sequence order, the way ingest does, and returns their sequences.
func (s *stream) publishAll(t *testing.T, prefix string) []int64 {
	t.Helper()
	ctx := context.Background()
	var seqs []int64
	if err := pg.InTenantTx(ctx, s.pool, s.tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT uid, seq FROM messages
			 WHERE tenant_id = $1 AND starts_with(wa_id, $2) ORDER BY seq`, s.tenant, prefix)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var uid uuid.UUID
			var seq int64
			if err := rows.Scan(&uid, &seq); err != nil {
				return err
			}
			s.bus.Publish(s.tenant, ingest.Event{
				Class: ingest.ClassMessage, Seq: seq,
				TenantID: s.tenant, DeviceID: s.device, ChatKey: streamChat,
				Kind: domain.KindMessage, Type: domain.TypeText, UID: uid,
			})
			seqs = append(seqs, seq)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return seqs
}

// bulk stores n messages in one statement, wa ids prefix1 to prefixN, each
// with the given body, without publishing them.
//
// Thousands of rows through Messages.Insert take minutes against the
// development database, a handful of round trips each; the replay reads
// rows, not how they were written.
func (s *stream) bulk(t *testing.T, prefix string, n int, body []byte) {
	t.Helper()
	ctx := context.Background()
	if err := pg.InTenantTx(ctx, s.pool, s.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			WITH c AS (
				UPDATE tenants SET last_seq = last_seq + $3 WHERE id = $1
				RETURNING last_seq - $3 AS base)
			INSERT INTO messages (tenant_id, device_id, seq, wa_id, chat_key, ts,
			                      kind, type, source, body_sealed)
			SELECT $1, $2, c.base + g, $4 || g, $5, now(), 'message', 'text', 'live', $6
			  FROM c, generate_series(1, $3::int) g`,
			s.tenant, s.device, n, prefix, streamChat, body)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
