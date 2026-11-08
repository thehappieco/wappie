package wsapi_test

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
	"whatserver2/internal/wsapi"
)

// inLoop reports whether the calling goroutine runs the session's loop
// named: readLoop, writeLoop or accessLoop. All three check a token
// session's sets, through the one hook.
func inLoop(name string) bool {
	buf := make([]byte, 64<<10)
	n := runtime.Stack(buf, false)
	return strings.Contains(string(buf[:n]), "wsapi.(*session)."+name+"(")
}

// waitFor waits on c, failing the test after 10 s.
func waitFor(t *testing.T, name string, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(10 * time.Second):
		t.Fatalf("no %s", name)
	}
}

// TestTheWriterJudgesUnderItsOwnCheck: the writer checks a token's sets
// before each batch, and the batch goes out under that check, whatever an
// other loop kept. Here the writer's check gets its number first but reads
// last, as one waiting for a connection does: accessLoop's check, numbered
// after it, reads a's grant, the key rotates, and the writer's check reads
// the rotation. The newest kept sets still hold a; a's presence, queued
// before the writer's check, must not go out.
func TestTheWriterJudgesUnderItsOwnCheck(t *testing.T) {
	var mu sync.Mutex
	state := 0
	writerHeld, releaseWriter, wideKept, stopAccess := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	hook := func(stage string) {
		mu.Lock()
		st := state
		switch {
		case st == 1 && stage == "asked" && inLoop("writeLoop"):
			state = 2
			mu.Unlock()
			close(writerHeld)
			<-releaseWriter
			return
		case st == 2 && stage == "asked" && inLoop("accessLoop"):
			state = 3
		case st == 3 && stage == "checked" && inLoop("accessLoop"):
			state = 4
			mu.Unlock()
			close(wideKept)
			return
		case st == 4 && stage == "asked" && inLoop("accessLoop"):
			// No later check of accessLoop's keeps the rotation before
			// the writer writes.
			mu.Unlock()
			<-stopAccess
			return
		}
		mu.Unlock()
	}
	ts := newTokenSocket(t, func(cfg *wsapi.Config) { wsapi.SetTokenHook(cfg, hook) })
	t.Cleanup(func() { close(stopAccess) })
	w := ts.w
	a, b := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Read(a), tokentest.Read(b))
	conn := ts.open(t, tok)
	frames := drain(conn)
	request(t, conn, "sub", wsapi.TypeSubscribe, wsapi.Subscribe{LiveOnly: true})
	next(t, frames, wsapi.TypeReplayEnd)
	presence := func(d uuid.UUID) {
		ts.bus.Publish(w.Tenant, ingest.Event{Class: ingest.ClassPresence, TenantID: w.Tenant, DeviceID: d, Ephemeral: true,
			Presence: &ingest.Presence{ChatKey: "5511999999999@s.whatsapp.net", State: "composing"}})
	}
	presence(a)
	if p := payload[wsapi.PresenceEvent](t, next(t, frames, wsapi.TypePresence)); p.DeviceID != a.String() {
		t.Fatalf("the first presence: %+v", p)
	}

	mu.Lock()
	state = 1
	mu.Unlock()
	presence(a)
	waitFor(t, "writer's check", writerHeld)
	ts.checker.Watch.Notify(tok.ID.String())
	waitFor(t, "check of accessLoop's", wideKept)
	w.Rotate(a, 2)
	close(releaseWriter)
	presence(b)
	if p := payload[wsapi.PresenceEvent](t, next(t, frames, wsapi.TypePresence)); p.DeviceID != b.String() {
		t.Fatalf("a's presence went out after the writer's own check read the rotation: %+v", p)
	}
}

// TestATokensBatchMeetsTheNewestSetsFrameByFrame: the writer takes the
// frames already queued as one batch, and a slow client can stretch a
// batch far past a second. Each frame meets the newest sets kept when it
// goes out, not the sets of the batch's start; and a check never replaces
// one that started after it. Here two replies, each an image of a, are
// one batch. While the first is written, a check of readLoop's reads
// attachments on and waits; attachments go off, which bumps no version;
// accessLoop's next checks keep that; then readLoop's older check lands.
// The second reply goes out withheld.
func TestATokensBatchMeetsTheNewestSetsFrameByFrame(t *testing.T) {
	var ts *tokenSocket
	var mu sync.Mutex
	var hold, held chan struct{}
	armed, counting, readReleased := false, false, false
	accessChecks := 0
	readHeld, releaseRead, readKept, accessKept := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	queued := make(chan struct{}, 16)
	ts = newTokenSocket(t, func(cfg *wsapi.Config) {
		wsapi.SetTokenHook(cfg, func(stage string) {
			switch stage {
			case "queried":
				mu.Lock()
				if armed && inLoop("readLoop") {
					armed = false
					mu.Unlock()
					close(readHeld)
					<-releaseRead
					return
				}
				mu.Unlock()
			case "checked":
				ts.checks.Add(1)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case counting && inLoop("accessLoop"):
					if accessChecks++; accessChecks == 2 {
						close(accessKept)
					}
				case readReleased && inLoop("readLoop"):
					readReleased = false
					close(readKept)
				}
			case "queued":
				select {
				case queued <- struct{}{}:
				default:
				}
			case "wrote":
				mu.Lock()
				h, d := hold, held
				hold, held = nil, nil
				mu.Unlock()
				if h != nil {
					close(d)
					<-h
				}
			}
		})
	})
	// holdNext holds the writer after the next frame it writes.
	holdNext := func() (<-chan struct{}, func()) {
		mu.Lock()
		defer mu.Unlock()
		hold, held = make(chan struct{}), make(chan struct{})
		h := hold
		return held, func() { close(h) }
	}
	w := ts.w
	a := w.Number("Vendas")
	tok := w.Token(tokentest.Read(a))
	image := func() uuid.UUID {
		uid := uuid.New()
		if _, err := store.NewMessages(ts.pool).Insert(context.Background(), store.InsertMessage{UID: uid, TenantID: w.Tenant, DeviceID: a,
			WAID: "wa-" + uid.String(), ChatKey: "5511999999999@s.whatsapp.net", TS: time.Now(), Kind: domain.KindMessage,
			Type: domain.TypeImage, Source: domain.SourceLive, BodySealed: []byte("caption"),
			Media: &store.InsertMedia{MediaType: "image", MimeType: "image/jpeg", MediaKeySealed: []byte("key")}}); err != nil {
			t.Fatal(err)
		}
		return uid
	}
	first, second := image(), image()
	conn := ts.open(t, tok)
	frames := drain(conn)

	// The writer is held after a pong while both replies are queued, so
	// it takes them as one batch.
	pong, releasePong := holdNext()
	request(t, conn, "p", wsapi.TypePing, nil)
	waitFor(t, "pong", pong)
	request(t, conn, "g1", wsapi.TypeMessageGet, wsapi.MessageGetRequest{UID: first.String()})
	request(t, conn, "g2", wsapi.TypeMessageGet, wsapi.MessageGetRequest{UID: second.String()})
	waitFor(t, "first reply queued", queued)
	waitFor(t, "second reply queued", queued)
	written, releaseWritten := holdNext()
	releasePong()
	waitFor(t, "first reply written", written)

	// A check of readLoop's reads attachments on, and waits to keep it.
	mu.Lock()
	armed = true
	mu.Unlock()
	request(t, conn, "p2", wsapi.TypePing, nil)
	waitFor(t, "readLoop's check", readHeld)
	// Attachments off, and two checks of accessLoop's after it: the
	// second started after the first ended, so after the switch.
	off := false
	w.Switches(nil, &off)
	mu.Lock()
	counting = true
	mu.Unlock()
	ts.checker.Watch.Notify(tok.ID.String())
	waitFor(t, "two checks of accessLoop's", accessKept)
	// readLoop's older check lands now, and must not replace them.
	mu.Lock()
	readReleased = true
	mu.Unlock()
	close(releaseRead)
	waitFor(t, "readLoop's check to land", readKept)
	releaseWritten()

	var got []wsapi.SealedMessage
	timeout := time.After(10 * time.Second)
	for len(got) < 2 {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("the connection ended")
			}
			if f.ReqID == "g1" || f.ReqID == "g2" {
				if f.Type != wsapi.TypeMessageFrame {
					t.Fatalf("%s: %s %s", f.ReqID, f.Type, f.Payload)
				}
				got = append(got, payload[wsapi.SealedMessage](t, f))
			}
		case <-timeout:
			t.Fatal("no replies")
		}
	}
	if got[0].Withheld != "" || got[0].Media == nil || got[0].Media.MediaKeySealed == nil {
		t.Fatalf("the reply written before the switch: %+v", got[0])
	}
	if got[1].Withheld != wsapi.WithheldAttachments || got[1].Media == nil || got[1].Media.MediaKeySealed != nil {
		t.Fatalf("the batch's second reply went out under older sets: %+v", got[1])
	}
}
