package wsapi_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thehappieco/kit/vectors"

	"whatserver2/internal/access"
	"whatserver2/internal/bus"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/membership"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

const (
	tokenFrameRefused  = "a platform token cannot do this"
	tokenNumberRefused = "this token cannot do that on this number"
)

// tokenSocket is a socket server whose checker takes platform tokens, over
// a workspace where tokens are on.
type tokenSocket struct {
	w       *tokentest.World
	pool    *pgxpool.Pool
	srv     *httptest.Server
	checker *access.Checker
	bus     *bus.Bus
	checks  atomic.Int64
	mu      sync.Mutex
	onReply func()
}

func newTokenSocket(t *testing.T, opts ...func(*wsapi.Config)) *tokenSocket {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ts := &tokenSocket{w: tokentest.New(t, pool, uuid.Nil), pool: pool, bus: bus.New()}
	users := store.NewUsers(pool)
	ts.checker = &access.Checker{Keys: store.NewAPIKeys(pool), Users: users, Tokens: ts.w.Tokens,
		Switches: store.TokenSwitches{Default: true}, Watch: access.NewTokenWatch(), Use: &access.TokenUse{Store: ts.w.Tokens}}
	cfg := wsapi.Config{Keys: store.NewAPIKeys(pool), Sessions: users, Accounts: users, Devices: store.NewDevices(pool),
		Messages: store.NewMessages(pool), Keys2: store.NewKeys(pool), Receipts: store.NewReceipts(pool), Media: store.NewMedia(pool),
		Bus: ts.bus, Access: ts.checker, Log: slog.New(slog.DiscardHandler)}
	wsapi.SetTokenHook(&cfg, func(stage string) {
		switch stage {
		case "checked":
			ts.checks.Add(1)
		case "reply":
			ts.mu.Lock()
			hook := ts.onReply
			ts.onReply = nil
			ts.mu.Unlock()
			if hook != nil {
				hook()
			}
		}
	})
	for _, opt := range opts {
		opt(&cfg)
	}
	ts.srv = httptest.NewServer(wsapi.NewServer(cfg))
	t.Cleanup(ts.srv.Close)
	return ts
}

// hello opens a socket with a hello of api_key text and returns its answer.
func (ts *tokenSocket) hello(t *testing.T, h wsapi.Hello) (*websocket.Conn, wsapi.Frame) {
	t.Helper()
	conn := dial(t, ts.srv)
	h.Version = wsapi.Version
	send(t, conn, wsapi.TypeHello, h)
	return conn, read(t, conn)
}

// open opens a token's socket.
func (ts *tokenSocket) open(t *testing.T, tok *tokentest.Token) *websocket.Conn {
	t.Helper()
	conn, f := ts.hello(t, wsapi.Hello{APIKey: tok.Text})
	if f.Type != wsapi.TypeWelcome {
		t.Fatalf("the token's hello: %s %s", f.Type, f.Payload)
	}
	return conn
}

var reqs atomic.Int64

// on sends one frame on conn and returns its answer.
func on(t *testing.T, conn *websocket.Conn, frameType string, payload any) wsapi.Frame {
	t.Helper()
	id := "r" + strconv.FormatInt(reqs.Add(1), 10)
	request(t, conn, id, frameType, payload)
	f, _ := replyTo(t, conn, id)
	return f
}

func refusedWith(t *testing.T, name string, f wsapi.Frame, message string) {
	t.Helper()
	if f.Type != wsapi.TypeError {
		t.Fatalf("%s: %s %s, want the refusal", name, f.Type, f.Payload)
	}
	e := payload[wsapi.Error](t, f)
	if e.Code != wsapi.ErrCodeNotAuthorized || e.Message != message {
		t.Fatalf("%s: %+v, want not_authorized %q", name, e, message)
	}
}

// passed reports that a frame got past the token's check: any answer but
// the token's two refusals.
func passed(t *testing.T, name string, f wsapi.Frame) {
	t.Helper()
	if f.Type == wsapi.TypeError {
		if e := payload[wsapi.Error](t, f); e.Message == tokenNumberRefused || e.Message == tokenFrameRefused {
			t.Fatalf("%s was refused: %+v", name, e)
		}
	}
}

// TestATokensHelloAndWelcome: a token's hello carries its text in api_key
// as it is; the welcome names no account, role or scope, and lists none of
// what a token is refused. A token beside a session, one in the session
// field, a garbled one and a revoked one are each the one refusal.
func TestATokensHelloAndWelcome(t *testing.T) {
	ts := newTokenSocket(t)
	w := ts.w
	tok := w.Token(tokentest.Read(w.Number("Vendas")))
	_, welcome := ts.hello(t, wsapi.Hello{APIKey: tok.Text})
	got := payload[wsapi.Welcome](t, welcome)
	if welcome.Type != wsapi.TypeWelcome || got.TenantID != w.Tenant.String() || got.Account != "" || got.Role != "" || got.Scope != "" {
		t.Fatalf("the welcome: %s %s", welcome.Type, welcome.Payload)
	}
	for _, f := range got.Features {
		if strings.HasPrefix(f, "pair") || strings.HasPrefix(f, "call") || f == "users.list" || f == "reproject.apply" {
			t.Errorf("a token's welcome lists %s", f)
		}
	}
	owner, err := w.Users.Get(context.Background(), w.Tenant, w.Owner)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := w.Users.StartSession(context.Background(), owner, "test")
	if err != nil {
		t.Fatal(err)
	}
	revoked := w.Token(tokentest.Read(w.Number("Suporte")))
	w.Revoke(revoked)
	for name, h := range map[string]wsapi.Hello{
		"beside a session":     {APIKey: tok.Text, Session: session},
		"in the session field": {Session: tok.Text},
		"garbled":              {APIKey: tok.Text[:40]},
		"upper case":           {APIKey: "THC_" + tok.Text[4:]},
		"revoked":              {APIKey: revoked.Text},
	} {
		_, f := ts.hello(t, h)
		e := wantError(t, f, wsapi.ErrCodeUnauthorized)
		if e.Message != "credential expired, revoked or invalid" || strings.Contains(e.Message, tok.Selector) {
			t.Errorf("%s: %+v", name, e)
		}
	}
}

// TestTokenFlagsAreIndependentPerNumber: read-only, send-only and
// manage-only tokens over two numbers. Each act needs its own perm on the
// number it names; a send-only token lists and reads nothing; a
// manage-only one renames, sets the mode, pauses and resumes with replies
// that carry only what it changed, and sends nothing; and every frame a
// token never sends is refused to all three: every kind of pairing (F1),
// calls, accounts, deletion, recovery, moving, reprojection, keys and
// grants.
func TestTokenFlagsAreIndependentPerNumber(t *testing.T) {
	ts := newTokenSocket(t)
	w := ts.w
	a, b := w.Number("Vendas"), w.Number("Suporte")
	reader := ts.open(t, w.Token(tokentest.Read(a)))
	sender := ts.open(t, w.Token(tokentest.Send(a)))
	managerTok := w.Token(tokentest.Manage(a))
	manager := ts.open(t, managerTok)
	ref := func(d uuid.UUID) wsapi.DeviceRef { return wsapi.DeviceRef{DeviceID: d.String()} }
	sendReq := map[string]any{"device_id": a.String(), "chat": "5511999999999@s.whatsapp.net", "text": "hi"}

	if f := on(t, reader, wsapi.TypeChatsList, ref(a)); f.Type != wsapi.TypeChats {
		t.Fatalf("a read: %s %s", f.Type, f.Payload)
	}
	refusedWith(t, "a read of the other number", on(t, reader, wsapi.TypeChatsList, ref(b)), tokenNumberRefused)
	refusedWith(t, "a reader's send", on(t, reader, wsapi.TypeSend, sendReq), tokenNumberRefused)
	refusedWith(t, "a reader's rename", on(t, reader, wsapi.TypeDeviceRename, map[string]string{"device_id": a.String(), "label": "x"}), tokenNumberRefused)

	refusedWith(t, "a sender's read", on(t, sender, wsapi.TypeChatsList, ref(a)), tokenNumberRefused)
	if devices := payload[wsapi.Devices](t, on(t, sender, wsapi.TypeDevicesList, nil)); len(devices.Devices) != 0 {
		t.Fatalf("a sender lists: %+v", devices)
	}
	refusedWith(t, "a sender's device.info", on(t, sender, wsapi.TypeDeviceInfo, ref(a)), tokenNumberRefused)
	passed(t, "a sender's send", on(t, sender, wsapi.TypeSend, sendReq))
	refusedWith(t, "a sender's group", on(t, sender, wsapi.TypeGroupCreate, map[string]any{"device_id": a.String(), "name": "g", "participants": []string{"5511988887777"}}), tokenNumberRefused)
	refusedWith(t, "a sender's stop", on(t, sender, wsapi.TypeDeviceStop, ref(a)), tokenNumberRefused)

	refusedWith(t, "a manager's send", on(t, manager, wsapi.TypeSend, sendReq), tokenNumberRefused)
	passed(t, "a manager's group", on(t, manager, wsapi.TypeGroupCreate, map[string]any{"device_id": a.String(), "name": "g", "participants": []string{"5511988887777"}}))
	passed(t, "a manager's backfill", on(t, manager, wsapi.TypeBackfill, map[string]any{"device_id": a.String(), "chat": "5511999999999@s.whatsapp.net"}))
	f := on(t, manager, wsapi.TypeDeviceRename, map[string]string{"device_id": a.String(), "label": "Novo"})
	if act := payload[wsapi.TokenAct](t, f); f.Type != wsapi.TypeDeviceDetail || !act.OK || act.DeviceID != a.String() || act.Label == nil || *act.Label != "Novo" ||
		strings.Contains(string(f.Payload), "receipt_mode") || strings.Contains(string(f.Payload), `"pn"`) {
		t.Fatalf("the rename's reply: %s %s", f.Type, f.Payload)
	}
	f = on(t, manager, wsapi.TypeDeviceMode, map[string]string{"device_id": a.String(), "receipt_mode": "active"})
	if act := payload[wsapi.TokenAct](t, f); f.Type != wsapi.TypeDeviceDetail || act.ReceiptMode == nil || *act.ReceiptMode != "active" || act.Label != nil {
		t.Fatalf("the mode's reply: %s %s", f.Type, f.Payload)
	}
	f = on(t, manager, wsapi.TypeDeviceStop, ref(a))
	if act := payload[wsapi.TokenAct](t, f); f.Type != wsapi.TypeDeviceStatus || act.Paused == nil || !*act.Paused || strings.Contains(string(f.Payload), "status") {
		t.Fatalf("the stop's reply: %s %s", f.Type, f.Payload)
	}
	dev, err := store.NewDevices(ts.pool).Get(context.Background(), w.Tenant.String(), a.String())
	if err != nil || !dev.Paused || dev.Label != "Novo" || dev.ReceiptMode != wa.ModeActive {
		t.Fatalf("the number after the manager's acts: %+v %v", dev, err)
	}
	passed(t, "a manager's start", on(t, manager, wsapi.TypeDeviceStart, ref(a)))
	refusedWith(t, "a manager's stop of the other number", on(t, manager, wsapi.TypeDeviceStop, ref(b)), tokenNumberRefused)

	for _, conn := range []*websocket.Conn{reader, sender, manager} {
		for kind, p := range map[string]any{
			wsapi.TypePair:         map[string]any{"device_id": uuid.NewString(), "method": "qr", "archive_public_key": make([]byte, 32), "orphan": true},
			"pair (a retry)":       map[string]any{"device_id": a.String(), "resume": true},
			"pair (a relink)":      map[string]any{"device_id": a.String(), "relink": true},
			wsapi.TypePairCancel:   ref(a),
			wsapi.TypeUsersList:    nil,
			wsapi.TypeCallsList:    ref(a),
			wsapi.TypeCallStart:    ref(a),
			wsapi.TypeDeviceDelete: ref(a), wsapi.TypeDeviceRecover: ref(a), wsapi.TypeDeviceTransfer: ref(a),
			wsapi.TypeReprojectGet: ref(a), wsapi.TypeReprojectPut: ref(a),
			wsapi.TypeGrantAdd: ref(a), wsapi.TypeGrantsList: nil, wsapi.TypeKeyCreate: map[string]string{"name": "x", "scope": "read"},
			wsapi.TypeKeysList: nil, wsapi.TypeReaderMode: ref(a), wsapi.TypeDeviceNoticeSeen: nil,
		} {
			frame := strings.Fields(kind)[0]
			refusedWith(t, kind, on(t, conn, frame, p), tokenFrameRefused)
		}
	}
	// An MCP draft needs a person.
	f = on(t, sender, wsapi.TypeSend, map[string]any{"device_id": a.String(), "chat": "5511999999999@s.whatsapp.net", "mcp_draft": uuid.NewString()})
	if f.Type != wsapi.TypeError {
		t.Fatalf("a token confirmed a draft: %s %s", f.Type, f.Payload)
	}
	// The stop was its creator's, by the token.
	var kind string
	var sub *uuid.UUID
	if err := ts.pool.QueryRow(context.Background(), `SELECT actor_kind, actor_sub FROM item_events WHERE item_id = $1 AND type = 'sync_paused'`, a).
		Scan(&kind, &sub); err == nil && (kind != "key" || sub == nil || *sub != w.OwnerSub) {
		t.Fatalf("the stop's actor: %s %v", kind, sub)
	}
}

// TestATokenLearnsNoNumberIdsOrExistenceOnTheSocket (F8): a prefix and an
// id in upper case are a bad request that names no number; a number it
// cannot read, one that does not exist, a deleted one and another
// workspace's get one answer, on every way a frame names a number; so do a
// message it cannot read and one that does not exist. Only the refusals on
// numbers of its workspace that exist are counted.
func TestATokenLearnsNoNumberIdsOrExistenceOnTheSocket(t *testing.T) {
	ts := newTokenSocket(t)
	w := ts.w
	a, refused := w.Number("Vendas"), w.Number("Suporte")
	gone := w.Number("Antigo")
	tok := w.Token(tokentest.Read(a), tokentest.Read(gone))
	w.Delete(gone)
	foreign := uuid.New()
	w.Exec(`INSERT INTO tenants (id, name) VALUES ($1, 'other')`, foreign)
	other, err := store.NewDevices(ts.pool).Create(context.Background(), foreign.String(), "Theirs", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	uid := uuid.New()
	if _, err := store.NewMessages(ts.pool).Insert(context.Background(), store.InsertMessage{UID: uid, TenantID: w.Tenant, DeviceID: refused,
		WAID: "wa-1", ChatKey: "5511999999999@s.whatsapp.net", TS: time.Now(), Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, BodySealed: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	conn := ts.open(t, tok)
	ids := []string{a.String(), refused.String(), gone.String(), other.ID}
	for name, id := range map[string]string{"refused": refused.String(), "missing": uuid.NewString(), "deleted": gone.String(), "another workspace's": other.ID} {
		for kind, p := range map[string]any{
			wsapi.TypeChatsList:  wsapi.DeviceRef{DeviceID: id},
			wsapi.TypeDeviceInfo: wsapi.DeviceRef{DeviceID: id},
			wsapi.TypeSubscribe:  wsapi.Subscribe{Devices: []string{id}, LiveOnly: true},
		} {
			refusedWith(t, name+" "+kind, on(t, conn, kind, p), tokenNumberRefused)
		}
	}
	for name, id := range map[string]string{"a prefix": a.String()[:8], "an ambiguous prefix": "0", "upper case": strings.ToUpper(a.String())} {
		for _, kind := range []string{wsapi.TypeChatsList, wsapi.TypeDeviceInfo} {
			f := on(t, conn, kind, wsapi.DeviceRef{DeviceID: id})
			e := wantError(t, f, wsapi.ErrCodeBadRequest)
			for _, known := range ids {
				if strings.Contains(e.Message, known) {
					t.Fatalf("%s %s names a number: %s", name, kind, e.Message)
				}
			}
		}
	}
	for name, p := range map[string]wsapi.MessageGetRequest{"refused": {UID: uid.String()}, "missing": {UID: uuid.NewString()}} {
		refusedWith(t, name+" message.get", on(t, conn, wsapi.TypeMessageGet, p), tokenNumberRefused)
		refusedWith(t, name+" message.history", on(t, conn, wsapi.TypeHistory, wsapi.HistoryRequest{UID: p.UID}), tokenNumberRefused)
	}
	if f := on(t, conn, wsapi.TypeDeviceInfo, wsapi.DeviceRef{DeviceID: a.String()}); f.Type != wsapi.TypeDeviceDetail ||
		payload[wsapi.DeviceDetail](t, f).Readers != nil || payload[wsapi.DeviceDetail](t, f).Tokens != nil {
		t.Fatalf("device.info of a readable number: %s %s", f.Type, f.Payload)
	}
	if err := ts.checker.Use.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := w.Refusals(tok); len(got) != 1 || got[refused.String()+"/read=no_permission"] != 5 {
		t.Fatalf("the refusals: %v", got)
	}
}

// TestANarrowingClosesTheTokensSocketsWithinASecond (the plan's 3.4): a
// narrowing that bumps the token's version, or ends it, closes its socket
// at once on the NOTIFY and by the second check without it; one that bumps
// none (a rotation, a switch, the workspace closed) leaves the socket open
// and stops what it carries: the subscription's frames of the number, and
// a reply read under it just before.
func TestANarrowingClosesTheTokensSocketsWithinASecond(t *testing.T) {
	ts := newTokenSocket(t)
	w := ts.w
	a, b := w.Number("Vendas"), w.Number("Suporte")
	closes := []struct {
		name   string
		narrow func(tok *tokentest.Token)
	}{
		{"a dropped perm", func(tok *tokentest.Token) { w.SetPerms(tok, tokentest.Read(b)) }},
		{"a revocation", func(tok *tokentest.Token) { w.Revoke(tok) }},
		{"an operator's stop", func(tok *tokentest.Token) {
			w.Exec(`INSERT INTO contract_token_stops (selector, cause, stopped_by) VALUES ($1, 'operator', 'test')`, tok.Selector)
		}},
		{"tokens off", func(*tokentest.Token) { w.Exec(`UPDATE contract_token_state SET mode = 'off'`) }},
	}
	for _, c := range closes {
		for _, notify := range []bool{true, false} {
			t.Run(c.name+map[bool]string{true: " with the NOTIFY", false: " by the tick"}[notify], func(t *testing.T) {
				w.Exec(`UPDATE contract_token_state SET mode = 'on', caught_up_at = coalesce(caught_up_at, clock_timestamp())`)
				tok := w.Token(tokentest.Read(a), tokentest.Read(b))
				conn := ts.open(t, tok)
				// Just after a tick, so only the NOTIFY can close it
				// before the next one.
				waitChecks(t, ts, 1)
				tick := time.Now()
				c.narrow(tok)
				if notify {
					ts.checker.Watch.Notify(tok.ID.String())
				}
				expectAccessClosed(t, conn)
				if limit := map[bool]time.Duration{true: 700 * time.Millisecond, false: 2500 * time.Millisecond}[notify]; time.Since(tick) > limit {
					t.Fatalf("closed %s after the tick", time.Since(tick))
				}
			})
		}
	}

	t.Run("what bumps no version", func(t *testing.T) {
		w.Exec(`UPDATE contract_token_state SET mode = 'on', caught_up_at = coalesce(caught_up_at, clock_timestamp())`)
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
		// A rotation leaves the token no grant at a's new epoch.
		w.Rotate(a, 2)
		ts.checker.Watch.Notify(tok.ID.String())
		waitChecks(t, ts, 2)
		presence(a)
		presence(b)
		if p := payload[wsapi.PresenceEvent](t, next(t, frames, wsapi.TypePresence)); p.DeviceID != b.String() {
			t.Fatalf("a's presence was carried after the rotation: %+v", p)
		}
		// A reply read under b, built just before the text switch goes off,
		// which bumps no version: the writer answers the refusal in its
		// place.
		ts.mu.Lock()
		ts.onReply = func() {
			off := false
			w.Switches(&off, nil)
		}
		ts.mu.Unlock()
		request(t, conn, "late", wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: b.String()})
		refusedWith(t, "a reply read under b before text went off", replyOn(t, frames, "late"), tokenNumberRefused)
		// The socket stays open: what bumps no version closes nothing.
		w.Switches(nil, nil)
		request(t, conn, "again", wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: b.String()})
		if f := replyOn(t, frames, "again"); f.Type != wsapi.TypeChats {
			t.Fatalf("text on again: %s %s", f.Type, f.Payload)
		}
		// The workspace closed: every act refused, the socket open.
		w.ExecIn(`INSERT INTO contract_workspaces (workspace_id, kind, status) VALUES ($1, 'team', 'closed')`, w.Tenant)
		request(t, conn, "closed", wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: b.String()})
		refusedWith(t, "a read in a closed workspace", replyOn(t, frames, "closed"), tokenNumberRefused)
	})
}

// replyOn is the frame answering reqID among a drained socket's frames.
func replyOn(t *testing.T, frames <-chan wsapi.Frame, reqID string) wsapi.Frame {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("the connection ended")
			}
			if f.ReqID == reqID && f.Type != wsapi.TypePresence && f.Type != wsapi.TypeMessage {
				return f
			}
		case <-timeout:
			t.Fatalf("no answer to %s", reqID)
		}
	}
}

// TestTokenSwitchesOnTheSocket (the plan's 3.5): with no MCP configured and
// no switch loaded, a workspace's own text switch off refuses every read
// and empties the listings; its attachments switch off refuses media.retry
// and media.expired and withholds the media rows of chat.page, message.get
// and the subscription's live frames, and leaves text rows alone.
func TestTokenSwitchesOnTheSocket(t *testing.T) {
	ts := newTokenSocket(t)
	w := ts.w
	a := w.Number("Vendas")
	tok := w.Token(tokentest.Read(a))
	insert := func(typ domain.Type) uuid.UUID {
		t.Helper()
		uid := uuid.New()
		in := store.InsertMessage{UID: uid, TenantID: w.Tenant, DeviceID: a, WAID: "wa-" + uid.String(), ChatKey: "5511999999999@s.whatsapp.net",
			TS: time.Now(), Kind: domain.KindMessage, Type: typ, Source: domain.SourceLive, BodySealed: []byte("caption"), PayloadSealed: []byte("payload")}
		if typ.HasMedia() {
			in.Media = &store.InsertMedia{MediaType: string(typ), MimeType: "image/jpeg", MediaKeySealed: []byte("key"), ThumbSealed: []byte("thumb"),
				FileNameSealed: []byte("name")}
		}
		if _, err := store.NewMessages(ts.pool).Insert(context.Background(), in); err != nil {
			t.Fatal(err)
		}
		return uid
	}
	image, text := insert(domain.TypeImage), insert(domain.TypeText)
	conn := ts.open(t, tok)
	frames := drain(conn)
	ask := func(reqID, kind string, p any) wsapi.Frame {
		t.Helper()
		request(t, conn, reqID, kind, p)
		return replyOn(t, frames, reqID)
	}
	withheld := func(name string, m wsapi.SealedMessage) {
		t.Helper()
		if m.BodySealed != nil || m.PayloadSealed != nil || m.Media == nil || m.Media.MediaKeySealed != nil || m.Media.ThumbSealed != nil ||
			m.Media.FileNameSealed != nil || m.Withheld != wsapi.WithheldAttachments || m.Media.MimeType != "image/jpeg" {
			t.Fatalf("%s is not withheld: %+v", name, m)
		}
	}
	off, on := false, true
	w.Switches(&off, nil)
	refusedWith(t, "text off", ask("t1", wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: a.String()}), tokenNumberRefused)
	if d := payload[wsapi.Devices](t, ask("t2", wsapi.TypeDevicesList, nil)); len(d.Devices) != 0 {
		t.Fatalf("text off lists: %+v", d)
	}
	w.Switches(&on, &off)
	request(t, conn, "sub", wsapi.TypeSubscribe, wsapi.Subscribe{LiveOnly: true})
	next(t, frames, wsapi.TypeReplayEnd)
	withheld("message.get", payload[wsapi.SealedMessage](t, ask("m1", wsapi.TypeMessageGet, wsapi.MessageGetRequest{UID: image.String()})))
	if m := payload[wsapi.SealedMessage](t, ask("m2", wsapi.TypeMessageGet, wsapi.MessageGetRequest{UID: text.String()})); m.BodySealed == nil || m.Withheld != "" {
		t.Fatalf("a text row: %+v", m)
	}
	page := payload[wsapi.Page](t, ask("p1", wsapi.TypeChatPage, map[string]any{"device_id": a.String(), "chat_key": "5511999999999@s.whatsapp.net", "limit": 10}))
	for _, m := range page.Messages {
		if m.Type == string(domain.TypeImage) {
			withheld("chat.page", m)
		}
	}
	refusedWith(t, "media.expired", ask("e1", wsapi.TypeMediaExpired, wsapi.ExpiredMediaRequest{DeviceID: a.String()}), tokenNumberRefused)
	// A live frame of a media row.
	live := insert(domain.TypeImage)
	ts.bus.Publish(w.Tenant, ingest.Event{Class: ingest.ClassMessage, TenantID: w.Tenant, DeviceID: a, UID: live, Seq: 1 << 40,
		Kind: domain.KindMessage, Type: domain.TypeImage})
	withheld("a live frame", payload[wsapi.SealedMessage](t, next(t, frames, wsapi.TypeMessage)))
	w.Switches(nil, nil)
	if f := ask("e2", wsapi.TypeMediaExpired, wsapi.ExpiredMediaRequest{DeviceID: a.String()}); f.Type != wsapi.TypeExpiredList {
		t.Fatalf("media.expired with attachments on: %s %s", f.Type, f.Payload)
	}
	if m := payload[wsapi.SealedMessage](t, ask("m3", wsapi.TypeMessageGet, wsapi.MessageGetRequest{UID: image.String()})); m.Media == nil || m.Media.MediaKeySealed == nil {
		t.Fatalf("attachments on: %+v", m)
	}
}

// TestATokensNotifyCrossesProcesses: two servers, each with its own pool,
// TokenWatch and ListenTokens, as two processes of one database: a
// revocation committed through one closes the token's socket on the other
// at its NOTIFY, before that server's next tick.
func TestATokensNotifyCrossesProcesses(t *testing.T) {
	ts := newTokenSocket(t)
	w := ts.w
	a := w.Number("Vendas")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	other, err := pgxpool.NewWithConfig(ctx, ts.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	watch := access.NewTokenWatch()
	listening := make(chan struct{})
	go func() { _ = access.ListenTokens(ctx, other, watch, func() { close(listening) }) }()
	<-listening
	users := store.NewUsers(other)
	var checks atomic.Int64
	cfg := wsapi.Config{Keys: store.NewAPIKeys(other), Sessions: users, Accounts: users, Devices: store.NewDevices(other),
		Messages: store.NewMessages(other), Keys2: store.NewKeys(other), Bus: bus.New(), Log: slog.New(slog.DiscardHandler),
		Access: &access.Checker{Tokens: store.NewTokens(other), Switches: store.TokenSwitches{Default: true}, Watch: watch}}
	wsapi.SetTokenHook(&cfg, func(stage string) {
		if stage == "checked" {
			checks.Add(1)
		}
	})
	srv := httptest.NewServer(wsapi.NewServer(cfg))
	defer srv.Close()
	tok := w.Token(tokentest.Read(a))
	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: tok.Text, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("the hello on the other server: %s %s", f.Type, f.Payload)
	}
	target := checks.Load() + 1
	for checks.Load() < target {
		time.Sleep(5 * time.Millisecond)
	}
	tick := time.Now()
	w.Revoke(tok)
	expectAccessClosed(t, conn)
	if time.Since(tick) > 700*time.Millisecond {
		t.Fatalf("the other process closed it %s after its tick", time.Since(tick))
	}
}

// waitChecks waits for n more checks of the token sessions' sets.
func waitChecks(t *testing.T, ts *tokenSocket, n int64) {
	t.Helper()
	target := ts.checks.Load() + n
	deadline := time.Now().Add(5 * time.Second)
	for ts.checks.Load() < target {
		if time.Now().After(deadline) {
			t.Fatal("the sets were not checked again")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// refusingFreshness refuses every act it is asked about.
type refusingFreshness struct{ asked atomic.Int64 }

func (r *refusingFreshness) RequireFresh(context.Context, string, uuid.UUID, ...membership.Party) (membership.Verdict, error) {
	r.asked.Add(1)
	return membership.Verdict{}, membership.ErrMembershipsUnconfirmed
}

func (r *refusingFreshness) RequireWidening(context.Context, string, uuid.UUID, ...membership.Party) (membership.Verdict, error) {
	r.asked.Add(1)
	return membership.Verdict{}, membership.ErrMembershipsUnconfirmed
}

func (r *refusingFreshness) RequireBackups(context.Context, string, uuid.UUID, uuid.UUID, uuid.UUID) (membership.Verdict, error) {
	r.asked.Add(1)
	return membership.Verdict{}, membership.ErrMembershipsUnconfirmed
}

func (r *refusingFreshness) RequireMover(context.Context, uuid.UUID, uuid.UUID) (membership.Verdict, error) {
	r.asked.Add(1)
	return membership.Verdict{}, membership.ErrMembershipsUnconfirmed
}

// TestMembershipFreshnessNeverGatesATokensAct (F14): a freshness hook
// that refuses every act changes nothing for a token's pause and resume.
func TestMembershipFreshnessNeverGatesATokensAct(t *testing.T) {
	fresh := &refusingFreshness{}
	ts := newTokenSocket(t, func(cfg *wsapi.Config) { cfg.Membership = fresh })
	w := ts.w
	a := w.Number("Vendas")
	conn := ts.open(t, w.Token(tokentest.Manage(a), tokentest.Send(a)))
	if f := on(t, conn, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: a.String()}); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("a token's stop: %s %s", f.Type, f.Payload)
	}
	passed(t, "a token's send", on(t, conn, wsapi.TypeSend, map[string]any{"device_id": a.String(), "chat": "5511999999999@s.whatsapp.net", "text": "hi"}))
	if n := fresh.asked.Load(); n != 0 {
		t.Fatalf("the freshness hook was asked %d times about a token", n)
	}
}

// TestEveryTokenVectorOnTheHello: every kit token authenticates as its own
// record, the two that share a secret included; every refused text in
// api_key gets the token's refusal when it holds thc_ in some case, and
// today's answer otherwise.
func TestEveryTokenVectorOnTheHello(t *testing.T) {
	ts := newTokenSocket(t)
	w := ts.w
	raw, err := fs.ReadFile(vectors.FS, "platform/contract-v1/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Tokens []struct {
			Name, Token, Selector, Hash string
		} `json:"tokens"`
		Refused []struct {
			Name, Token string
		} `json:"refused"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	device := w.Number("Vendas")
	for _, k := range v.Tokens {
		tok := w.TokenWith(k.Token, k.Selector, k.Hash, tokentest.Read(device))
		conn := ts.open(t, tok)
		if f := on(t, conn, wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: device.String()}); f.Type != wsapi.TypeChats {
			t.Errorf("%s: %s %s", k.Name, f.Type, f.Payload)
		}
	}
	for _, c := range v.Refused {
		if c.Token == "" {
			continue // an empty api_key is no credential at all
		}
		_, f := ts.hello(t, wsapi.Hello{APIKey: c.Token})
		e := wantError(t, f, wsapi.ErrCodeUnauthorized)
		want := "credential expired, revoked or invalid"
		if !strings.Contains(strings.ToLower(c.Token), "thc_") {
			want = "invalid api key"
		}
		if e.Message != want {
			t.Errorf("refused %q: %q, want %q", c.Name, e.Message, want)
		}
	}
}
