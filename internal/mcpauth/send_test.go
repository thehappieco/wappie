package mcpauth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/domain"
	"whatserver2/internal/mcpauth"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Sending over HTTP (docs/mcp-enclave.md §17.3, §17.7): the consent, the
// reader's status, the reader's draft, send, refusal and ledger routes, and
// the console's. The ledger is real Postgres under an ordinary role; the
// enclave is the fake on the far side of the signed relay, and WhatsApp is a
// fake SendText.

const (
	friend  = "5511911111111@s.whatsapp.net"
	quiet   = "5511922222222@s.whatsapp.net"
	group   = "120363000000000001@g.us"
	ownChat = "5511900000000@s.whatsapp.net"
)

// fakeSender stands in for the socket's text send.
type fakeSender struct {
	mu    sync.Mutex
	calls []mcpauth.OutboundText
	// err, archived and hold shape the next answers.
	err      error
	archived bool
	hold     chan struct{}
}

func (f *fakeSender) send(ctx context.Context, in mcpauth.OutboundText) (mcpauth.OutboundSent, error) {
	f.mu.Lock()
	f.calls = append(f.calls, in)
	err, archived, hold := f.err, f.archived, f.hold
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if err != nil {
		return mcpauth.OutboundSent{}, err
	}
	out := mcpauth.OutboundSent{WAID: "3EB0" + strings.ToUpper(uuid.NewString()[:8]), Timestamp: time.Now()}
	if archived {
		uid := uuid.New()
		out.MessageUID = &uid
	}
	return out, nil
}

func (f *fakeSender) sent() []mcpauth.OutboundText {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mcpauth.OutboundText(nil), f.calls...)
}

func (f *fakeSender) set(err error, archived bool) {
	f.mu.Lock()
	f.err, f.archived = err, archived
	f.mu.Unlock()
}

type sendHarness struct {
	*attestedHarness
	sendOn, selfOn atomic.Bool
	sender         *fakeSender
	ownerToken     string
}

// newSendHarness is the attested harness with content on, sending's
// switches wired to its own flags (on, the own chat on), a fake sender, and
// a number with chats: one the other side wrote in, one it did not, a group
// and the number's own.
func newSendHarness(t *testing.T) *sendHarness {
	t.Helper()
	ctx := context.Background()
	h := &sendHarness{attestedHarness: newAttestedHarness(t), sender: &fakeSender{archived: true}}
	h.contentOn.Store(true)
	h.sendOn.Store(true)
	h.selfOn.Store(true)
	h.handler.SendAllowed = func(tenant uuid.UUID) bool { return h.sendOn.Load() && tenant == h.tenant }
	h.handler.SendSelfAllowed = func(tenant uuid.UUID) bool { return h.selfOn.Load() && tenant == h.tenant }
	h.handler.SendDirectAllowed = func(uuid.UUID) bool { return false }
	h.handler.SendText = h.sender.send
	h.handler.SendLimits = store.SendLimits{MinInterval: time.Microsecond}
	h.ownerToken = h.session(t, h.owner)
	h.archiveKey(t)
	pn, _ := types.ParseJID("5511900000000:3@s.whatsapp.net")
	if err := store.NewDevices(h.pool).SetIdentity(ctx, h.tenant.String(), h.device.String(), wa.Identity{PN: pn}); err != nil {
		t.Fatal(err)
	}
	if err := h.users.SetDevicePermission(ctx, h.tenant, h.owner.ID, store.DevicePermission{DeviceID: h.device, UserID: h.owner.ID, Read: true, Send: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(h.pool).PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: h.device, UserID: h.owner.ID, Epoch: 1, SealedDSK: []byte("the owner's")}, &h.owner.ID); err != nil {
		t.Fatal(err)
	}
	h.message(t, friend, false, false)
	h.message(t, quiet, false, true)
	h.message(t, group, true, false)
	h.message(t, ownChat, false, true)
	return h
}

func (h *sendHarness) message(t *testing.T, chat string, isGroup, fromMe bool) uuid.UUID {
	t.Helper()
	uid := uuid.New()
	if _, err := store.NewMessages(h.pool).Insert(context.Background(), store.InsertMessage{
		UID: uid, TenantID: h.tenant, DeviceID: h.device, WAID: "wa-" + uid.String(), ChatKey: chat, IsGroup: isGroup,
		IsFromMe: fromMe, Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1},
	}); err != nil {
		t.Fatal(err)
	}
	return uid
}

// sendBody is a version-3 content consent with drafts and, as asked, the
// own chat.
func sendBody(t *testing.T, requestID, prefix string, service uuid.UUID, self bool) map[string]any {
	t.Helper()
	body := contentBody(t, requestID, prefix, service)
	body["consent_version"] = 3
	body["send"] = "draft"
	if self {
		body["send_self"] = true
	}
	return body
}

// sending is a live connection that drafts and, as asked, sends to its own
// chat: its id, its key, and the request it answered.
type sending struct {
	id, key, request string
}

func (h *sendHarness) consentSending(t *testing.T, token string, extra map[string]any) sending {
	t.Helper()
	requestID, service, key, prefix := h.prepareContent(t, h.owner.ID)
	body := sendBody(t, requestID, prefix, service, true)
	for k, v := range extra {
		body[k] = v
	}
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(token))
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID string `json:"id"`
	}
	r.into(t, &created)
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	return sending{id: created.ID, key: key, request: requestID}
}

// asConnection calls a reader's route for a connection: signed as the
// enclave, and with the connection's key as the bearer.
func (h *sendHarness) asConnection(t *testing.T, method, target, key string, body any) reply {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	s := asEnclave(t)
	s.body = raw
	req, err := http.NewRequest(method, h.srv.URL+target, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if raw == nil {
		req.Body = http.NoBody
	}
	ts := strconv.FormatInt(s.at.Unix(), 10)
	req.Header.Set(mcpauth.HeaderReader, s.reader)
	req.Header.Set(mcpauth.HeaderTimestamp, ts)
	req.Header.Set(mcpauth.HeaderNonce, s.nonce)
	req.Header.Set(mcpauth.HeaderSignature, mcpauth.Signature(s.secret, s.direction, s.reader, method, target, ts, s.nonce, raw))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent && resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("%s %s: missing Cache-Control: no-store", method, target)
	}
	return reply{status: resp.StatusCode, body: out}
}

func draftBody(chat string) map[string]any {
	return map[string]any{
		"id": uuid.NewString(), "device_id": "", "chat_key": chat, "epoch": 1,
		"sealed": base64.RawURLEncoding.EncodeToString([]byte("a sealed draft")),
	}
}

func (h *sendHarness) draft(t *testing.T, c sending, chat string, mutate func(map[string]any)) reply {
	t.Helper()
	body := draftBody(chat)
	body["device_id"] = h.device.String()
	if mutate != nil {
		mutate(body)
	}
	return h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+c.id+"/drafts", c.key, body)
}

// clientRef is a send's reference as the reader draws it: 16 random bytes.
func clientRef() string {
	id := uuid.New()
	return base64.RawURLEncoding.EncodeToString(id[:])
}

func (h *sendHarness) selfSend(t *testing.T, c sending, ref, text string) reply {
	t.Helper()
	return h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+c.id+"/send", c.key,
		map[string]any{"client_ref": ref, "kind": "self", "device_id": h.device.String(), "text": text})
}

// ledger reads the connection's ledger in its workspace's transaction:
// status and code, oldest first.
func (h *sendHarness) ledger(t *testing.T, connection string) [][2]string {
	t.Helper()
	var out [][2]string
	if err := pg.InTenantTx(context.Background(), h.pool, h.tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT status, coalesce(code, '') FROM mcp_outbound WHERE connection_id=$1 ORDER BY created_at, id`, connection)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row [2]string
			if err := rows.Scan(&row[0], &row[1]); err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// ---------------------------------------------------------------------------

// A consent asks for sending on version 3 only, in the contract's order, and
// is refused with send_not_allowed before the ledger and the reader while
// the switches say no. The relay carries what was consented, and the list
// shows it.
func TestSendConsent(t *testing.T) {
	h := newSendHarness(t)
	ctx := context.Background()
	requestID, service, _, prefix := h.prepareContent(t, h.owner.ID)
	for name, tc := range map[string]struct {
		mutate func(map[string]any)
		msg    string
	}{
		"metadata with send": {func(b map[string]any) {
			for _, k := range []string{"kind", "service_user_id", "key_mode", "consent_version", "send_self"} {
				delete(b, k)
			}
		}, "for a content connection only"},
		"own chat without send":  {func(b map[string]any) { delete(b, "send") }, "need send"},
		"groups without send":    {func(b map[string]any) { delete(b, "send"); delete(b, "send_self"); b["send_groups"] = true }, "need send"},
		"version 4 to 0.5.0":     {func(b map[string]any) { b["consent_version"] = 4 }, "consent_version 4 are for a reader that describes its client"},
		"version 5":              {func(b map[string]any) { b["consent_version"] = 5 }, "consent_version must be 1, 2, 3 or 4"},
		"version 3 without send": {func(b map[string]any) { delete(b, "send"); delete(b, "send_self") }, "consent version 3 carries sending"},
		"send on version 2":      {func(b map[string]any) { b["consent_version"] = 2 }, "consent version 3 carries sending"},
		"media on version 1": {func(b map[string]any) {
			b["consent_version"], b["media"] = 1, true
			delete(b, "send")
			delete(b, "send_self")
		}, "media requires consent_version 2 or later"},
		"direct before S3":         {func(b map[string]any) { b["send"] = "direct" }, "not available yet"},
		"send_chats":               {func(b map[string]any) { b["send_chats"] = []any{} }, "not available yet"},
		"not a mode":               {func(b map[string]any) { b["send"] = "now" }, "send must be draft"},
		"send_self not a boolean":  {func(b map[string]any) { b["send_self"] = "yes" }, "malformed request"},
		"send not a string at all": {func(b map[string]any) { b["send"] = true }, "malformed request"},
	} {
		t.Run(name, func(t *testing.T) {
			body := sendBody(t, requestID, prefix, service, true)
			tc.mutate(body)
			r := h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.ownerToken))
			expect(t, r, http.StatusBadRequest, "bad_request")
			if !strings.Contains(string(r.body), tc.msg) {
				t.Fatalf("message = %s", r.body)
			}
		})
	}
	// The switches: sending off, then the own chat off. Refused before the
	// ledger and before the reader, and after the content gate.
	h.sendOn.Store(false)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", sendBody(t, requestID, prefix, service, false), bearer(h.ownerToken)), http.StatusForbidden, "send_not_allowed")
	h.contentOn.Store(false)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", sendBody(t, requestID, prefix, service, false), bearer(h.ownerToken)), http.StatusForbidden, "content_not_allowed")
	h.contentOn.Store(true)
	h.sendOn.Store(true)
	h.selfOn.Store(false)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", sendBody(t, requestID, prefix, service, true), bearer(h.ownerToken)), http.StatusForbidden, "send_not_allowed")
	if rows, err := h.conns.List(ctx, h.tenant); err != nil || len(rows) != 0 {
		t.Fatalf("a refused consent left rows: %+v %v", rows, err)
	}
	if h.enclave.bundle(requestID) != nil {
		t.Fatal("a refused consent reached the enclave")
	}
	// Drafts alone pass with the own chat off; the relay says send and
	// nothing it was not asked.
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", sendBody(t, requestID, prefix, service, false), bearer(h.ownerToken))
	expect(t, r, http.StatusCreated, "")
	if got := fieldNames(h.enclave.bundle(requestID)); got != "connection_id,expires_at,kid,kind,sealed,send,tenant_id" || h.enclave.bundle(requestID)["send"] != "draft" {
		t.Fatalf("relay = %v", h.enclave.bundle(requestID))
	}
	h.selfOn.Store(true)
	h.mediaOn.Store(true)
	all := h.consentSending(t, h.ownerToken, map[string]any{"send_groups": true, "media": true})
	bundle := h.enclave.bundle(all.request)
	if got := fieldNames(bundle); got != "connection_id,expires_at,kid,kind,media,sealed,send,send_groups,send_self,tenant_id" ||
		bundle["send_self"] != true || bundle["send_groups"] != true {
		t.Fatalf("relay = %v", bundle)
	}
	// Version 1 and 2 relays carry no sending field at all.
	v1ID, _, _ := h.consentContent(t, h.owner)
	if got := fieldNames(h.enclave.bundle(h.requestOf(t, v1ID))); got != relayFields {
		t.Fatalf("version-1 relay fields = %s", got)
	}

	// The list: the consent's sending, whatever the switches say.
	r = h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(h.ownerToken))
	expect(t, r, http.StatusOK, "")
	var listed struct {
		Connections []struct {
			ID         string  `json:"id"`
			Version    *int    `json:"consent_version"`
			SendMode   *string `json:"send_mode"`
			SendSelf   *bool   `json:"send_self"`
			SendGroups *bool   `json:"send_groups"`
			SendPaused *bool   `json:"send_paused"`
			SendChats  *int    `json:"send_chats"`
		} `json:"connections"`
	}
	r.into(t, &listed)
	seen := 0
	for _, c := range listed.Connections {
		if c.SendMode == nil && c.SendSelf != nil && !*c.SendSelf && c.SendPaused != nil && c.SendChats != nil && *c.SendChats == 0 && c.ID == v1ID {
			seen++
		}
		if c.ID == all.id {
			if *c.Version != 3 || *c.SendMode != "draft" || !*c.SendSelf || !*c.SendGroups || *c.SendPaused || *c.SendChats != 0 {
				t.Fatalf("listed = %s", r.body)
			}
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("list = %s", r.body)
	}
}

// GET /v1/mcp/content answers the three send toggles' conditions for the
// session's workspace.
func TestContentReplySend(t *testing.T) {
	h := newSendHarness(t)
	answer := func() (send, self, direct bool) {
		t.Helper()
		r := h.call(t, http.MethodGet, "/v1/mcp/content", nil, bearer(h.ownerToken))
		expect(t, r, http.StatusOK, "")
		var out struct {
			Send       *bool `json:"send"`
			SendSelf   *bool `json:"send_self"`
			SendDirect *bool `json:"send_direct"`
		}
		r.into(t, &out)
		if out.Send == nil || out.SendSelf == nil || out.SendDirect == nil {
			t.Fatalf("content reply = %s", r.body)
		}
		return *out.Send, *out.SendSelf, *out.SendDirect
	}
	if s, self, direct := answer(); !s || !self || direct {
		t.Fatalf("on = %v %v %v", s, self, direct)
	}
	h.selfOn.Store(false)
	if s, self, _ := answer(); !s || self {
		t.Fatalf("own chat off = %v %v", s, self)
	}
	h.selfOn.Store(true)
	h.contentOn.Store(false)
	if s, self, _ := answer(); s || self {
		t.Fatalf("content off = %v %v", s, self)
	}
}

// The reader's status says how a connection may send right now: the row,
// the switches and the pause, and only on an active answer. Sending never
// makes an answer reseal.
func TestStatusSend(t *testing.T) {
	h := newSendHarness(t)
	c := h.consentSending(t, h.ownerToken, nil)
	standing := func() (status string, send *string, self bool) {
		t.Helper()
		r, _ := h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/connections/"+c.id, asEnclave(t))
		expect(t, r, http.StatusOK, "")
		var s struct {
			Status   string          `json:"status"`
			Send     json.RawMessage `json:"send"`
			SendSelf *bool           `json:"send_self"`
		}
		r.into(t, &s)
		if s.Send == nil || s.SendSelf == nil {
			t.Fatalf("status without send or send_self: %s", r.body)
		}
		if string(s.Send) != "null" {
			var mode string
			if err := json.Unmarshal(s.Send, &mode); err != nil {
				t.Fatal(err)
			}
			send = &mode
		}
		return s.Status, send, *s.SendSelf
	}
	is := func(t *testing.T, wantStatus, wantSend string, wantSelf bool) {
		t.Helper()
		status, send, self := standing()
		got := ""
		if send != nil {
			got = *send
		}
		if status != wantStatus || got != wantSend || self != wantSelf {
			t.Fatalf("status = %s %q %v, want %s %q %v", status, got, self, wantStatus, wantSend, wantSelf)
		}
	}
	is(t, "active", "draft", true)
	h.selfOn.Store(false)
	is(t, "active", "draft", false)
	h.sendOn.Store(false)
	is(t, "active", "", false)
	h.sendOn.Store(true)
	h.selfOn.Store(true)
	expect(t, h.call(t, http.MethodPatch, "/v1/mcp/connections/"+c.id+"/send", map[string]any{"paused": true}, bearer(h.ownerToken)), http.StatusOK, "")
	is(t, "active", "", false)
	expect(t, h.call(t, http.MethodPatch, "/v1/mcp/connections/"+c.id+"/send", map[string]any{"paused": false}, bearer(h.ownerToken)), http.StatusOK, "")
	is(t, "active", "draft", true)
	h.contentOn.Store(false)
	is(t, "reseal", "", false)
	h.contentOn.Store(true)
	// A connection without sending answers null and false, as metadata does.
	text, _, _ := h.consentContent(t, h.owner)
	c.id = text
	is(t, "active", "", false)
}

// The draft route, in the contract's order: the connection is the caller's
// and the bearer its key; the body; the switches, the connection and the
// person; the chat; the limits. Every refusal after the body is written to
// the ledger.
func TestDraftRoute(t *testing.T) {
	h := newSendHarness(t)
	c := h.consentSending(t, h.ownerToken, nil)
	other := h.consentSending(t, h.ownerToken, nil)

	// The bearer: none, another connection's, or a person's session.
	expect(t, h.draft(t, sending{id: c.id}, friend, nil), http.StatusNotFound, "not_found")
	expect(t, h.draft(t, sending{id: c.id, key: other.key}, friend, nil), http.StatusNotFound, "not_found")
	expect(t, h.draft(t, sending{id: c.id, key: h.ownerToken}, friend, nil), http.StatusNotFound, "not_found")
	expect(t, h.draft(t, sending{id: uuid.NewString(), key: c.key}, friend, nil), http.StatusNotFound, "not_found")
	// The body.
	for name, mutate := range map[string]func(map[string]any){
		"an upper-case id":   func(b map[string]any) { b["id"] = strings.ToUpper(b["id"].(string)) },
		"a chat with spaces": func(b map[string]any) { b["chat_key"] = "a b" },
		"a long chat":        func(b map[string]any) { b["chat_key"] = strings.Repeat("9", 129) },
		"epoch zero":         func(b map[string]any) { b["epoch"] = 0 },
		"padded base64":      func(b map[string]any) { b["sealed"] = base64.URLEncoding.EncodeToString([]byte("a sealed draft")) },
		"too large":          func(b map[string]any) { b["sealed"] = base64.RawURLEncoding.EncodeToString(make([]byte, 16385)) },
		"an unknown field":   func(b map[string]any) { b["text"] = "never" },
		"a bad reply":        func(b map[string]any) { b["reply_to_uid"] = "nope" },
	} {
		t.Run(name, func(t *testing.T) {
			expect(t, h.draft(t, c, friend, mutate), http.StatusBadRequest, "bad_request")
		})
	}
	if rows := h.ledger(t, c.id); len(rows) != 0 {
		t.Fatalf("a malformed draft was recorded: %v", rows)
	}

	r := h.draft(t, c, friend, nil)
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	r.into(t, &created)
	if created.ExpiresAt.Sub(time.Now().Add(24*time.Hour)).Abs() > time.Minute || !strings.HasSuffix(string(r.body), "Z\"}\n") {
		t.Fatalf("created = %s", r.body)
	}
	expect(t, h.draft(t, c, friend, func(b map[string]any) { b["id"] = created.ID }), http.StatusConflict, "draft_exists")
	reply := h.message(t, friend, false, false).String()
	expect(t, h.draft(t, c, friend, func(b map[string]any) { b["reply_to_uid"] = reply }), http.StatusCreated, "")

	expect(t, h.draft(t, c, quiet, nil), http.StatusUnprocessableEntity, "chat_not_eligible")
	expect(t, h.draft(t, c, group, nil), http.StatusUnprocessableEntity, "group_not_allowed")
	expect(t, h.draft(t, c, friend, func(b map[string]any) { b["reply_to_uid"] = uuid.NewString() }), http.StatusUnprocessableEntity, "reply_not_found")
	h.sendOn.Store(false)
	expect(t, h.draft(t, c, friend, nil), http.StatusForbidden, "send_not_allowed")
	h.sendOn.Store(true)
	h.handler.SendLimits.DraftsPending = 2
	r = h.draft(t, c, friend, nil)
	expect(t, r, http.StatusTooManyRequests, "rate_limited")
	var limited struct {
		RetryAt time.Time `json:"retry_at"`
	}
	r.into(t, &limited)
	if limited.RetryAt.Sub(time.Now().Add(24*time.Hour)).Abs() > time.Minute {
		t.Fatalf("retry_at = %s", r.body)
	}
	h.handler.SendLimits.DraftsPending = 0
	// The person who consented loses send on the number.
	if err := h.users.SetDevicePermission(context.Background(), h.tenant, h.owner.ID, store.DevicePermission{DeviceID: h.device, UserID: h.owner.ID, Read: true}); err != nil {
		t.Fatal(err)
	}
	expect(t, h.draft(t, c, friend, nil), http.StatusForbidden, "send_not_allowed")

	want := [][2]string{{"pending", ""}, {"pending", ""}, {"refused", "chat_not_eligible"}, {"refused", "group_not_allowed"},
		{"refused", "reply_not_found"}, {"refused", "send_not_allowed"}, {"refused", "rate_limited"}, {"refused", "send_not_allowed"}}
	if got := h.ledger(t, c.id); !equalRows(got, want) {
		t.Fatalf("ledger = %v", got)
	}
	// A paused or revoked connection.
	if err := h.users.SetDevicePermission(context.Background(), h.tenant, h.owner.ID, store.DevicePermission{DeviceID: h.device, UserID: h.owner.ID, Read: true, Send: true}); err != nil {
		t.Fatal(err)
	}
	expect(t, h.call(t, http.MethodPatch, "/v1/mcp/connections/"+other.id+"/send", map[string]any{"paused": true}, bearer(h.ownerToken)), http.StatusOK, "")
	expect(t, h.draft(t, other, friend, nil), http.StatusForbidden, "send_not_allowed")
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+other.id, nil, bearer(h.ownerToken)), http.StatusNoContent, "")
	expect(t, h.draft(t, other, friend, nil), http.StatusNotFound, "not_found")
}

func equalRows(a, b [][2]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The send route: an own-chat note, sent through the socket's send to the
// number's own chat and never anywhere the reader names, recorded before it
// leaves and answered from the record when asked again.
func TestSendRoute(t *testing.T) {
	h := newSendHarness(t)
	c := h.consentSending(t, h.ownerToken, nil)
	ref := clientRef()
	r := h.selfSend(t, c, ref, "lembrar: pagar a conta\r\namanhã")
	expect(t, r, http.StatusOK, "")
	var sent struct {
		ID         string  `json:"id"`
		MessageUID *string `json:"message_uid"`
		WAID       string  `json:"wa_id"`
		Timestamp  string  `json:"timestamp"`
		Duplicate  bool    `json:"duplicate"`
	}
	r.into(t, &sent)
	if sent.MessageUID == nil || sent.WAID == "" || sent.Duplicate || !strings.HasSuffix(sent.Timestamp, "Z") {
		t.Fatalf("sent = %s", r.body)
	}
	calls := h.sender.sent()
	if len(calls) != 1 || calls[0].Chat != ownChat || calls[0].Body != "lembrar: pagar a conta\namanhã" || calls[0].Device != h.device || calls[0].Tenant != h.tenant {
		t.Fatalf("sender = %+v", calls)
	}
	// The same reference: the record, and no second message.
	r = h.selfSend(t, c, ref, "lembrar: pagar a conta\r\namanhã")
	expect(t, r, http.StatusOK, "")
	var again struct {
		ID         string  `json:"id"`
		MessageUID *string `json:"message_uid"`
		Duplicate  bool    `json:"duplicate"`
	}
	r.into(t, &again)
	if again.ID != sent.ID || again.MessageUID == nil || *again.MessageUID != *sent.MessageUID || !again.Duplicate || len(h.sender.sent()) != 1 {
		t.Fatalf("again = %s, %d sends", r.body, len(h.sender.sent()))
	}

	// What the rules refuse never reaches the sender, and is recorded.
	for _, text := range []string{"veja https://exemplo.com", "abc\u202edef", strings.Repeat("a", 1001), "   "} {
		expect(t, h.selfSend(t, c, clientRef(), text), http.StatusUnprocessableEntity, "text_not_allowed")
	}
	lone := h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+c.id+"/send", c.key,
		json.RawMessage(`{"client_ref":"`+clientRef()+`","kind":"self","device_id":"`+h.device.String()+`","text":"a\ud800b"}`))
	expect(t, lone, http.StatusUnprocessableEntity, "text_not_allowed")
	// The body: a chat for an own-chat send, and direct send before S3.
	expect(t, h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+c.id+"/send", c.key,
		map[string]any{"client_ref": clientRef(), "kind": "self", "device_id": h.device.String(), "text": "x", "chat_key": friend}), http.StatusBadRequest, "bad_request")
	expect(t, h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+c.id+"/send", c.key,
		map[string]any{"client_ref": "short", "kind": "self", "device_id": h.device.String(), "text": "x"}), http.StatusBadRequest, "bad_request")
	for _, text := range []any{nil, 7, []string{"x"}} {
		expect(t, h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+c.id+"/send", c.key,
			map[string]any{"client_ref": clientRef(), "kind": "self", "device_id": h.device.String(), "text": text}), http.StatusBadRequest, "bad_request")
	}
	expect(t, h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+c.id+"/send", c.key,
		map[string]any{"client_ref": clientRef(), "kind": "send", "device_id": h.device.String(), "text": "x", "chat_key": friend}), http.StatusForbidden, "send_not_allowed")
	if len(h.sender.sent()) != 1 {
		t.Fatalf("a refused send reached the sender: %+v", h.sender.sent())
	}

	// Archiving failed: sent all the same, with no uid.
	h.sender.set(nil, false)
	r = h.selfSend(t, c, clientRef(), "sem arquivo")
	expect(t, r, http.StatusOK, "")
	if !strings.Contains(string(r.body), `"message_uid":null`) {
		t.Fatalf("unarchived = %s", r.body)
	}
	// A transport error: uncertain, never repeated, the record answering.
	h.sender.set(errors.New("websocket closed mid-send"), true)
	uncertain := clientRef()
	expect(t, h.selfSend(t, c, uncertain, "talvez"), http.StatusBadGateway, "send_uncertain")
	h.sender.set(nil, true)
	r = h.selfSend(t, c, uncertain, "talvez")
	expect(t, r, http.StatusBadGateway, "send_uncertain")
	if !strings.Contains(string(r.body), `"duplicate":true`) {
		t.Fatalf("replayed uncertain = %s", r.body)
	}
	// The number is not connected: refused, nothing sent, the same answer
	// again.
	h.sender.set(mcpauth.ErrDeviceOffline, true)
	offline := clientRef()
	expect(t, h.selfSend(t, c, offline, "desligado"), http.StatusConflict, "device_offline")
	h.sender.set(nil, true)
	expect(t, h.selfSend(t, c, offline, "desligado"), http.StatusConflict, "device_offline")
	h.sender.set(mcpauth.ErrStoragePaused, true)
	expect(t, h.selfSend(t, c, clientRef(), "pausado"), http.StatusConflict, "storage_paused")
	h.sender.set(nil, true)

	// In flight: the same reference waits for nothing and sends nothing.
	hold := make(chan struct{})
	h.sender.mu.Lock()
	h.sender.hold = hold
	h.sender.mu.Unlock()
	inFlight := clientRef()
	done := make(chan reply)
	before := len(h.sender.sent())
	go func() { done <- h.selfSend(t, c, inFlight, "devagar") }()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.sender.sent()) == before {
		if time.Now().After(deadline) {
			t.Fatal("the send never reached the sender")
		}
		time.Sleep(10 * time.Millisecond)
	}
	expect(t, h.selfSend(t, c, inFlight, "devagar"), http.StatusConflict, "send_in_progress")
	h.sender.mu.Lock()
	h.sender.hold = nil
	h.sender.mu.Unlock()
	close(hold)
	expect(t, <-done, http.StatusOK, "")

	// The own chat switched off.
	h.selfOn.Store(false)
	expect(t, h.selfSend(t, c, clientRef(), "desligado"), http.StatusForbidden, "send_not_allowed")
	h.selfOn.Store(true)

	want := [][2]string{{"sent", ""}, {"refused", "text_not_allowed"}, {"refused", "text_not_allowed"}, {"refused", "text_not_allowed"},
		{"refused", "text_not_allowed"}, {"refused", "text_not_allowed"}, {"refused", "send_not_allowed"}, {"sent", ""}, {"uncertain", ""},
		{"refused", "device_offline"}, {"refused", "storage_paused"}, {"sent", ""}, {"refused", "send_not_allowed"}}
	if got := h.ledger(t, c.id); !equalRows(got, want) {
		t.Fatalf("ledger = %v", got)
	}
}

// The limits of the send route, Go's own on top of the reader's.
func TestSendRouteLimits(t *testing.T) {
	h := newSendHarness(t)
	c := h.consentSending(t, h.ownerToken, nil)
	h.handler.SendLimits = store.SendLimits{MinInterval: time.Hour}
	expect(t, h.selfSend(t, c, clientRef(), "um"), http.StatusOK, "")
	r := h.selfSend(t, c, clientRef(), "dois")
	expect(t, r, http.StatusTooManyRequests, "rate_limited")
	var limited struct {
		RetryAt time.Time `json:"retry_at"`
	}
	r.into(t, &limited)
	if limited.RetryAt.Sub(time.Now().Add(time.Hour)).Abs() > time.Minute {
		t.Fatalf("retry_at = %s", r.body)
	}
	if len(h.sender.sent()) != 1 {
		t.Fatalf("sends = %d", len(h.sender.sent()))
	}
}

// Refusals the reader decided: recorded, in their shape, for a connection
// that sends.
func TestRefusalRoute(t *testing.T) {
	h := newSendHarness(t)
	c := h.consentSending(t, h.ownerToken, nil)
	post := func(body map[string]any) reply {
		return h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+c.id+"/refusals", c.key, body)
	}
	device := h.device.String()
	expect(t, post(map[string]any{"kind": "draft", "device_id": device, "chat_key": friend, "code": "text_not_allowed"}), http.StatusNoContent, "")
	expect(t, post(map[string]any{"kind": "self", "device_id": device, "code": "rate_limited"}), http.StatusNoContent, "")
	// A draft to a chat the number does not have, or to a group the consent
	// leaves out, is the reader's to refuse, and the ledger's to show.
	expect(t, post(map[string]any{"kind": "draft", "device_id": device, "chat_key": "5511977776666@s.whatsapp.net", "code": "chat_not_eligible"}), http.StatusNoContent, "")
	expect(t, post(map[string]any{"kind": "draft", "device_id": device, "chat_key": "120363041234567890@g.us", "code": "group_not_allowed"}), http.StatusNoContent, "")
	for name, body := range map[string]map[string]any{
		"a code Go decides":      {"kind": "draft", "device_id": device, "chat_key": friend, "code": "reply_not_found"},
		"own chat with a chat":   {"kind": "self", "device_id": device, "chat_key": friend, "code": "rate_limited"},
		"a draft without a chat": {"kind": "draft", "device_id": device, "code": "rate_limited"},
		"another number":         {"kind": "self", "device_id": uuid.NewString(), "code": "rate_limited"},
		"not a kind":             {"kind": "call", "device_id": device, "code": "rate_limited"},
	} {
		t.Run(name, func(t *testing.T) {
			expect(t, post(body), http.StatusBadRequest, "bad_request")
		})
	}
	if got := h.ledger(t, c.id); !equalRows(got, [][2]string{{"refused", "text_not_allowed"}, {"refused", "rate_limited"}, {"refused", "chat_not_eligible"}, {"refused", "group_not_allowed"}}) {
		t.Fatalf("ledger = %v", got)
	}
	// A connection without sending has no ledger to write to, whichever
	// route it calls.
	text, _, key := h.consentContent(t, h.owner)
	expect(t, h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+text+"/refusals", key,
		map[string]any{"kind": "self", "device_id": device, "code": "rate_limited"}), http.StatusNotFound, "not_found")
	expect(t, h.draft(t, sending{id: text, key: key}, friend, nil), http.StatusForbidden, "send_not_allowed")
	expect(t, h.selfSend(t, sending{id: text, key: key}, clientRef(), "x"), http.StatusForbidden, "send_not_allowed")
	if rows := h.ledger(t, text); len(rows) != 0 {
		t.Fatalf("a connection without sending has a ledger: %v", rows)
	}
}

type outboundPage struct {
	Items []struct {
		ID        string  `json:"id"`
		Kind      string  `json:"kind"`
		Status    string  `json:"status"`
		Code      *string `json:"code"`
		ChatKey   *string `json:"chat_key"`
		DecidedBy *string `json:"decided_by"`
	} `json:"items"`
	Next *string `json:"next"`
}

// The reader's list_outgoing: pages, newest first, narrowed, never the
// envelope; the console's adds who decided.
func TestOutboundLists(t *testing.T) {
	h := newSendHarness(t)
	c := h.consentSending(t, h.ownerToken, nil)
	for range 3 {
		expect(t, h.draft(t, c, friend, nil), http.StatusCreated, "")
	}
	expect(t, h.draft(t, c, quiet, nil), http.StatusUnprocessableEntity, "chat_not_eligible")
	expect(t, h.selfSend(t, c, clientRef(), "nota"), http.StatusOK, "")

	get := func(query string) (reply, outboundPage) {
		t.Helper()
		r := h.asConnection(t, http.MethodGet, "/v1/mcp/enclave/connections/"+c.id+"/outbound"+query, c.key, nil)
		var page outboundPage
		if r.status == http.StatusOK {
			r.into(t, &page)
		}
		return r, page
	}
	r, first := get("?limit=2")
	expect(t, r, http.StatusOK, "")
	if len(first.Items) != 2 || first.Next == nil || first.Items[0].Kind != "self" || first.Items[1].Code == nil ||
		*first.Items[1].Code != "chat_not_eligible" || strings.Contains(string(r.body), "sealed") || strings.Contains(string(r.body), "decided_by") {
		t.Fatalf("first page = %s", r.body)
	}
	r, rest := get("?limit=2&before=" + *first.Next)
	expect(t, r, http.StatusOK, "")
	if len(rest.Items) != 2 || rest.Next == nil {
		t.Fatalf("second page = %s", r.body)
	}
	r, last := get("?limit=2&before=" + *rest.Next)
	if len(last.Items) != 1 || last.Next != nil {
		t.Fatalf("last page = %s", r.body)
	}
	if _, pending := get("?status=pending&device_id=" + h.device.String()); len(pending.Items) != 3 {
		t.Fatalf("pending = %+v", pending)
	}
	for _, bad := range []string{"?limit=51", "?limit=0", "?before=nope", "?status=lost", "?device_id=x", "?limit=1&limit=2", "?chat=x"} {
		r, _ := get(bad)
		expect(t, r, http.StatusBadRequest, "bad_request")
	}

	// The console: the consenter, an owner, an admin; decided_by shown.
	admin := h.person(t, "admin")
	member := h.person(t, "member")
	console := func(token string) reply {
		return h.call(t, http.MethodGet, "/v1/mcp/connections/"+c.id+"/outbound?limit=50", nil, bearer(token))
	}
	r = console(h.session(t, admin))
	expect(t, r, http.StatusOK, "")
	var page outboundPage
	r.into(t, &page)
	if len(page.Items) != 5 || !strings.Contains(string(r.body), `"decided_by":null`) {
		t.Fatalf("console page = %s", r.body)
	}
	expect(t, console(h.session(t, member)), http.StatusForbidden, "not_authorized")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/connections/"+uuid.NewString()+"/outbound", nil, bearer(h.ownerToken)), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/connections/"+c.id+"/outbound?status=pending", nil, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
}

// The console's draft routes: only the person who consented opens, lists and
// discards a connection's drafts.
func TestConsoleDrafts(t *testing.T) {
	h := newSendHarness(t)
	c := h.consentSending(t, h.ownerToken, nil)
	r := h.draft(t, c, friend, nil)
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID string `json:"id"`
	}
	r.into(t, &created)
	admin := h.session(t, h.person(t, "admin"))

	r = h.call(t, http.MethodGet, "/v1/mcp/drafts/"+created.ID, nil, bearer(h.ownerToken))
	expect(t, r, http.StatusOK, "")
	var d struct {
		ID           string  `json:"id"`
		ConnectionID string  `json:"connection_id"`
		ClientName   string  `json:"client_name"`
		DeviceID     string  `json:"device_id"`
		ChatKey      string  `json:"chat_key"`
		Epoch        int     `json:"epoch"`
		Sealed       *string `json:"sealed"`
		Status       string  `json:"status"`
	}
	r.into(t, &d)
	if d.ConnectionID != c.id || d.ClientName != "Claude" || d.DeviceID != h.device.String() || d.ChatKey != friend || d.Epoch != 1 ||
		d.Sealed == nil || *d.Sealed != base64.RawURLEncoding.EncodeToString([]byte("a sealed draft")) || d.Status != "pending" {
		t.Fatalf("draft = %s", r.body)
	}
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/drafts/"+created.ID, nil, bearer(admin)), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/drafts/"+strings.ToUpper(created.ID), nil, bearer(h.ownerToken)), http.StatusNotFound, "not_found")

	r = h.call(t, http.MethodGet, "/v1/mcp/connections/"+c.id+"/drafts?status=pending", nil, bearer(h.ownerToken))
	expect(t, r, http.StatusOK, "")
	var list struct {
		Drafts []struct {
			ID string `json:"id"`
		} `json:"drafts"`
	}
	r.into(t, &list)
	if len(list.Drafts) != 1 || list.Drafts[0].ID != created.ID {
		t.Fatalf("pending = %s", r.body)
	}
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/connections/"+c.id+"/drafts", nil, bearer(admin)), http.StatusForbidden, "not_authorized")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/connections/"+c.id+"/drafts?status=sent", nil, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/connections/"+uuid.NewString()+"/drafts", nil, bearer(h.ownerToken)), http.StatusNotFound, "not_found")

	expect(t, h.call(t, http.MethodPost, "/v1/mcp/drafts/"+created.ID+"/discard", nil, bearer(admin)), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/drafts/"+created.ID+"/discard", nil, bearer(h.ownerToken)), http.StatusNoContent, "")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/drafts/"+created.ID+"/discard", nil, bearer(h.ownerToken)), http.StatusConflict, "draft_state")
	r = h.call(t, http.MethodGet, "/v1/mcp/drafts/"+created.ID, nil, bearer(h.ownerToken))
	expect(t, r, http.StatusOK, "")
	if !strings.Contains(string(r.body), `"sealed":null`) || !strings.Contains(string(r.body), `"status":"discarded"`) {
		t.Fatalf("discarded = %s", r.body)
	}
	// Sessions only.
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/drafts/"+created.ID, nil, bearer(c.key)), http.StatusUnauthorized, "unauthorized")
}

// The pause, over HTTP: who may switch it which way, and the list row it
// answers.
func TestConsolePause(t *testing.T) {
	h := newSendHarness(t)
	c := h.consentSending(t, h.ownerToken, nil)
	admin := h.session(t, h.person(t, "admin"))
	member := h.session(t, h.person(t, "member"))
	patch := func(token string, body any) reply {
		return h.call(t, http.MethodPatch, "/v1/mcp/connections/"+c.id+"/send", body, bearer(token))
	}
	expect(t, patch(member, map[string]any{"paused": true}), http.StatusForbidden, "not_authorized")
	r := patch(admin, map[string]any{"paused": true})
	expect(t, r, http.StatusOK, "")
	if !strings.Contains(string(r.body), `"send_paused":true`) || !strings.Contains(string(r.body), `"id":"`+c.id+`"`) {
		t.Fatalf("paused = %s", r.body)
	}
	expect(t, patch(admin, map[string]any{"paused": false}), http.StatusForbidden, "not_authorized")
	r = patch(h.ownerToken, map[string]any{"paused": false})
	expect(t, r, http.StatusOK, "")
	if !strings.Contains(string(r.body), `"send_paused":false`) {
		t.Fatalf("unpaused = %s", r.body)
	}
	expect(t, patch(h.ownerToken, map[string]any{}), http.StatusBadRequest, "bad_request")
	expect(t, patch(h.ownerToken, map[string]any{"paused": true, "remove_chats": []any{}}), http.StatusBadRequest, "bad_request")
	expect(t, patch(h.ownerToken, map[string]any{"paused": "yes"}), http.StatusBadRequest, "bad_request")
	text, _, _ := h.consentContent(t, h.owner)
	expect(t, h.call(t, http.MethodPatch, "/v1/mcp/connections/"+text+"/send", map[string]any{"paused": true}, bearer(h.ownerToken)), http.StatusConflict, "connection_state")
}

// The conversation's "via" label: which archived messages a connection
// sent, for a person who reads the number.
func TestOutboundMessagesRoute(t *testing.T) {
	h := newSendHarness(t)
	c := h.consentSending(t, h.ownerToken, nil)
	r := h.selfSend(t, c, clientRef(), "via")
	expect(t, r, http.StatusOK, "")
	var sent struct {
		MessageUID string `json:"message_uid"`
	}
	r.into(t, &sent)
	path := "/v1/mcp/outbound/messages?device_id=" + h.device.String() + "&uids=" + sent.MessageUID + "," + uuid.NewString()
	r = h.call(t, http.MethodGet, path, nil, bearer(h.ownerToken))
	expect(t, r, http.StatusOK, "")
	want := `{"items":[{"message_uid":"` + sent.MessageUID + `","connection_id":"` + c.id + `","client_name":"Claude","kind":"self"}]}`
	if strings.TrimSpace(string(r.body)) != want {
		t.Fatalf("via = %s", r.body)
	}
	// A person who does not read the number.
	expect(t, h.call(t, http.MethodGet, path, nil, bearer(h.session(t, h.person(t, "admin")))), http.StatusForbidden, "not_authorized")
	many := make([]string, 101)
	for i := range many {
		many[i] = uuid.NewString()
	}
	for _, bad := range []string{
		"?device_id=" + h.device.String(), "?uids=" + sent.MessageUID, "?device_id=x&uids=" + sent.MessageUID,
		"?device_id=" + h.device.String() + "&uids=", "?device_id=" + h.device.String() + "&uids=" + strings.Join(many, ","),
	} {
		expect(t, h.call(t, http.MethodGet, "/v1/mcp/outbound/messages"+bad, nil, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
	}
}
