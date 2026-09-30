package mcpauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// Sending (docs/mcp-enclave.md §17): the routes the attested reader drafts
// and sends through, the console's, and the ledger's plumbing.
//
// The reader asks; this server decides, on every request and from its own
// ledger. A draft or a send needs, in order: a signed request from the
// connection's reader carrying the connection's own key; a connection that
// is active, has sending in its consent, is not paused, and whose workspace
// the switches allow; the person who consented still able to send on the
// number; a chat the connection may reach; and room under the limits. A
// refusal of any of those is written to the ledger with its code. Nothing
// here ever sees a draft's text, and a send's text only on its way to
// WhatsApp, as for any send from the console.

// OutboundText is one text to send as a number, for SendText: the chat is
// this server's to work out, never the reader's.
type OutboundText struct {
	Tenant, Device uuid.UUID
	Chat           string
	Body           string
}

// OutboundSent is a text that left: WhatsApp's id and time, and the archived
// message's uid, nil when archiving failed (the message left all the same).
type OutboundSent struct {
	WAID       string
	Timestamp  time.Time
	MessageUID *uuid.UUID
}

var (
	// ErrNotSent is SendText refusing before anything reached WhatsApp.
	// Any other error of SendText is a send that may or may not have left.
	ErrNotSent = errors.New("mcpauth: the message was not sent")
	// ErrDeviceOffline is SendText's answer for a number that is not
	// connected.
	ErrDeviceOffline = fmt.Errorf("%w: the number is not connected", ErrNotSent)
	// ErrStoragePaused is SendText's answer for a workspace whose archive
	// capture is paused: as for a send from the console, a message it could
	// not archive is not sent.
	ErrStoragePaused = fmt.Errorf("%w: archive capture is paused", ErrNotSent)
)

// The image's own bounds (packages/mcp-http/enclave/send/policy.mjs), which
// this server applies again to what it is handed.
const (
	// draftSealedMax is DRAFT_SEALED_MAX_BYTES: a draft's envelope.
	draftSealedMax = 16_384
	// selfTextMax is SELF_TEXT_MAX_CHARS, in UTF-16 code units.
	selfTextMax = 1_000
	// chatKeyMax bounds a chat key, in characters, as the ledger's CHECK.
	chatKeyMax = 128
	// outboundPageDefault is a ledger page when the asker names no size.
	outboundPageDefault = 20
	// sendTimeout bounds one send and its record, whoever hangs up: the
	// outcome is written whatever the reader's connection does.
	sendTimeout = 60 * time.Second
)

// defaultSendLimits are the image's ceilings, for a Handler whose limits
// are left zero.
var defaultSendLimits = store.SendLimits{
	DraftsPerHour: 30, DraftsPending: 20, PerDay: 20, PerChatPerDay: 5, MinInterval: 30 * time.Second, TenantPerDay: 100,
}

// sendLimits are the configured limits, a zero field being its default.
func (h *Handler) sendLimits() store.SendLimits {
	l, d := h.SendLimits, defaultSendLimits
	if l.DraftsPerHour == 0 {
		l.DraftsPerHour = d.DraftsPerHour
	}
	if l.DraftsPending == 0 {
		l.DraftsPending = d.DraftsPending
	}
	if l.PerDay == 0 {
		l.PerDay = d.PerDay
	}
	if l.PerChatPerDay == 0 {
		l.PerChatPerDay = d.PerChatPerDay
	}
	if l.MinInterval == 0 {
		l.MinInterval = d.MinInterval
	}
	if l.TenantPerDay == 0 {
		l.TenantPerDay = d.TenantPerDay
	}
	return l
}

func (h *Handler) mountEnclaveSend(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/mcp/enclave/connections/{id}/drafts", h.signed(maxBody, h.enclaveDraft))
	mux.HandleFunc("POST /v1/mcp/enclave/connections/{id}/send", h.signed(maxBody, h.enclaveSend))
	mux.HandleFunc("POST /v1/mcp/enclave/connections/{id}/refusals", h.signed(maxBody, h.enclaveRefusal))
	mux.HandleFunc("GET /v1/mcp/enclave/connections/{id}/outbound", h.signed(maxBody, h.enclaveOutbound))
}

func (h *Handler) mountSendConsole(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/mcp/drafts/{id}", h.consoleDraft)
	mux.HandleFunc("POST /v1/mcp/drafts/{id}/discard", h.consoleDiscard)
	mux.HandleFunc("GET /v1/mcp/connections/{id}/drafts", h.consolePending)
	mux.HandleFunc("GET /v1/mcp/connections/{id}/outbound", h.consoleOutbound)
	mux.HandleFunc("PATCH /v1/mcp/connections/{id}/send", h.consolePause)
	mux.HandleFunc("GET /v1/mcp/outbound/messages", h.outboundMessages)
}

// ---------------------------------------------------------------------------
// The reader's routes
// ---------------------------------------------------------------------------

// sendingConnection is the second step of every send route, after the
// signature: the connection is the calling reader's, and the request
// carries its key, still live, as a bearer. The signature proves the caller
// is the enclave; the bearer proves the enclave holds this connection's key,
// so a mix-up of connection ids inside it fails here. Anything else is 404.
func (h *Handler) sendingConnection(w http.ResponseWriter, r *http.Request, caller *AttestedReader) (store.SendConnection, uuid.UUID, bool) {
	id, ok := connectionID(w, r)
	if !ok {
		return store.SendConnection{}, uuid.Nil, false
	}
	conn, err := h.Connections.SendConnection(r.Context(), caller.ID, id)
	if errors.Is(err, store.ErrMCPConnectionNotFound) {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return store.SendConnection{}, uuid.Nil, false
	}
	if err != nil {
		h.log().Error("could not read a sending connection", "connection", id, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not read the connection")
		return store.SendConnection{}, uuid.Nil, false
	}
	token, ok := bearerToken(r)
	if !ok || h.APIKeys == nil {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return store.SendConnection{}, uuid.Nil, false
	}
	key, err := h.APIKeys.VerifyScoped(r.Context(), token)
	if err != nil || key.ID != conn.APIKeyID || key.TenantID != conn.TenantID.String() {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return store.SendConnection{}, uuid.Nil, false
	}
	return conn, key.ID, true
}

// decodeSigned decodes a signed body strictly: known fields, one value.
func decodeSigned(body []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("one JSON object only")
	}
	return nil
}

// parseID reads a lower-case, canonical, non-nil UUID.
func parseID(raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	return id, err == nil && id != uuid.Nil && id.String() == raw
}

// validChatKey is a chat key the ledger holds: 1 to 128 characters of valid
// UTF-8 with no white space, comma or control character, as the reader's
// schema says.
func validChatKey(key string) bool {
	return utf8.ValidString(key) && key != "" && utf8.RuneCountInString(key) <= chatKeyMax &&
		!strings.ContainsFunc(key, func(r rune) bool { return r <= ' ' || r == ',' || r == 0x7F || r >= 0x80 && r <= 0xA0 })
}

// draftRequest is the reader's draft: the id it drew, where it goes, and the
// envelope it sealed to the number's archive key.
type draftRequest struct {
	ID         string  `json:"id"`
	DeviceID   string  `json:"device_id"`
	ChatKey    string  `json:"chat_key"`
	ReplyToUID *string `json:"reply_to_uid"`
	Epoch      int     `json:"epoch"`
	Sealed     string  `json:"sealed"`
}

type draftCreated struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// enclaveDraft records a draft (docs/mcp-enclave.md §17.7, the draft route's
// order). A refusal of the connection's state, the switches, the person's
// permission, the chat or the limits is also written to the ledger.
func (h *Handler) enclaveDraft(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte) {
	conn, key, ok := h.sendingConnection(w, r, caller)
	if !ok {
		return
	}
	var req draftRequest
	if err := decodeSigned(body, &req); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request: "+err.Error())
		return
	}
	in, msg := checkDraft(req)
	if msg != "" {
		fail(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	refusal := store.Refusal{Kind: store.OutboundDraft, Device: in.Device, ChatKey: in.ChatKey}
	rd, known := h.readerByID(caller.ID)
	if !known || !h.sendAllowed(rd, conn.TenantID) {
		h.refuseSend(w, r.Context(), conn, refusal, store.ErrSendNotAllowed)
		return
	}
	expires, err := h.Connections.CreateDraft(r.Context(), conn, key, in, h.sendLimits())
	switch {
	case errors.Is(err, store.ErrDraftExists):
		fail(w, http.StatusConflict, "draft_exists", "a draft with that id exists")
		return
	case err != nil:
		h.refuseSend(w, r.Context(), conn, refusal, err)
		return
	}
	h.log().Info("mcp_draft_created", "connection", conn.ID, "draft", in.ID, "device", in.Device)
	send(w, http.StatusCreated, draftCreated{ID: in.ID.String(), ExpiresAt: expires.UTC()})
}

// checkDraft validates a draft's shape; the message says what is wrong.
func checkDraft(req draftRequest) (store.NewDraft, string) {
	var in store.NewDraft
	var ok bool
	if in.ID, ok = parseID(req.ID); !ok {
		return in, "id must be a lower-case UUID"
	}
	if in.Device, ok = parseID(req.DeviceID); !ok {
		return in, "device_id must be a lower-case UUID"
	}
	if !validChatKey(req.ChatKey) {
		return in, "chat_key must be 1 to 128 characters, without white space or commas"
	}
	in.ChatKey = req.ChatKey
	if req.ReplyToUID != nil {
		reply, ok := parseID(*req.ReplyToUID)
		if !ok {
			return in, "reply_to_uid must be a lower-case UUID"
		}
		in.ReplyTo = &reply
	}
	if req.Epoch < 1 || req.Epoch > 65535 {
		return in, "epoch must be 1 to 65535"
	}
	in.Epoch = req.Epoch
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(req.Sealed)
	if err != nil || len(sealed) == 0 || len(sealed) > draftSealedMax {
		return in, "sealed must be the unpadded base64url of at most 16384 bytes"
	}
	in.Sealed = sealed
	return in, ""
}

// sendRequest is the reader's send. Kind "self" is an own-chat note; kind
// "send" (a direct send, with chat_key, reply_to_uid and reply_body) is S3's
// and refused until then.
type sendRequest struct {
	ClientRef  string          `json:"client_ref"`
	Kind       string          `json:"kind"`
	DeviceID   string          `json:"device_id"`
	Text       json.RawMessage `json:"text"`
	ChatKey    *string         `json:"chat_key"`
	ReplyToUID *string         `json:"reply_to_uid"`
	ReplyBody  *string         `json:"reply_body"`
}

// clientRefPattern is a send's reference: 16 random bytes in base64url.
var clientRefPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// sentReply answers a send that left, or a reference already recorded.
type sentReply struct {
	ID         string    `json:"id"`
	MessageUID *string   `json:"message_uid"`
	WAID       string    `json:"wa_id"`
	Timestamp  time.Time `json:"timestamp"`
	Duplicate  bool      `json:"duplicate"`
}

// enclaveSend sends an own-chat note (docs/mcp-enclave.md §17.7, the send
// route's order). The ledger takes the send before it leaves, so a repeated
// reference never makes a second message: it answers what was recorded.
// Nothing here retries; a send that may or may not have left is uncertain,
// and a person resolves it.
func (h *Handler) enclaveSend(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte) {
	conn, key, ok := h.sendingConnection(w, r, caller)
	if !ok {
		return
	}
	var req sendRequest
	if err := decodeSigned(body, &req); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request: "+err.Error())
		return
	}
	device, text, textOK, msg := checkSend(req)
	if msg != "" {
		fail(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	refusal := store.Refusal{Kind: req.Kind, Device: device}
	rd, known := h.readerByID(caller.ID)
	if req.Kind != store.OutboundSelf || !known || !h.sendSelfAllowed(rd, conn.TenantID) || h.SendText == nil {
		// Direct send is S3's: no connection has it yet, and its switch
		// cannot be on.
		if req.Kind == store.OutboundSend {
			refusal.ChatKey = *req.ChatKey
		}
		h.refuseSend(w, r.Context(), conn, refusal, store.ErrSendNotAllowed)
		return
	}
	started, prior, err := h.Connections.StartSend(r.Context(), conn, key,
		store.NewSend{Kind: req.Kind, Device: device, ClientRef: req.ClientRef, TextOK: textOK}, h.sendLimits())
	if err != nil {
		h.refuseSend(w, r.Context(), conn, refusal, err)
		return
	}
	if prior != nil {
		h.recordedSend(w, *prior)
		return
	}

	// The send and its record run to their end whoever hangs up: a reader
	// that loses the answer calls it uncertain and never repeats it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), sendTimeout)
	defer cancel()
	sent, err := h.SendText(ctx, OutboundText{Tenant: conn.TenantID, Device: device, Chat: started.ChatKey, Body: text})
	switch {
	case errors.Is(err, ErrNotSent):
		code, status, msg := "internal", http.StatusInternalServerError, "nothing was sent; try again later"
		switch {
		case errors.Is(err, ErrDeviceOffline):
			code, status, msg = "device_offline", http.StatusConflict, "the number is not connected to WhatsApp right now; nothing was sent"
		case errors.Is(err, ErrStoragePaused):
			code, status, msg = "storage_paused", http.StatusConflict, "the workspace's archive capture is paused; nothing was sent"
		default:
			h.log().Error("a send failed before it left", "connection", conn.ID, "send", started.ID, "error", err)
		}
		h.finishSend(ctx, conn, started.ID, store.SendOutcome{Status: store.OutboundRefused, Code: code, At: time.Now()})
		h.log().Info("mcp_send_refused", "connection", conn.ID, "send", started.ID, "device", device, "kind", req.Kind, "code", code)
		fail(w, status, code, msg)
		return
	case err != nil:
		h.finishSend(ctx, conn, started.ID, store.SendOutcome{Status: store.OutboundUncertain, At: time.Now()})
		// Not the error's text: a transport error may name the chat.
		h.log().Warn("mcp_send_uncertain", "connection", conn.ID, "send", started.ID, "device", device, "kind", req.Kind)
		fail(w, http.StatusBadGateway, "send_uncertain", "the message may or may not have reached WhatsApp; it is not sent again")
		return
	}
	at := sent.Timestamp.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	h.finishSend(ctx, conn, started.ID, store.SendOutcome{Status: store.OutboundSent, MessageUID: sent.MessageUID, WAID: sent.WAID, At: at})
	h.log().Info("mcp_send", "connection", conn.ID, "send", started.ID, "device", device, "kind", req.Kind, "archived", sent.MessageUID != nil)
	reply := sentReply{ID: started.ID.String(), WAID: sent.WAID, Timestamp: at}
	if sent.MessageUID != nil {
		uid := sent.MessageUID.String()
		reply.MessageUID = &uid
	}
	send(w, http.StatusOK, reply)
}

// checkSend validates a send's shape. The text is decoded exactly and put to
// the rules: a text they refuse is not malformed, and is refused in its
// place in the order, with the ledger told.
func checkSend(req sendRequest) (device uuid.UUID, text string, textOK bool, msg string) {
	if !clientRefPattern.MatchString(req.ClientRef) {
		return uuid.Nil, "", false, "client_ref must be 22 base64url characters"
	}
	var ok bool
	if device, ok = parseID(req.DeviceID); !ok {
		return uuid.Nil, "", false, "device_id must be a lower-case UUID"
	}
	if len(req.Text) == 0 || req.Text[0] != '"' || json.Unmarshal(req.Text, &text) != nil {
		return uuid.Nil, "", false, "text must be a string"
	}
	switch req.Kind {
	case store.OutboundSelf:
		if req.ChatKey != nil || req.ReplyToUID != nil || req.ReplyBody != nil {
			return uuid.Nil, "", false, "an own-chat send names no chat and no reply"
		}
	case store.OutboundSend:
		if req.ChatKey == nil || !validChatKey(*req.ChatKey) {
			return uuid.Nil, "", false, "chat_key must be 1 to 128 characters, without white space or commas"
		}
	default:
		return uuid.Nil, "", false, `kind must be "self" or "send"`
	}
	exact, ok := jsonString(req.Text)
	if !ok {
		return device, "", false, ""
	}
	return device, normalizeNewlines(exact), textRefusal(exact, true, selfTextMax) == "", ""
}

// finishSend records a send's outcome. A failure leaves the row sending,
// which the janitor turns uncertain: the ledger never says sent for a send
// it cannot vouch for.
func (h *Handler) finishSend(ctx context.Context, conn store.SendConnection, id uuid.UUID, out store.SendOutcome) {
	if err := h.Connections.FinishSend(ctx, conn.TenantID, id, out); err != nil {
		h.log().Error("could not record how a send ended", "connection", conn.ID, "send", id, "status", out.Status, "error", err)
	}
}

// duplicateError is a refusal that repeats what the ledger recorded.
type duplicateError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Duplicate bool   `json:"duplicate"`
}

// recordedSend answers a reference already in the ledger with what was
// recorded, marked as a duplicate.
func (h *Handler) recordedSend(w http.ResponseWriter, o store.Outbound) {
	switch o.Status {
	case store.OutboundSent:
		reply := sentReply{ID: o.ID.String(), WAID: o.WAID, Duplicate: true}
		if o.DecidedAt != nil {
			reply.Timestamp = o.DecidedAt.UTC()
		}
		if o.MessageUID != nil {
			uid := o.MessageUID.String()
			reply.MessageUID = &uid
		}
		send(w, http.StatusOK, reply)
	case store.OutboundUncertain:
		send(w, http.StatusBadGateway, duplicateError{Code: "send_uncertain", Message: "the message may or may not have reached WhatsApp; it is not sent again", Duplicate: true})
	case store.OutboundRefused:
		send(w, refusedStatus(o.Code), duplicateError{Code: o.Code, Message: "this send was refused", Duplicate: true})
	default:
		send(w, http.StatusConflict, duplicateError{Code: "send_in_progress", Message: "this message is still being sent", Duplicate: true})
	}
}

// refusedStatus is the status a recorded refusal answers with.
func refusedStatus(code string) int {
	switch code {
	case "send_not_allowed":
		return http.StatusForbidden
	case "connection_state", "device_offline", "storage_paused":
		return http.StatusConflict
	case "rate_limited":
		return http.StatusTooManyRequests
	case "internal":
		return http.StatusInternalServerError
	default:
		return http.StatusUnprocessableEntity
	}
}

// rateLimited answers a limit, with when the refused request would pass.
type rateLimited struct {
	Code    string    `json:"code"`
	Message string    `json:"message"`
	RetryAt time.Time `json:"retry_at"`
}

// refuseSend answers a refused draft or send, and writes the refusal to the
// ledger unless it is about the request rather than the connection: an
// unknown connection is only answered.
func (h *Handler) refuseSend(w http.ResponseWriter, ctx context.Context, conn store.SendConnection, refusal store.Refusal, err error) {
	var limited *store.RateLimitError
	switch {
	case errors.Is(err, store.ErrMCPConnectionNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return
	case errors.Is(err, store.ErrMCPConnectionState):
		refusal.Code = "connection_state"
		fail(w, http.StatusConflict, refusal.Code, "the connection is not active")
	case errors.Is(err, store.ErrSendNotAllowed):
		refusal.Code = "send_not_allowed"
		fail(w, http.StatusForbidden, refusal.Code, "sending is not enabled for this connection right now")
	case errors.Is(err, store.ErrChatNotEligible):
		refusal.Code = "chat_not_eligible"
		fail(w, http.StatusUnprocessableEntity, refusal.Code, "messages go only to chats of this connection's numbers where the other side has written")
	case errors.Is(err, store.ErrGroupNotAllowed):
		refusal.Code = "group_not_allowed"
		fail(w, http.StatusUnprocessableEntity, refusal.Code, "this connection does not send to groups")
	case errors.Is(err, store.ErrReplyNotFound):
		refusal.Code = "reply_not_found"
		fail(w, http.StatusUnprocessableEntity, refusal.Code, "reply_to_uid is not a message of this chat")
	case errors.Is(err, store.ErrTextNotAllowed):
		refusal.Code = "text_not_allowed"
		fail(w, http.StatusUnprocessableEntity, refusal.Code, "the text has characters or links this connection does not send")
	case errors.As(err, &limited):
		refusal.Code = "rate_limited"
		send(w, http.StatusTooManyRequests, rateLimited{Code: refusal.Code, Message: "this connection's limit is reached", RetryAt: limited.RetryAt.UTC()})
	default:
		h.log().Error("a draft or send failed", "connection", conn.ID, "kind", refusal.Kind, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not draft or send")
		return
	}
	h.recordRefusal(ctx, conn, refusal)
}

// recordRefusal writes a refusal to the ledger, or counts it for the log
// once the connection's daily cap is reached. A connection whose consent has
// no sending has no ledger: a reader that asks for it anyway is only
// answered.
func (h *Handler) recordRefusal(ctx context.Context, conn store.SendConnection, refusal store.Refusal) {
	if conn.SendMode == "" {
		return
	}
	recorded, err := h.Connections.RecordRefusal(context.WithoutCancel(ctx), conn.TenantID, conn.ID, refusal)
	switch {
	case err != nil:
		h.log().Warn("could not record a refusal", "connection", conn.ID, "kind", refusal.Kind, "code", refusal.Code, "error", err)
	case recorded:
		h.log().Info("mcp_send_refused", "connection", conn.ID, "kind", refusal.Kind, "device", refusal.Device, "code", refusal.Code)
	default:
		h.dropped.note(conn.ID)
	}
}

// refusalRequest is a refusal the reader decided itself.
type refusalRequest struct {
	Kind     string  `json:"kind"`
	DeviceID string  `json:"device_id"`
	ChatKey  *string `json:"chat_key"`
	Code     string  `json:"code"`
}

// readerRefusalCodes are the refusals the reader decides on its own and
// records here.
var readerRefusalCodes = []string{"text_not_allowed", "cross_chat_blocked", "chat_not_allowed", "recipient_mismatch", "rate_limited",
	"chat_not_eligible", "group_not_allowed"}

// enclaveRefusal records a refusal the reader decided: a text its rules
// refused, its own limits, a draft to a chat the number does not have or to
// a group its consent leaves out, and from S3 a chat off the list, a
// recipient that does not match or a copy from another chat. A connection
// without sending has no ledger to write to.
func (h *Handler) enclaveRefusal(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte) {
	conn, _, ok := h.sendingConnection(w, r, caller)
	if !ok {
		return
	}
	var req refusalRequest
	if err := decodeSigned(body, &req); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request: "+err.Error())
		return
	}
	device, ok := parseID(req.DeviceID)
	switch {
	case req.Kind != store.OutboundDraft && req.Kind != store.OutboundSelf && req.Kind != store.OutboundSend:
		fail(w, http.StatusBadRequest, "bad_request", `kind must be "draft", "self" or "send"`)
		return
	case !ok:
		fail(w, http.StatusBadRequest, "bad_request", "device_id must be a lower-case UUID")
		return
	case req.Kind == store.OutboundSelf && req.ChatKey != nil:
		fail(w, http.StatusBadRequest, "bad_request", "an own-chat refusal names no chat")
		return
	case req.Kind != store.OutboundSelf && (req.ChatKey == nil || !validChatKey(*req.ChatKey)):
		fail(w, http.StatusBadRequest, "bad_request", "chat_key must be 1 to 128 characters, without white space or commas")
		return
	case !slices.Contains(readerRefusalCodes, req.Code):
		fail(w, http.StatusBadRequest, "bad_request", "code must be one of "+strings.Join(readerRefusalCodes, ", "))
		return
	}
	if conn.SendMode == "" {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return
	}
	refusal := store.Refusal{Kind: req.Kind, Device: device, Code: req.Code}
	if req.ChatKey != nil {
		refusal.ChatKey = *req.ChatKey
	}
	recorded, err := h.Connections.RecordRefusal(r.Context(), conn.TenantID, conn.ID, refusal)
	switch {
	case errors.Is(err, store.ErrChatNotEligible):
		fail(w, http.StatusBadRequest, "bad_request", "device_id is not one of this connection's numbers")
		return
	case err != nil:
		h.log().Error("could not record a refusal", "connection", conn.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not record the refusal")
		return
	case recorded:
		h.log().Info("mcp_send_refused", "connection", conn.ID, "kind", req.Kind, "device", device, "code", req.Code)
	default:
		h.dropped.note(conn.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// outboundItem is one ledger row as the reader and the console list it:
// never the envelope.
type outboundItem struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	Code       *string    `json:"code"`
	DeviceID   string     `json:"device_id"`
	ChatKey    *string    `json:"chat_key"`
	ReplyToUID *string    `json:"reply_to_uid"`
	CreatedAt  time.Time  `json:"created_at"`
	DecidedAt  *time.Time `json:"decided_at"`
	Edited     bool       `json:"edited"`
	MessageUID *string    `json:"message_uid"`
}

// consoleOutboundItem adds who decided a draft, for the console.
type consoleOutboundItem struct {
	outboundItem
	DecidedBy *string `json:"decided_by"`
}

type outboundPage[T any] struct {
	Items []T     `json:"items"`
	Next  *string `json:"next"`
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optionalID(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func itemOf(o store.Outbound) outboundItem {
	item := outboundItem{
		ID: o.ID.String(), Kind: o.Kind, Status: o.Status, Code: optional(o.Code), DeviceID: o.DeviceID.String(),
		ChatKey: optional(o.ChatKey), ReplyToUID: optionalID(o.ReplyTo), CreatedAt: o.CreatedAt.UTC(),
		Edited: o.Edited, MessageUID: optionalID(o.MessageUID),
	}
	if o.DecidedAt != nil {
		at := o.DecidedAt.UTC()
		item.DecidedAt = &at
	}
	return item
}

// encodeCursor and decodeCursor carry a page's end as an opaque 32
// characters: the last row's time in microseconds and its id.
func encodeCursor(o store.Outbound) string {
	raw := make([]byte, 24)
	binary.BigEndian.PutUint64(raw, uint64(o.CreatedAt.UnixMicro())) //nolint:gosec // G115: a time since 1970, positive
	copy(raw[8:], o.ID[:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor(s string) (store.OutboundCursor, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != 24 {
		return store.OutboundCursor{}, false
	}
	micros := int64(binary.BigEndian.Uint64(raw)) //nolint:gosec // G115: checked below
	if micros <= 0 {
		return store.OutboundCursor{}, false
	}
	var id uuid.UUID
	copy(id[:], raw[8:])
	return store.OutboundCursor{CreatedAt: time.UnixMicro(micros), ID: id}, true
}

// outboundQuery reads a ledger page's query: limit (1 to 50, 20 by default),
// before (a previous page's next), and, where allowed, status and device_id.
// Each at most once; anything else is refused.
func outboundQuery(w http.ResponseWriter, r *http.Request, narrowing bool) (store.OutboundQuery, bool) {
	q := store.OutboundQuery{Limit: outboundPageDefault}
	allowed := []string{"limit", "before"}
	if narrowing {
		allowed = append(allowed, "status", "device_id")
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	bad := func(msg string) (store.OutboundQuery, bool) {
		fail(w, http.StatusBadRequest, "bad_request", msg)
		return store.OutboundQuery{}, false
	}
	if err != nil {
		return bad("invalid query parameters")
	}
	for name, items := range values {
		if !slices.Contains(allowed, name) || len(items) != 1 {
			return bad("unknown or repeated query parameter; allowed: " + strings.Join(allowed, ", "))
		}
	}
	if raw, ok := values["limit"]; ok {
		n, err := strconv.Atoi(raw[0])
		if err != nil || n < 1 || n > store.MaxOutboundPage {
			return bad("limit must be 1 to 50")
		}
		q.Limit = n
	}
	if raw, ok := values["before"]; ok {
		cursor, ok := decodeCursor(raw[0])
		if !ok || len(raw[0]) > 64 {
			return bad("before must be a previous page's next")
		}
		q.Before = &cursor
	}
	if raw, ok := values["status"]; ok {
		if !slices.Contains(store.OutboundStatuses, raw[0]) {
			return bad("status must be one of " + strings.Join(store.OutboundStatuses, ", "))
		}
		q.Status = raw[0]
	}
	if raw, ok := values["device_id"]; ok {
		device, ok := parseID(raw[0])
		if !ok {
			return bad("device_id must be a lower-case UUID")
		}
		q.Device = &device
	}
	return q, true
}

// enclaveOutbound is a page of the connection's ledger for the reader's
// list_outgoing, newest first.
func (h *Handler) enclaveOutbound(w http.ResponseWriter, r *http.Request, caller *AttestedReader, _ []byte) {
	conn, _, ok := h.sendingConnection(w, r, caller)
	if !ok {
		return
	}
	q, ok := outboundQuery(w, r, true)
	if !ok {
		return
	}
	rows, more, err := h.Connections.ListOutbound(r.Context(), conn.TenantID, conn.ID, q)
	if err != nil {
		h.log().Error("could not list a ledger", "connection", conn.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not list the ledger")
		return
	}
	page := outboundPage[outboundItem]{Items: make([]outboundItem, 0, len(rows))}
	for _, o := range rows {
		page.Items = append(page.Items, itemOf(o))
	}
	if more {
		next := encodeCursor(rows[len(rows)-1])
		page.Next = &next
	}
	send(w, http.StatusOK, page)
}

// ---------------------------------------------------------------------------
// The console's routes
// ---------------------------------------------------------------------------

// draftInfo is a draft for the console to open: its envelope while it
// waits, and the routing fields the console binds the opening to.
type draftInfo struct {
	ID           string    `json:"id"`
	ConnectionID string    `json:"connection_id"`
	ClientName   string    `json:"client_name"`
	DeviceID     string    `json:"device_id"`
	ChatKey      string    `json:"chat_key"`
	ReplyToUID   *string   `json:"reply_to_uid"`
	Epoch        int       `json:"epoch"`
	Sealed       *string   `json:"sealed"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func draftOf(o store.Outbound) draftInfo {
	d := draftInfo{
		ID: o.ID.String(), ConnectionID: o.ConnectionID, ClientName: o.ClientName, DeviceID: o.DeviceID.String(),
		ChatKey: o.ChatKey, ReplyToUID: optionalID(o.ReplyTo), Epoch: o.Epoch, Status: o.Status, CreatedAt: o.CreatedAt.UTC(),
	}
	if o.ExpiresAt != nil {
		d.ExpiresAt = o.ExpiresAt.UTC()
	}
	if len(o.Sealed) > 0 {
		sealed := base64.RawURLEncoding.EncodeToString(o.Sealed)
		d.Sealed = &sealed
	}
	return d
}

// draftID reads the path's draft id.
func draftID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, ok := parseID(r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such draft")
	}
	return id, ok
}

// consoleDraft hands a draft to the person who consented to its connection,
// and to nobody else: anyone else is told there is no such draft.
func (h *Handler) consoleDraft(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := draftID(w, r)
	if !ok {
		return
	}
	o, err := h.Connections.Draft(r.Context(), user.TenantID, user.ID, id)
	if errors.Is(err, store.ErrOutboundNotFound) {
		fail(w, http.StatusNotFound, "not_found", "no such draft")
		return
	}
	if err != nil {
		h.log().Error("could not read a draft", "draft", id, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not read the draft")
		return
	}
	send(w, http.StatusOK, draftOf(o))
}

// consoleDiscard throws a waiting draft away for the person who consented.
func (h *Handler) consoleDiscard(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := draftID(w, r)
	if !ok {
		return
	}
	connection, err := h.Connections.DiscardDraft(r.Context(), user.TenantID, user.ID, id)
	switch {
	case errors.Is(err, store.ErrOutboundNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such draft")
		return
	case errors.Is(err, store.ErrDraftState):
		fail(w, http.StatusConflict, "draft_state", "the draft is no longer waiting")
		return
	case err != nil:
		h.log().Error("could not discard a draft", "draft", id, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not discard the draft")
		return
	}
	h.log().Info("mcp_draft_decided", "connection", connection, "draft", id, "status", store.OutboundDiscarded)
	w.WriteHeader(http.StatusNoContent)
}

type pendingReply struct {
	Drafts []draftInfo `json:"drafts"`
}

// consolePending lists a connection's waiting drafts, oldest first, for the
// person who consented; anyone else in the workspace gets 403.
func (h *Handler) consolePending(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values) > 1 || len(values) == 1 && (len(values["status"]) != 1 || values.Get("status") != store.OutboundPending) {
		fail(w, http.StatusBadRequest, "bad_request", "the only query is status=pending")
		return
	}
	rows, err := h.Connections.PendingDrafts(r.Context(), user.TenantID, user.ID, id)
	if err != nil {
		h.consoleSendError(w, err)
		return
	}
	out := pendingReply{Drafts: make([]draftInfo, 0, len(rows))}
	for _, o := range rows {
		out.Drafts = append(out.Drafts, draftOf(o))
	}
	send(w, http.StatusOK, out)
}

// consoleOutbound is a page of a connection's ledger for the person who
// consented, an owner or an admin.
func (h *Handler) consoleOutbound(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	q, ok := outboundQuery(w, r, false)
	if !ok {
		return
	}
	rows, more, err := h.Connections.ConsoleOutbound(r.Context(), user.TenantID, user.ID, id, q)
	if err != nil {
		h.consoleSendError(w, err)
		return
	}
	page := outboundPage[consoleOutboundItem]{Items: make([]consoleOutboundItem, 0, len(rows))}
	for _, o := range rows {
		page.Items = append(page.Items, consoleOutboundItem{outboundItem: itemOf(o), DecidedBy: optionalID(o.DecidedBy)})
	}
	if more {
		next := encodeCursor(rows[len(rows)-1])
		page.Next = &next
	}
	send(w, http.StatusOK, page)
}

// pauseRequest switches a connection's pause. remove_chats is S3's.
type pauseRequest struct {
	Paused      *bool           `json:"paused"`
	RemoveChats json.RawMessage `json:"remove_chats"`
}

// consolePause switches a connection's sending pause: the person who
// consented, an owner or an admin may pause it, and only the person who
// consented may take the pause off. Reading goes on either way. It answers
// the connection as the list shows it.
func (h *Handler) consolePause(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	var req pauseRequest
	if !decode(w, r, &req) {
		return
	}
	switch {
	case len(req.RemoveChats) > 0:
		fail(w, http.StatusBadRequest, "bad_request", "remove_chats arrives with direct send")
		return
	case req.Paused == nil:
		fail(w, http.StatusBadRequest, "bad_request", "paused must be true or false")
		return
	}
	if err := h.Connections.SetSendPaused(r.Context(), user.TenantID, user.ID, id, *req.Paused); err != nil {
		h.consoleSendError(w, err)
		return
	}
	h.log().Info("mcp connection send pause", "connection", id, "paused", *req.Paused)
	rows, err := h.Connections.List(r.Context(), user.TenantID)
	if err != nil {
		h.log().Error("could not list mcp connections", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not list the connections")
		return
	}
	allowed, now := h.contentEnabledFor(user.TenantID), time.Now()
	for _, c := range rows {
		if c.ID == id {
			send(w, http.StatusOK, listedConnection(c, user.ID, allowed, now))
			return
		}
	}
	fail(w, http.StatusNotFound, "not_found", "no such connection")
}

// consoleSendError maps what the ledger says to the console's answers.
func (h *Handler) consoleSendError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrMCPConnectionNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such connection in this workspace")
	case errors.Is(err, store.ErrMembershipForbidden):
		fail(w, http.StatusForbidden, "not_authorized", "only the person who consented, or for some things an owner or an admin, may do this")
	case errors.Is(err, store.ErrMCPConnectionState):
		fail(w, http.StatusConflict, "connection_state", "the connection is not live, or does not send")
	default:
		h.log().Error("an mcp sending operation failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not manage the connection")
	}
}

type outboundMessage struct {
	MessageUID   string `json:"message_uid"`
	ConnectionID string `json:"connection_id"`
	ClientName   string `json:"client_name"`
	Kind         string `json:"kind"`
}

type outboundMessages struct {
	Items []outboundMessage `json:"items"`
}

// maxOutboundUIDs bounds one question about which messages a connection
// sent: a page of a conversation.
const maxOutboundUIDs = 100

// outboundMessages says which of a number's archived messages a connection
// sent, for the conversation's "via" label: to a person who reads the
// number.
func (h *Handler) outboundMessages(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values) != 2 || len(values["device_id"]) != 1 || len(values["uids"]) != 1 {
		fail(w, http.StatusBadRequest, "bad_request", "device_id and uids are required, once each")
		return
	}
	device, ok := parseID(values.Get("device_id"))
	if !ok {
		fail(w, http.StatusBadRequest, "bad_request", "device_id must be a lower-case UUID")
		return
	}
	parts := strings.Split(values.Get("uids"), ",")
	if len(parts) < 1 || len(parts) > maxOutboundUIDs {
		fail(w, http.StatusBadRequest, "bad_request", "uids must be 1 to 100 message uids, comma separated")
		return
	}
	uids := make([]uuid.UUID, 0, len(parts))
	for _, part := range parts {
		uid, ok := parseID(part)
		if !ok {
			fail(w, http.StatusBadRequest, "bad_request", "uids must be 1 to 100 message uids, comma separated")
			return
		}
		uids = append(uids, uid)
	}
	p, err := h.Users.DevicePermission(r.Context(), user.TenantID, user.ID, device)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.log().Error("could not check a device permission", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not check the number")
		return
	}
	if err != nil || !p.Allows(store.ActionRead) {
		fail(w, http.StatusForbidden, "not_authorized", "reading this number requires read permission and its key")
		return
	}
	rows, err := h.Connections.OutboundMessages(r.Context(), user.TenantID, device, uids)
	if err != nil {
		h.log().Error("could not read which messages a connection sent", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not read the ledger")
		return
	}
	out := outboundMessages{Items: make([]outboundMessage, 0, len(rows))}
	for _, o := range rows {
		out.Items = append(out.Items, outboundMessage{MessageUID: o.MessageUID.String(), ConnectionID: o.ConnectionID, ClientName: o.ClientName, Kind: o.Kind})
	}
	send(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Refusals past the cap
// ---------------------------------------------------------------------------

// refusalDrops counts, per connection, the refusals the ledger's daily cap
// left out, until the next time they are logged.
type refusalDrops struct {
	mu     sync.Mutex
	counts map[string]int
}

func newRefusalDrops() *refusalDrops { return &refusalDrops{counts: map[string]int{}} }

func (d *refusalDrops) note(connection string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.counts[connection]++
	d.mu.Unlock()
}

// droppedEvery is how often the refusals past the cap are logged.
const droppedEvery = time.Hour

// WatchDroppedRefusals logs the refusals past the ledger's cap once an hour
// until ctx ends.
func (h *Handler) WatchDroppedRefusals(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(droppedEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			h.LogDroppedRefusals()
		}
	}()
}

// LogDroppedRefusals logs, per connection, the refusals the ledger's cap
// left out since it was last called, and forgets them.
func (h *Handler) LogDroppedRefusals() {
	if h.dropped == nil {
		return
	}
	h.dropped.mu.Lock()
	counts := h.dropped.counts
	h.dropped.counts = map[string]int{}
	h.dropped.mu.Unlock()
	for connection, n := range counts {
		h.log().Warn("mcp_refusals_dropped", "connection", connection, "count", n)
	}
}
