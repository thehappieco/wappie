package restapi

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"whatserver2/internal/access"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

type Devices struct {
	TenantID string `json:"tenant_id"`
	wsapi.Devices
}
type Chats struct {
	TenantID string `json:"tenant_id"`
	wsapi.Chats
	Limit     int  `json:"limit"`
	Truncated bool `json:"truncated"`
}
type Page struct {
	TenantID string `json:"tenant_id"`
	wsapi.Page
}
type Message struct {
	TenantID string `json:"tenant_id"`
	wsapi.SealedMessage
}
type History struct {
	TenantID     string `json:"tenant_id"`
	RequestedUID string `json:"requested_uid"`
	wsapi.History
}
type Keys struct {
	TenantID string `json:"tenant_id"`
	wsapi.Keys
}
type Grants struct {
	TenantID string `json:"tenant_id"`
	wsapi.Grants
}

func (h *Handler) devices(q *request) {
	if _, ok := q.query(); !ok {
		return
	}
	rows, err := h.Devices.List(q.r.Context(), q.actor.Tenant.String())
	if err != nil {
		q.internal(err)
		return
	}
	out := make([]wsapi.DeviceInfo, 0, len(rows))
	for _, row := range rows {
		id, err := uuid.Parse(row.ID)
		if err != nil {
			q.internal(err)
			return
		}
		allowed, err := q.permitted(id, store.ActionView)
		if err != nil {
			q.internal(err)
			return
		}
		if !allowed {
			continue
		}
		info := wsapi.DeviceFromRow(row)
		info.CanManage, err = access.Allows(q.r.Context(), q.actor, id, store.ActionManage, h.APIKeys, h.Users)
		if err != nil {
			q.internal(err)
			return
		}
		info.CanSend, err = access.Allows(q.r.Context(), q.actor, id, store.ActionSend, h.APIKeys, h.Users)
		if err != nil {
			q.internal(err)
			return
		}
		if q.actor.User != uuid.Nil && q.actor.Key == uuid.Nil {
			mode, err := h.Users.ReaderMode(q.r.Context(), q.actor.Tenant, q.actor.User, id)
			if err != nil {
				q.internal(err)
				return
			}
			info.ReaderReceiptMode = string(mode)
		}
		info.Running = h.Running != nil && row.Status == wa.StatusOnline && !row.Paused && h.Running(row.ID)
		out = append(out, info)
	}
	q.finish(Devices{q.actor.Tenant.String(), wsapi.Devices{Devices: out}})
}

func (h *Handler) chats(q *request) {
	values, ok := q.query("limit")
	if !ok {
		return
	}
	limit, ok := q.limit(values, 100, 3000)
	if !ok {
		return
	}
	device, ok := q.device(store.ActionRead)
	if !ok {
		return
	}
	id := uuid.MustParse(device.ID)
	rows, truncated, err := h.Messages.ChatsWithLimit(q.r.Context(), q.actor.Tenant, id, limit)
	if err != nil {
		q.internal(err)
		return
	}
	out := make([]wsapi.ChatSummary, 0, len(rows))
	for _, row := range rows {
		out = append(out, wsapi.ChatFromRow(row))
	}
	q.finish(Chats{q.actor.Tenant.String(), wsapi.Chats{DeviceID: device.ID, Chats: out}, limit, truncated})
}

func (h *Handler) page(q *request) {
	values, ok := q.query("chat_key", "limit", "before_ts", "before_seq")
	if !ok {
		return
	}
	chat := values.Get("chat_key")
	if chat == "" || len(chat) > 512 {
		q.bad("chat_key is required and limited to 512 bytes")
		return
	}
	limit, ok := q.limit(values, 50, 200)
	if !ok {
		return
	}
	_, hasTS := values["before_ts"]
	_, hasSeq := values["before_seq"]
	if hasTS != hasSeq {
		q.bad("before_ts and before_seq must be supplied together")
		return
	}
	cursor := store.Cursor{}
	if hasTS {
		var err error
		cursor.TS, err = time.Parse(time.RFC3339Nano, values.Get("before_ts"))
		if err != nil || cursor.TS.IsZero() {
			q.bad("before_ts must be an RFC3339 timestamp")
			return
		}
		cursor.Seq, err = strconv.ParseInt(values.Get("before_seq"), 10, 64)
		if err != nil || cursor.Seq < 1 {
			q.bad("before_seq must be a positive integer")
			return
		}
	}
	device, ok := q.device(store.ActionRead)
	if !ok {
		return
	}
	id := uuid.MustParse(device.ID)
	siblings, err := h.Messages.SiblingKeys(q.r.Context(), q.actor.Tenant, id, chat)
	if err != nil {
		q.internal(err)
		return
	}
	rows, err := h.Messages.Page(q.r.Context(), q.actor.Tenant, id, siblings, cursor, limit+1)
	if err != nil {
		q.internal(err)
		return
	}
	more := len(rows) > limit
	if more {
		rows = rows[len(rows)-limit:]
	}
	page := wsapi.Page{ChatKey: chat, Messages: make([]wsapi.SealedMessage, 0, len(rows)), HasMore: more}
	for _, row := range rows {
		page.Messages = append(page.Messages, wsapi.SealedMessageFromRow(row))
	}
	if next := store.Before(rows); !next.TS.IsZero() {
		page.NextTS = &next.TS
		page.NextSeq = next.Seq
	}
	if h.Receipts != nil && len(rows) > 0 {
		ids := make([]string, 0, len(rows))
		for _, row := range rows {
			if !row.Kind.IsControl() {
				ids = append(ids, row.WAID)
			}
		}
		acks, err := h.Receipts.AcksForPage(q.r.Context(), q.actor.Tenant, id, ids)
		if err != nil {
			q.internal(err)
			return
		}
		page.Receipts = wsapi.PageReceipts(rows, acks)
	}
	q.finish(Page{q.actor.Tenant.String(), page})
}

func (q *request) messageRow() (store.Row, bool) {
	if _, ok := q.query(); !ok {
		return store.Row{}, false
	}
	uid, ok := q.uuid(q.r.PathValue("uid"))
	if !ok {
		return store.Row{}, false
	}
	row, err := q.h.Messages.Get(q.r.Context(), q.actor.Tenant, uid)
	if err != nil {
		q.storeError(err)
		return store.Row{}, false
	}
	allowed, err := q.permitted(row.DeviceID, store.ActionRead)
	if err != nil {
		q.internal(err)
		return store.Row{}, false
	}
	if !allowed {
		fail(q.w, http.StatusForbidden, "not_authorized", "this credential cannot read the message")
		return store.Row{}, false
	}
	return row, true
}
func (h *Handler) message(q *request) {
	row, ok := q.messageRow()
	if !ok {
		return
	}
	q.finish(Message{q.actor.Tenant.String(), wsapi.SealedMessageFromRow(row)})
}
func (h *Handler) history(q *request) {
	row, ok := q.messageRow()
	if !ok {
		return
	}
	history, err := h.Messages.History(q.r.Context(), q.actor.Tenant, row.DeviceID, row.ChatKey, row.WAID, h.Receipts)
	if err != nil {
		q.storeError(err)
		return
	}
	q.finish(History{q.actor.Tenant.String(), row.UID.String(), wsapi.HistoryFromStore(history)})
}

func (h *Handler) contentKeys(q *request) {
	values, ok := q.query("ids")
	if !ok {
		return
	}
	raw := strings.Split(values.Get("ids"), ",")
	if len(raw) < 1 || len(raw) > 500 {
		q.bad("request between 1 and 500 content key IDs")
		return
	}
	ids := make([]uint32, 0, len(raw))
	seen := map[uint32]bool{}
	for _, value := range raw {
		id, err := strconv.ParseUint(value, 10, 31)
		if err != nil || id < 1 || id > math.MaxInt32 {
			q.bad("content key IDs must be integers between 1 and 2147483647")
			return
		}
		if !seen[uint32(id)] {
			ids = append(ids, uint32(id))
			seen[uint32(id)] = true
		}
	}
	device, ok := q.device(store.ActionRead)
	if !ok {
		return
	}
	id := uuid.MustParse(device.ID)
	out := make([]wsapi.SealedKey, 0, len(ids))
	for _, keyID := range ids {
		sealed, err := h.Keys.SealedContentKey(q.r.Context(), q.actor.Tenant, id, keyID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			q.internal(err)
			return
		}
		out = append(out, wsapi.SealedKey{ID: keyID, Sealed: sealed})
	}
	q.finish(Keys{q.actor.Tenant.String(), wsapi.Keys{ArchiveTenantID: device.ArchiveTenantID, DeviceID: device.ID, Keys: out}})
}

func (h *Handler) grants(q *request) {
	if _, ok := q.query(); !ok {
		return
	}
	if q.actor.User == uuid.Nil {
		fail(q.w, http.StatusForbidden, "not_authorized", "grants require a session or an API key acting as a service account")
		return
	}
	rows, err := h.Keys.GrantsFor(q.r.Context(), q.actor.Tenant, q.actor.User)
	if err != nil {
		q.internal(err)
		return
	}
	out := make([]wsapi.GrantEntry, 0, len(rows))
	for _, row := range rows {
		allowed, err := q.permitted(row.DeviceID, store.ActionRead)
		if err != nil {
			q.internal(err)
			return
		}
		if !allowed {
			continue
		}
		device, err := h.Devices.Get(q.r.Context(), q.actor.Tenant.String(), row.DeviceID.String())
		if err != nil {
			q.storeError(err)
			return
		}
		out = append(out, wsapi.GrantEntry{ArchiveTenantID: row.ArchiveTenantID.String(), DeviceID: row.DeviceID.String(), Label: device.Label, Epoch: int(row.Epoch), SealedDSK: row.SealedDSK})
	}
	q.finish(Grants{q.actor.Tenant.String(), wsapi.Grants{UserID: q.actor.User.String(), Grants: out}})
}
