package restapi

import (
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

type Contacts struct {
	TenantID string `json:"tenant_id"`
	wsapi.Contacts
	HasMore bool   `json:"has_more"`
	NextKey string `json:"next_key,omitempty"`
}

// ScanMessage preserves the original sender timestamp (including its absence).
// OrderTS explicitly identifies the timestamp used for filtering and paging.
type ScanMessage struct {
	wsapi.SealedMessage
	OrderTS time.Time `json:"order_ts"`
}

type ScanPage struct {
	TenantID string        `json:"tenant_id"`
	DeviceID string        `json:"device_id"`
	From     time.Time     `json:"from"`
	Until    time.Time     `json:"until"`
	Messages []ScanMessage `json:"messages"`
	HasMore  bool          `json:"has_more"`
	NextTS   *time.Time    `json:"next_ts,omitempty"`
	NextSeq  int64         `json:"next_seq,omitempty"`
}

func routingKey(value string) bool {
	return value != "" && len(value) <= 512 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func (h *Handler) contacts(q *request) {
	values, ok := q.query("limit", "after_key")
	if !ok {
		return
	}
	limit, ok := q.limit(values, 100, 500)
	if !ok {
		return
	}
	after := values.Get("after_key")
	if values.Has("after_key") && !routingKey(after) {
		q.bad("after_key must be a nonempty contact key of at most 512 bytes")
		return
	}
	device, ok := q.device(store.ActionRead)
	if !ok {
		return
	}
	rows, err := h.Contacts.Page(q.r.Context(), q.actor.Tenant, uuid.MustParse(device.ID), after, limit+1)
	if err != nil {
		q.internal(err)
		return
	}
	out := Contacts{TenantID: q.actor.Tenant.String(), Contacts: wsapi.Contacts{DeviceID: device.ID, Contacts: make([]wsapi.ContactSummary, 0, min(len(rows), limit))}, HasMore: len(rows) > limit}
	if out.HasMore {
		rows = rows[:limit]
		out.NextKey = rows[len(rows)-1].ContactKey
	}
	for _, row := range rows {
		out.Contacts.Contacts = append(out.Contacts.Contacts, wsapi.ContactFromRow(row))
	}
	q.finish(out)
}

func (q *request) scanCursor(values url.Values) (store.Cursor, bool) {
	if values.Has("before_ts") != values.Has("before_seq") {
		q.bad("before_ts and before_seq must be supplied together")
		return store.Cursor{}, false
	}
	cursor := store.Cursor{}
	if values.Has("before_ts") {
		var err error
		cursor.TS, err = time.Parse(time.RFC3339Nano, values.Get("before_ts"))
		if err != nil || cursor.TS.IsZero() {
			q.bad("before_ts must be an RFC3339 timestamp")
			return cursor, false
		}
		cursor.Seq, err = strconv.ParseInt(values.Get("before_seq"), 10, 64)
		if err != nil || cursor.Seq < 1 {
			q.bad("before_seq must be a positive integer")
			return cursor, false
		}
	}
	return cursor, true
}

func validContentType(value string) bool {
	switch domain.Type(value) {
	case domain.TypeText, domain.TypeImage, domain.TypeVideo, domain.TypePTV, domain.TypeAudio, domain.TypePTT,
		domain.TypeDocument, domain.TypeSticker, domain.TypeLocation, domain.TypeLiveLocation, domain.TypeContact,
		domain.TypeContactArray, domain.TypePoll, domain.TypePollVote, domain.TypeEvent, domain.TypeGroupInvite,
		domain.TypeAlbum, domain.TypeTemplate, domain.TypeInteractive, domain.TypeButtons, domain.TypeList,
		domain.TypeButtonReply, domain.TypePlaceholder, domain.TypeReaction, domain.TypeProtocol,
		domain.TypeUnsupported, domain.TypeUndecryptable:
		return true
	}
	return false
}

func (h *Handler) scan(q *request) {
	values, ok := q.query("from", "until", "sender_keys", "chat_key", "direction", "type", "kind", "limit", "before_ts", "before_seq")
	if !ok {
		return
	}
	from, fromErr := time.Parse(time.RFC3339Nano, values.Get("from"))
	until, untilErr := time.Parse(time.RFC3339Nano, values.Get("until"))
	if fromErr != nil || untilErr != nil || !from.Before(until) {
		q.bad("from and until must be RFC3339 timestamps with from before until")
		return
	}
	limit, ok := q.limit(values, 50, 200)
	if !ok {
		return
	}
	cursor, ok := q.scanCursor(values)
	if !ok {
		return
	}
	filter := store.ScanFilter{From: from, Until: until}
	if values.Has("sender_keys") {
		filter.SenderKeys = strings.Split(values.Get("sender_keys"), ",")
		if len(filter.SenderKeys) > 3 {
			q.bad("sender_keys accepts at most three exact identifiers")
			return
		}
		for _, key := range filter.SenderKeys {
			if !routingKey(key) {
				q.bad("sender_keys must contain nonempty identifiers of at most 512 bytes")
				return
			}
		}
	}
	chat := values.Get("chat_key")
	if values.Has("chat_key") && !routingKey(chat) {
		q.bad("chat_key must be nonempty and at most 512 bytes")
		return
	}
	if values.Has("direction") {
		direction := values.Get("direction")
		if direction != "incoming" && direction != "outgoing" {
			q.bad("direction must be incoming or outgoing")
			return
		}
		fromMe := direction == "outgoing"
		filter.FromMe = &fromMe
	}
	if values.Has("type") {
		if !validContentType(values.Get("type")) {
			q.bad("type must be a supported archive content type")
			return
		}
		filter.Type = domain.Type(values.Get("type"))
	}
	if values.Has("kind") {
		filter.Kind = domain.Kind(values.Get("kind"))
		if !filter.Kind.Valid() {
			q.bad("kind must be message, edit, delete or reaction")
			return
		}
	}
	device, ok := q.device(store.ActionRead)
	if !ok {
		return
	}
	id := uuid.MustParse(device.ID)
	if chat != "" {
		var err error
		filter.ChatKeys, err = h.Messages.SiblingKeys(q.r.Context(), q.actor.Tenant, id, chat)
		if err != nil {
			q.internal(err)
			return
		}
	}
	rows, err := h.Messages.Scan(q.r.Context(), q.actor.Tenant, id, filter, cursor, limit+1)
	if err != nil {
		q.internal(err)
		return
	}
	out := ScanPage{TenantID: q.actor.Tenant.String(), DeviceID: device.ID, From: from, Until: until, Messages: make([]ScanMessage, 0, min(len(rows), limit)), HasMore: len(rows) > limit}
	if out.HasMore {
		rows = rows[len(rows)-limit:]
		next := store.Before(rows)
		out.NextTS, out.NextSeq = &next.TS, next.Seq
	}
	for _, row := range rows {
		at := row.CreatedAt
		if row.TS != nil {
			at = *row.TS
		}
		out.Messages = append(out.Messages, ScanMessage{SealedMessage: wsapi.SealedMessageFromRow(row), OrderTS: at})
	}
	q.finish(out)
}
