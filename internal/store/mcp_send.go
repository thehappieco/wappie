package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/pg"
)

// Sending (docs/mcp-enclave.md §17): a content connection whose consent
// carries sending drafts messages for the person who consented to confirm in
// the console, and sends notes to the number's own chat.
//
// This server decides every draft and send on its own ledger, at the moment
// it is asked: the connection is live and not paused, the person who
// consented may still send on the number, the chat is one the connection may
// reach, and the limits hold. The ledger, mcp_outbound, records every draft,
// send and refusal and never a word of text: a draft's text travels sealed to
// the number's archive key, and a send's is handed to WhatsApp and archived
// like any other outbound message. The ledger forces row-level security, so
// everything here runs in the connection's tenant transaction.

// Sending modes, as mcp_connections.send_mode stores them.
const (
	SendModeDraft  = "draft"
	SendModeDirect = "direct"
)

// Ledger kinds: a draft for the console, an own-chat send, a direct send (S3).
const (
	OutboundDraft = "draft"
	OutboundSelf  = "self"
	OutboundSend  = "send"
)

// Ledger statuses. A draft waits pending until a person sends it (sending,
// then sent or uncertain), discards it, or it expires or its connection ends
// (revoked); a send starts sending. A refusal is written refused, with its
// code, and never changes.
const (
	OutboundPending   = "pending"
	OutboundSending   = "sending"
	OutboundSent      = "sent"
	OutboundUncertain = "uncertain"
	OutboundDiscarded = "discarded"
	OutboundExpired   = "expired"
	OutboundRevoked   = "revoked"
	OutboundRefused   = "refused"
)

// OutboundStatuses are every status a ledger row can be in.
var OutboundStatuses = []string{OutboundPending, OutboundSending, OutboundSent, OutboundUncertain,
	OutboundDiscarded, OutboundExpired, OutboundRevoked, OutboundRefused}

const (
	// DraftTTL is a draft's life: the image's DRAFT_TTL_MS.
	DraftTTL = 24 * time.Hour
	// maxRefusalsPerDay caps the refusals the ledger records per connection
	// in a rolling day; past it they are only counted in the log.
	maxRefusalsPerDay = 100
	// outboundRetention is how long a ledger row is kept.
	outboundRetention = 365 * 24 * time.Hour
	// staleSending is how long a send may stay in flight before the janitor
	// calls it uncertain: its request died with its process, and nobody
	// knows whether WhatsApp took it.
	staleSending = 10 * time.Minute
	// MaxPendingDraftsListed bounds the console's list of pending drafts,
	// which is also the image's DRAFTS_PENDING_MAX.
	MaxPendingDraftsListed = 20
	// MaxOutboundPage bounds a page of the ledger.
	MaxOutboundPage = 50
)

var (
	// ErrSendNotAllowed is a connection that may not draft or send right
	// now: its consent has no sending, it is paused, or the person who
	// consented may not send on the number.
	ErrSendNotAllowed = errors.New("store: this connection may not send now")
	// ErrChatNotEligible is a chat the connection may not reach: not a chat
	// of its numbers, a broadcast or a channel, or one where the other side
	// has never written.
	ErrChatNotEligible = errors.New("store: that chat is not eligible")
	// ErrGroupNotAllowed is a group, for a connection whose consent leaves
	// groups out.
	ErrGroupNotAllowed = errors.New("store: this connection does not send to groups")
	// ErrReplyNotFound is a reply to something that is not a message of the
	// same chat.
	ErrReplyNotFound = errors.New("store: the reply names no message of that chat")
	// ErrTextNotAllowed is a text the rules refuse.
	ErrTextNotAllowed = errors.New("store: the text is not allowed")
	// ErrDraftExists is a draft id already in the ledger.
	ErrDraftExists = errors.New("store: that draft already exists")
	// ErrDraftState is a draft that is no longer waiting: sent, discarded,
	// expired or ended with its connection.
	ErrDraftState = errors.New("store: the draft is not waiting")
	// ErrDraftMismatch is a confirmation for another number or chat than
	// the draft's.
	ErrDraftMismatch = errors.New("store: the draft is for another chat")
	// ErrOutboundNotFound is a draft or ledger row the asker may not see.
	ErrOutboundNotFound = errors.New("store: no such draft")
)

// RateLimitError is a limit that refused a draft or a send, with the moment
// the refused request would first pass.
type RateLimitError struct {
	RetryAt time.Time
}

func (e *RateLimitError) Error() string {
	return "store: rate limited until " + e.RetryAt.UTC().Format(time.RFC3339)
}

// SendLimits bound drafts and sends; the server's configuration, each at most
// the reader image's own.
type SendLimits struct {
	DraftsPerHour, DraftsPending int
	PerDay, PerChatPerDay        int
	MinInterval                  time.Duration
	TenantPerDay                 int
}

// SendConnection is what the send routes read of a connection before they
// act. The transaction that acts reads it again under the row's lock.
type SendConnection struct {
	ID         string
	TenantID   uuid.UUID
	APIKeyID   uuid.UUID
	CreatedBy  uuid.UUID
	ClientName string
	Status     string
	ExpiresAt  time.Time
	SendMode   string
	SendSelf   bool
	SendGroups bool
	SendPaused bool
}

// SendConnection reads one of a reader's connections for a send route.
// Another reader's is ErrMCPConnectionNotFound.
func (m *MCPConnections) SendConnection(ctx context.Context, reader, id string) (SendConnection, error) {
	c := SendConnection{ID: id}
	err := m.pool.QueryRow(ctx, `SELECT tenant_id, api_key_id, created_by, client_name, status, expires_at,
		coalesce(send_mode, ''), send_self, send_groups, send_paused_at IS NOT NULL
		FROM mcp_connections WHERE id=$1 AND reader=$2`, id, reader).
		Scan(&c.TenantID, &c.APIKeyID, &c.CreatedBy, &c.ClientName, &c.Status, &c.ExpiresAt,
			&c.SendMode, &c.SendSelf, &c.SendGroups, &c.SendPaused)
	if errors.Is(err, pgx.ErrNoRows) {
		return SendConnection{}, ErrMCPConnectionNotFound
	}
	if err != nil {
		return SendConnection{}, fmt.Errorf("store: read a sending connection: %w", err)
	}
	return c, nil
}

// HoldsAPIKey reports whether a key is, or was, a connection's: the
// WebSocket refuses such a key every frame that sends or manages.
func (m *MCPConnections) HoldsAPIKey(ctx context.Context, key uuid.UUID) (bool, error) {
	var held bool
	if err := m.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_connections WHERE api_key_id=$1)`, key).Scan(&held); err != nil {
		return false, fmt.Errorf("store: is the key a connection's: %w", err)
	}
	return held, nil
}

// lockedSending is a connection read under its row lock, in its tenant's
// transaction.
type lockedSending struct {
	status     string
	expiresAt  time.Time
	apiKey     uuid.UUID
	createdBy  uuid.UUID
	sendMode   string
	sendSelf   bool
	sendGroups bool
	paused     bool
}

// lockSendingTx locks a connection's row for the rest of the transaction:
// two drafts or sends of one connection pass the limits one after the other.
func lockSendingTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, id string) (lockedSending, error) {
	var l lockedSending
	err := tx.QueryRow(ctx, `SELECT status, expires_at, api_key_id, created_by, coalesce(send_mode, ''), send_self, send_groups,
		send_paused_at IS NOT NULL FROM mcp_connections WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, id, tenant).
		Scan(&l.status, &l.expiresAt, &l.apiKey, &l.createdBy, &l.sendMode, &l.sendSelf, &l.sendGroups, &l.paused)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedSending{}, ErrMCPConnectionNotFound
	}
	return l, err
}

// liveForSending is the connection's own state for a draft or a send, in
// the order the routes answer it: a connection that is not active inside
// its lifetime is ErrMCPConnectionState, one whose key is no longer the one
// the reader presented is not found, and one that has no sending or is
// paused is ErrSendNotAllowed.
func (l lockedSending) liveForSending(key uuid.UUID) error {
	switch {
	case l.status != statusActive || !l.expiresAt.After(time.Now()):
		return ErrMCPConnectionState
	case l.apiKey != key:
		return ErrMCPConnectionNotFound
	case l.sendMode == "" || l.paused:
		return ErrSendNotAllowed
	}
	return nil
}

// sendPermittedTx is the permission on every draft, send and confirmation
// (docs/mcp-enclave.md §17.5): the person who consented is an active user
// with an active, unexpired membership and send permission on the number,
// now. The same rule access.Allows applies to a person, read in the caller's
// transaction. The connection's service account is never asked.
func sendPermittedTx(ctx context.Context, tx pgx.Tx, tenant, user, device uuid.UUID) (bool, error) {
	p, err := devicePermissionTx(ctx, tx, tenant, user, device)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return p.Allows(ActionSend), nil
}

// requireSendPermittedTx is sendPermittedTx for the routes: a person who
// may not send is ErrSendNotAllowed.
func requireSendPermittedTx(ctx context.Context, tx pgx.Tx, tenant, user, device uuid.UUID) error {
	ok, err := sendPermittedTx(ctx, tx, tenant, user, device)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSendNotAllowed
	}
	return nil
}

// ownChatsTx are the keys of a number's own chat: its account by LID and by
// phone number, the device suffix dropped.
func ownChatsTx(ctx context.Context, tx pgx.Tx, device uuid.UUID) (lid, pn string, err error) {
	var rawLID, rawPN string
	err = tx.QueryRow(ctx, `SELECT coalesce(lid, ''), coalesce(pn, '') FROM devices WHERE id=$1`, device).Scan(&rawLID, &rawPN)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	if j := parseJID(rawLID); j.User != "" {
		lid = types.NewJID(j.User, types.HiddenUserServer).String()
	}
	if j := parseJID(rawPN); j.User != "" {
		pn = types.NewJID(j.User, types.DefaultUserServer).String()
	}
	return lid, pn, nil
}

// siblingChats is the SQL for a chat's keys: the chat itself and, for a
// person, the other halves of the same person (the one addressed by phone
// number and the one by LID), as the archive folds them. $1 is the device and
// $2 the chat key.
const siblingChats = `SELECT c.chat_key FROM chats c WHERE c.device_id = $1 AND (c.chat_key = $2 OR (
	NOT c.is_group AND c.chat_pn IS NOT NULL
	AND c.chat_pn = (SELECT chat_pn FROM chats WHERE device_id = $1 AND chat_key = $2 AND NOT is_group)))`

// chatEligibleTx applies docs/mcp-enclave.md §17.5 to a chat of one of the
// connection's numbers: a chats row exists; it is no broadcast and no
// channel; it is the number's own chat, or the other side has written in it
// at least once; and a group needs groups. The caller has checked that the
// device is one of the connection's.
func chatEligibleTx(ctx context.Context, tx pgx.Tx, device uuid.UUID, chatKey string, groups bool) error {
	if chatKey == "status@broadcast" || strings.HasSuffix(chatKey, "@broadcast") || strings.HasSuffix(chatKey, "@newsletter") {
		return ErrChatNotEligible
	}
	var group bool
	err := tx.QueryRow(ctx, `SELECT is_group FROM chats WHERE device_id=$1 AND chat_key=$2`, device, chatKey).Scan(&group)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrChatNotEligible
	}
	if err != nil {
		return err
	}
	lid, pn, err := ownChatsTx(ctx, tx, device)
	if err != nil {
		return err
	}
	if !group && (chatKey == lid || chatKey == pn) {
		return nil
	}
	var inbound bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM messages m WHERE m.device_id = $1 AND NOT m.is_from_me
		AND m.kind = 'message' AND m.chat_key IN (`+siblingChats+`))`, device, chatKey).Scan(&inbound); err != nil {
		return err
	}
	if !inbound {
		return ErrChatNotEligible
	}
	if group && !groups {
		return ErrGroupNotAllowed
	}
	return nil
}

// replyFoundTx reports whether a reply's target is a message of the chat.
func replyFoundTx(ctx context.Context, tx pgx.Tx, device uuid.UUID, chatKey string, reply uuid.UUID) (bool, error) {
	var found bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM messages m WHERE m.uid = $3 AND m.device_id = $1
		AND m.kind = 'message' AND m.chat_key IN (`+siblingChats+`))`, device, chatKey, reply).Scan(&found)
	return found, err
}

// NewDraft is a draft the enclave sealed: its id, where it goes, and the
// envelope that only the number's archive key opens.
type NewDraft struct {
	ID      uuid.UUID
	Device  uuid.UUID
	ChatKey string
	ReplyTo *uuid.UUID
	Epoch   int
	Sealed  []byte
}

// CreateDraft records a draft for the person who consented to confirm, in
// the order of docs/mcp-enclave.md §17.7: the connection is active, not
// paused and has sending (ErrMCPConnectionState, ErrSendNotAllowed); the
// person who consented may send on the number (ErrSendNotAllowed); the chat
// and the reply are ones the connection may reach (ErrChatNotEligible,
// ErrGroupNotAllowed, ErrReplyNotFound); and, under the connection's lock,
// the drafts waiting and those of the last hour are below the limits
// (*RateLimitError). key is the API key the reader presented, which must
// still be the connection's. It returns when the draft expires.
func (m *MCPConnections) CreateDraft(ctx context.Context, conn SendConnection, key uuid.UUID, in NewDraft, limits SendLimits) (time.Time, error) {
	var expires time.Time
	err := pg.InTenantTx(ctx, m.pool, conn.TenantID.String(), func(tx pgx.Tx) error {
		l, err := lockSendingTx(ctx, tx, conn.TenantID, conn.ID)
		if err != nil {
			return err
		}
		if err := l.liveForSending(key); err != nil {
			return err
		}
		if err := requireSendPermittedTx(ctx, tx, conn.TenantID, l.createdBy, in.Device); err != nil {
			return err
		}
		devices, err := keyDevicesTx(ctx, tx, l.apiKey)
		if err != nil {
			return err
		}
		if !devices[in.Device] {
			return ErrChatNotEligible
		}
		if err := chatEligibleTx(ctx, tx, in.Device, in.ChatKey, l.sendGroups); err != nil {
			return err
		}
		if in.ReplyTo != nil {
			found, err := replyFoundTx(ctx, tx, in.Device, in.ChatKey, *in.ReplyTo)
			if err != nil {
				return err
			}
			if !found {
				return ErrReplyNotFound
			}
		}
		if err := draftLimitsTx(ctx, tx, conn.ID, limits); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO mcp_outbound
			(id, tenant_id, connection_id, device_id, chat_key, reply_to_uid, kind, status, sealed, epoch, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'draft', 'pending', $7, $8, now() + $9::interval) RETURNING expires_at`,
			in.ID, conn.TenantID, conn.ID, in.Device, in.ChatKey, in.ReplyTo, in.Sealed, in.Epoch, DraftTTL).Scan(&expires)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDraftExists
		}
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	return expires, nil
}

// draftLimitsTx counts a connection's drafts, under its lock: those waiting,
// and those created in the last hour. A refusal is not a draft.
func draftLimitsTx(ctx context.Context, tx pgx.Tx, connection string, limits SendLimits) error {
	var pending, lastHour int
	if err := tx.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE status = 'pending' AND expires_at > now()),
		count(*) FILTER (WHERE created_at > now() - interval '1 hour')
		FROM mcp_outbound WHERE connection_id = $1 AND kind = 'draft' AND status <> 'refused'`, connection).
		Scan(&pending, &lastHour); err != nil {
		return err
	}
	if pending >= limits.DraftsPending {
		// A place frees when the soonest of the drafts beyond the limit
		// expires; a person deciding one frees it sooner.
		var at time.Time
		if err := tx.QueryRow(ctx, `SELECT expires_at FROM mcp_outbound
			WHERE connection_id = $1 AND kind = 'draft' AND status = 'pending' AND expires_at > now()
			ORDER BY expires_at OFFSET $2 LIMIT 1`, connection, pending-limits.DraftsPending).Scan(&at); err != nil {
			return err
		}
		return &RateLimitError{RetryAt: at}
	}
	if lastHour >= limits.DraftsPerHour {
		var at time.Time
		if err := tx.QueryRow(ctx, `SELECT created_at + interval '1 hour' FROM mcp_outbound
			WHERE connection_id = $1 AND kind = 'draft' AND status <> 'refused' AND created_at > now() - interval '1 hour'
			ORDER BY created_at OFFSET $2 LIMIT 1`, connection, lastHour-limits.DraftsPerHour).Scan(&at); err != nil {
			return err
		}
		return &RateLimitError{RetryAt: at}
	}
	return nil
}

// Refusal is one refusal for the ledger: a draft or a send the enclave or
// this server did not make, and why. ChatKey is empty for an own-chat send.
// ClientRef, when set, binds a refused send to the reference it was asked
// under, so asking again answers the same refusal.
type Refusal struct {
	Kind      string
	Device    uuid.UUID
	ChatKey   string
	Code      string
	ClientRef string
}

// RecordRefusal writes a refusal to a connection's ledger, within the cap of
// a hundred a rolling day; past the cap it writes nothing and reports false.
// A number that is not the connection's is ErrChatNotEligible. The
// connection's lock keeps the count honest under concurrency.
func (m *MCPConnections) RecordRefusal(ctx context.Context, tenant uuid.UUID, connection string, r Refusal) (bool, error) {
	recorded := false
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		l, err := lockSendingTx(ctx, tx, tenant, connection)
		if err != nil {
			return err
		}
		devices, err := keyDevicesTx(ctx, tx, l.apiKey)
		if err != nil {
			return err
		}
		if !devices[r.Device] {
			return ErrChatNotEligible
		}
		var today int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_outbound
			WHERE connection_id = $1 AND status = 'refused' AND created_at > now() - interval '1 day'`, connection).Scan(&today); err != nil {
			return err
		}
		if today >= maxRefusalsPerDay {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mcp_outbound (id, tenant_id, connection_id, device_id, chat_key, kind, status, code, client_ref, decided_at)
			VALUES (uuidv7(), $1, $2, $3, NULLIF($4, ''), $5, 'refused', $6, NULLIF($7, ''), now())`,
			tenant, connection, r.Device, r.ChatKey, r.Kind, r.Code, r.ClientRef); err != nil {
			return err
		}
		recorded = true
		return nil
	})
	if errors.Is(err, ErrChatNotEligible) {
		return false, err
	}
	if err != nil {
		return false, fmt.Errorf("store: record a refusal: %w", err)
	}
	return recorded, nil
}

// NewSend is a send the reader asked for: an own-chat note (OutboundSelf) in
// S0. The chat is this server's to work out, never the reader's. TextOK is
// the text rules' verdict, checked in its place in the order.
type NewSend struct {
	Kind      string
	Device    uuid.UUID
	ClientRef string
	TextOK    bool
}

// StartedSend is a send the ledger took: its id and the chat it goes to.
type StartedSend struct {
	ID      uuid.UUID
	ChatKey string
}

// StartSend records a send before it leaves, in the order of
// docs/mcp-enclave.md §17.7: the connection is active, not paused, has
// sending and the own chat (ErrMCPConnectionState, ErrSendNotAllowed); the
// person who consented may send on the number (ErrSendNotAllowed); the
// number has an own chat by phone number (ErrChatNotEligible); the text
// passed (ErrTextNotAllowed); then, under the connection's lock, a
// reference already recorded answers what was recorded (prior, with no
// error), and the connection's sends in the rolling day, the interval since
// its last send and the workspace's sends in the rolling day are below the
// limits (*RateLimitError), the last counted under a lock of the workspace
// so two connections cannot pass it together. The row is written sending.
func (m *MCPConnections) StartSend(ctx context.Context, conn SendConnection, key uuid.UUID, in NewSend, limits SendLimits) (started StartedSend, prior *Outbound, err error) {
	if in.Kind != OutboundSelf {
		return StartedSend{}, nil, ErrSendNotAllowed
	}
	err = pg.InTenantTx(ctx, m.pool, conn.TenantID.String(), func(tx pgx.Tx) error {
		l, err := lockSendingTx(ctx, tx, conn.TenantID, conn.ID)
		if err != nil {
			return err
		}
		if err := l.liveForSending(key); err != nil {
			return err
		}
		if !l.sendSelf {
			return ErrSendNotAllowed
		}
		if err := requireSendPermittedTx(ctx, tx, conn.TenantID, l.createdBy, in.Device); err != nil {
			return err
		}
		devices, err := keyDevicesTx(ctx, tx, l.apiKey)
		if err != nil {
			return err
		}
		if !devices[in.Device] {
			return ErrChatNotEligible
		}
		_, pn, err := ownChatsTx(ctx, tx, in.Device)
		if err != nil {
			return err
		}
		if pn == "" {
			return ErrChatNotEligible
		}
		if !in.TextOK {
			return ErrTextNotAllowed
		}
		recorded, err := outboundByRefTx(ctx, tx, conn.ID, in.ClientRef)
		if err != nil || recorded != nil {
			prior = recorded
			return err
		}
		if err := sendLimitsTx(ctx, tx, conn.TenantID, conn.ID, limits); err != nil {
			return err
		}
		started.ChatKey = pn
		return tx.QueryRow(ctx, `INSERT INTO mcp_outbound (id, tenant_id, connection_id, device_id, chat_key, kind, status, client_ref)
			VALUES (uuidv7(), $1, $2, $3, $4, $5, 'sending', $6) RETURNING id`,
			conn.TenantID, conn.ID, in.Device, pn, in.Kind, in.ClientRef).Scan(&started.ID)
	})
	if err != nil {
		return StartedSend{}, nil, err
	}
	return started, prior, nil
}

// counted is the SQL of the sends the limits count: own-chat and direct
// sends that left, or may have. A refusal did not.
const counted = `kind IN ('self', 'send') AND status IN ('sending', 'sent', 'uncertain')`

// sendLimitsTx checks a connection's send limits and the workspace's, under
// the connection's lock and then the workspace's.
func sendLimitsTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, connection string, limits SendLimits) error {
	var today int
	var last *time.Time
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE created_at > now() - interval '1 day'), max(created_at)
		FROM mcp_outbound WHERE connection_id = $1 AND `+counted, connection).Scan(&today, &last); err != nil {
		return err
	}
	if today >= limits.PerDay {
		var at time.Time
		if err := tx.QueryRow(ctx, `SELECT created_at + interval '1 day' FROM mcp_outbound
			WHERE connection_id = $1 AND `+counted+` AND created_at > now() - interval '1 day'
			ORDER BY created_at OFFSET $2 LIMIT 1`, connection, today-limits.PerDay).Scan(&at); err != nil {
			return err
		}
		return &RateLimitError{RetryAt: at}
	}
	if last != nil {
		var wait bool
		var at time.Time
		if err := tx.QueryRow(ctx, `SELECT $1::timestamptz + $2::interval > now(), $1::timestamptz + $2::interval`,
			*last, limits.MinInterval).Scan(&wait, &at); err != nil {
			return err
		}
		if wait {
			return &RateLimitError{RetryAt: at}
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mcp_send:' || $1::text, 0))`, tenant); err != nil {
		return err
	}
	var workspace int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_outbound
		WHERE tenant_id = $1 AND `+counted+` AND created_at > now() - interval '1 day'`, tenant).Scan(&workspace); err != nil {
		return err
	}
	if workspace >= limits.TenantPerDay {
		var at time.Time
		if err := tx.QueryRow(ctx, `SELECT created_at + interval '1 day' FROM mcp_outbound
			WHERE tenant_id = $1 AND `+counted+` AND created_at > now() - interval '1 day'
			ORDER BY created_at OFFSET $2 LIMIT 1`, tenant, workspace-limits.TenantPerDay).Scan(&at); err != nil {
			return err
		}
		return &RateLimitError{RetryAt: at}
	}
	return nil
}

// SendOutcome is how a send ended: sent (with the archived message's uid,
// nil when archiving failed, and WhatsApp's id and time), uncertain, or
// refused with a code (a number that is not connected).
type SendOutcome struct {
	Status     string
	Code       string
	MessageUID *uuid.UUID
	WAID       string
	At         time.Time
}

// FinishSend records how a send ended. Only a send still in flight is
// changed: the ledger never rewrites an outcome.
func (m *MCPConnections) FinishSend(ctx context.Context, tenant, id uuid.UUID, out SendOutcome) error {
	return pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_outbound SET status = $3, code = NULLIF($4, ''), message_uid = $5, wa_id = NULLIF($6, ''),
			decided_at = $7 WHERE id = $1 AND tenant_id = $2 AND status = 'sending'`,
			id, tenant, out.Status, out.Code, out.MessageUID, out.WAID, out.At)
		return err
	})
}

// Outbound is one ledger row.
type Outbound struct {
	ID           uuid.UUID
	ConnectionID string
	ClientName   string
	Kind         string
	Status       string
	Code         string
	DeviceID     uuid.UUID
	ChatKey      string
	ReplyTo      *uuid.UUID
	Epoch        int
	Sealed       []byte
	ClientRef    string
	Edited       bool
	DecidedBy    *uuid.UUID
	MessageUID   *uuid.UUID
	WAID         string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	DecidedAt    *time.Time
}

// outboundColumns read an Outbound, joined with its connection as c. A draft
// still pending past its expiry reads as expired, and without its envelope,
// before the janitor has written it.
const outboundColumns = `o.id, o.connection_id::text, c.client_name, o.kind,
	CASE WHEN o.status = 'pending' AND o.expires_at <= now() THEN 'expired' ELSE o.status END,
	coalesce(o.code, ''), o.device_id, coalesce(o.chat_key, ''), o.reply_to_uid, coalesce(o.epoch, 0),
	CASE WHEN o.status = 'pending' AND o.expires_at > now() THEN o.sealed END,
	coalesce(o.client_ref, ''), o.edited, o.decided_by, o.message_uid, coalesce(o.wa_id, ''),
	o.created_at, o.expires_at, o.decided_at`

func scanOutbound(s interface{ Scan(...any) error }) (Outbound, error) {
	var o Outbound
	err := s.Scan(&o.ID, &o.ConnectionID, &o.ClientName, &o.Kind, &o.Status, &o.Code, &o.DeviceID, &o.ChatKey, &o.ReplyTo,
		&o.Epoch, &o.Sealed, &o.ClientRef, &o.Edited, &o.DecidedBy, &o.MessageUID, &o.WAID, &o.CreatedAt, &o.ExpiresAt, &o.DecidedAt)
	return o, err
}

// outboundByRefTx is the row a connection recorded under a reference, or nil.
func outboundByRefTx(ctx context.Context, tx pgx.Tx, connection, ref string) (*Outbound, error) {
	o, err := scanOutbound(tx.QueryRow(ctx, `SELECT `+outboundColumns+` FROM mcp_outbound o
		JOIN mcp_connections c ON c.id = o.connection_id WHERE o.connection_id = $1 AND o.client_ref = $2`, connection, ref))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// OutboundCursor is where a page of the ledger ends: the last row's time
// and id, newest first.
type OutboundCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

// OutboundQuery selects a page of a connection's ledger, newest first.
type OutboundQuery struct {
	Limit  int
	Before *OutboundCursor
	// Status and Device narrow the page; empty and nil take every one.
	Status string
	Device *uuid.UUID
}

// ListOutbound is a page of a connection's ledger, newest first, and whether
// more rows follow it. The caller has decided who may read it.
func (m *MCPConnections) ListOutbound(ctx context.Context, tenant uuid.UUID, connection string, q OutboundQuery) ([]Outbound, bool, error) {
	if q.Limit < 1 || q.Limit > MaxOutboundPage || q.Status != "" && !slices.Contains(OutboundStatuses, q.Status) {
		return nil, false, fmt.Errorf("store: not a ledger query: %+v", q)
	}
	var out []Outbound
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		var beforeAt *time.Time
		var beforeID *uuid.UUID
		if q.Before != nil {
			beforeAt, beforeID = &q.Before.CreatedAt, &q.Before.ID
		}
		rows, err := tx.Query(ctx, `SELECT `+outboundColumns+` FROM mcp_outbound o
			JOIN mcp_connections c ON c.id = o.connection_id
			WHERE o.connection_id = $1
			  AND ($2 = '' OR (CASE WHEN o.status = 'pending' AND o.expires_at <= now() THEN 'expired' ELSE o.status END) = $2)
			  AND ($3::uuid IS NULL OR o.device_id = $3)
			  AND ($4::timestamptz IS NULL OR (o.created_at, o.id) < ($4, $5::uuid))
			ORDER BY o.created_at DESC, o.id DESC LIMIT $6`,
			connection, q.Status, q.Device, beforeAt, beforeID, q.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			o, err := scanOutbound(rows)
			if err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, fmt.Errorf("store: list the ledger: %w", err)
	}
	more := len(out) > q.Limit
	if more {
		out = out[:q.Limit]
	}
	return out, more, nil
}

// ---------------------------------------------------------------------------
// The console: the person who consented, and the workspace's managers
// ---------------------------------------------------------------------------

// Draft is one draft for the person who consented to its connection; for
// anyone else it is ErrOutboundNotFound, whatever they may otherwise see.
func (m *MCPConnections) Draft(ctx context.Context, tenant, user, id uuid.UUID) (Outbound, error) {
	var o Outbound
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		o, err = scanOutbound(tx.QueryRow(ctx, `SELECT `+outboundColumns+` FROM mcp_outbound o
			JOIN mcp_connections c ON c.id = o.connection_id
			WHERE o.id = $1 AND o.kind = 'draft' AND c.tenant_id = $2 AND c.created_by = $3`, id, tenant, user))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Outbound{}, ErrOutboundNotFound
	}
	if err != nil {
		return Outbound{}, fmt.Errorf("store: read a draft: %w", err)
	}
	return o, nil
}

// connectionReaderTx reads who consented to a connection of the workspace
// and the asker's role in it. ErrMCPConnectionNotFound for another
// workspace's or an unknown id.
func connectionReaderTx(ctx context.Context, tx pgx.Tx, tenant, user uuid.UUID, connection string) (createdBy uuid.UUID, role string, err error) {
	err = tx.QueryRow(ctx, `SELECT created_by FROM mcp_connections WHERE id = $1 AND tenant_id = $2`, connection, tenant).Scan(&createdBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrMCPConnectionNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	err = tx.QueryRow(ctx, `SELECT m.role FROM workspace_memberships m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active' AND u.status = 'active'
		  AND (m.expires_at IS NULL OR m.expires_at > now())`, tenant, user).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return createdBy, "", nil
	}
	return createdBy, role, err
}

// PendingDrafts are a connection's drafts still waiting, oldest first, at
// most MaxPendingDraftsListed, for the person who consented; anyone else in
// the workspace is ErrMembershipForbidden.
func (m *MCPConnections) PendingDrafts(ctx context.Context, tenant, user uuid.UUID, connection string) ([]Outbound, error) {
	out := []Outbound{}
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		createdBy, _, err := connectionReaderTx(ctx, tx, tenant, user, connection)
		if err != nil {
			return err
		}
		if createdBy != user {
			return ErrMembershipForbidden
		}
		rows, err := tx.Query(ctx, `SELECT `+outboundColumns+` FROM mcp_outbound o
			JOIN mcp_connections c ON c.id = o.connection_id
			WHERE o.connection_id = $1 AND o.kind = 'draft' AND o.status = 'pending' AND o.expires_at > now()
			ORDER BY o.created_at, o.id LIMIT $2`, connection, MaxPendingDraftsListed)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			o, err := scanOutbound(rows)
			if err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// DiscardDraft throws a waiting draft away, text and all, for the person who
// consented to its connection: ErrOutboundNotFound for anyone else, and
// ErrDraftState for a draft that is no longer waiting. It returns the
// draft's connection.
func (m *MCPConnections) DiscardDraft(ctx context.Context, tenant, user, id uuid.UUID) (connection string, err error) {
	err = pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		var status string
		var expires *time.Time
		err := tx.QueryRow(ctx, `SELECT o.status, o.expires_at, o.connection_id::text FROM mcp_outbound o
			JOIN mcp_connections c ON c.id = o.connection_id
			WHERE o.id = $1 AND o.kind = 'draft' AND c.tenant_id = $2 AND c.created_by = $3 FOR UPDATE OF o`, id, tenant, user).
			Scan(&status, &expires, &connection)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOutboundNotFound
		}
		if err != nil {
			return err
		}
		if status != OutboundPending || expires == nil || !expires.After(time.Now()) {
			return ErrDraftState
		}
		_, err = tx.Exec(ctx, `UPDATE mcp_outbound SET status = 'discarded', sealed = NULL, decided_by = $2, decided_at = now()
			WHERE id = $1`, id, user)
		return err
	})
	return connection, err
}

// ConsoleOutbound is a page of a connection's ledger for the console: the
// person who consented, an owner or an admin; any other member is
// ErrMembershipForbidden.
func (m *MCPConnections) ConsoleOutbound(ctx context.Context, tenant, user uuid.UUID, connection string, q OutboundQuery) ([]Outbound, bool, error) {
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		createdBy, role, err := connectionReaderTx(ctx, tx, tenant, user, connection)
		if err != nil {
			return err
		}
		if createdBy != user && role != "owner" && role != "admin" {
			return ErrMembershipForbidden
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return m.ListOutbound(ctx, tenant, connection, q)
}

// SetSendPaused switches a connection's pause. The person who consented, an
// owner or an admin may pause it; only the person who consented may take the
// pause off (ErrMembershipForbidden). The connection must be live and have
// sending (ErrMCPConnectionState).
func (m *MCPConnections) SetSendPaused(ctx context.Context, tenant, user uuid.UUID, connection string, paused bool) error {
	return pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		createdBy, role, err := connectionReaderTx(ctx, tx, tenant, user, connection)
		if err != nil {
			return err
		}
		switch {
		case createdBy == user:
		case paused && (role == "owner" || role == "admin"):
		default:
			return ErrMembershipForbidden
		}
		l, err := lockSendingTx(ctx, tx, tenant, connection)
		if err != nil {
			return err
		}
		if !liveStatus(l.status) || !l.expiresAt.After(time.Now()) || l.sendMode == "" {
			return ErrMCPConnectionState
		}
		_, err = tx.Exec(ctx, `UPDATE mcp_connections
			SET send_paused_at = CASE WHEN $3 THEN coalesce(send_paused_at, now()) END
			WHERE id = $1 AND tenant_id = $2`, connection, tenant, paused)
		return err
	})
}

// OutboundMessage says which connection sent an archived message.
type OutboundMessage struct {
	MessageUID   uuid.UUID
	ConnectionID string
	ClientName   string
	Kind         string
}

// OutboundMessages are the archived messages of one number, among uids,
// that a connection sent or whose draft a person confirmed. The caller has
// checked that the asker reads the number.
func (m *MCPConnections) OutboundMessages(ctx context.Context, tenant, device uuid.UUID, uids []uuid.UUID) ([]OutboundMessage, error) {
	out := []OutboundMessage{}
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT o.message_uid, o.connection_id::text, c.client_name, o.kind
			FROM mcp_outbound o JOIN mcp_connections c ON c.id = o.connection_id
			WHERE o.tenant_id = $1 AND o.device_id = $2 AND o.message_uid = ANY($3)
			ORDER BY o.message_uid`, tenant, device, uids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o OutboundMessage
			if err := rows.Scan(&o.MessageUID, &o.ConnectionID, &o.ClientName, &o.Kind); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: which messages a connection sent: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Confirmation, over the WebSocket
// ---------------------------------------------------------------------------

// ClaimedDraft is a draft a person is sending: its connection, for the log.
type ClaimedDraft struct {
	ID           uuid.UUID
	ConnectionID string
}

// ClaimDraft takes a waiting draft for the person sending it, in one
// transaction under the draft's lock (docs/mcp-enclave.md §17.7a): it must
// be the person who consented to the draft's connection
// (ErrOutboundNotFound otherwise, whoever else asks); the draft is waiting
// (ErrDraftState); the connection is live, has sending, is not paused and
// sendAllowed says its workspace may send (ErrSendNotAllowed); the frame
// names the draft's number and chat (ErrDraftMismatch); and the person may
// send on the number now (ErrMembershipForbidden). The draft is then sending,
// its envelope gone, so a second confirmation finds it taken.
func (m *MCPConnections) ClaimDraft(ctx context.Context, tenant, user, id, device uuid.UUID, chat string, sendAllowed func(uuid.UUID) bool) (ClaimedDraft, error) {
	claimed := ClaimedDraft{ID: id}
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		var status, chatKey, connStatus, mode string
		var expires *time.Time
		var draftDevice, createdBy uuid.UUID
		var connExpires time.Time
		var paused bool
		err := tx.QueryRow(ctx, `SELECT o.status, o.expires_at, o.device_id, coalesce(o.chat_key, ''), o.connection_id::text,
			c.created_by, c.status, c.expires_at, coalesce(c.send_mode, ''), c.send_paused_at IS NOT NULL
			FROM mcp_outbound o JOIN mcp_connections c ON c.id = o.connection_id
			WHERE o.id = $1 AND o.kind = 'draft' AND c.tenant_id = $2 FOR UPDATE OF o`, id, tenant).
			Scan(&status, &expires, &draftDevice, &chatKey, &claimed.ConnectionID, &createdBy, &connStatus, &connExpires, &mode, &paused)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrOutboundNotFound
		case err != nil:
			return err
		case createdBy != user:
			return ErrOutboundNotFound
		case status != OutboundPending || expires == nil || !expires.After(time.Now()):
			return ErrDraftState
		case !liveStatus(connStatus) || !connExpires.After(time.Now()) || mode == "" || paused || sendAllowed == nil || !sendAllowed(tenant):
			return ErrSendNotAllowed
		case device != draftDevice || chat != chatKey:
			return ErrDraftMismatch
		}
		ok, err := sendPermittedTx(ctx, tx, tenant, user, device)
		if err != nil {
			return err
		}
		if !ok {
			return ErrMembershipForbidden
		}
		_, err = tx.Exec(ctx, `UPDATE mcp_outbound SET status = 'sending', sealed = NULL, decided_by = $2 WHERE id = $1`, id, user)
		return err
	})
	if err != nil {
		return ClaimedDraft{}, err
	}
	return claimed, nil
}

// DraftOutcome is how a person's send of a draft ended.
type DraftOutcome struct {
	Status     string
	MessageUID *uuid.UUID
	WAID       string
	Edited     bool
	At         time.Time
}

// FinishDraft records how a claimed draft's send ended: sent or uncertain,
// and whether the person edited the text first (their console's word; this
// server never sees the draft's text).
func (m *MCPConnections) FinishDraft(ctx context.Context, tenant, id uuid.UUID, out DraftOutcome) error {
	return pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_outbound SET status = $3, message_uid = $4, wa_id = NULLIF($5, ''), edited = $6, decided_at = $7
			WHERE id = $1 AND tenant_id = $2 AND status = 'sending'`, id, tenant, out.Status, out.MessageUID, out.WAID, out.Edited, out.At)
		return err
	})
}

// ---------------------------------------------------------------------------
// The janitor
// ---------------------------------------------------------------------------

// SettledOutbound is what one janitor round did to the ledgers.
type SettledOutbound struct {
	// Expired are the drafts that ran out, and Uncertain the sends whose
	// request died in flight, as (connection, ledger id).
	Expired, Uncertain [][2]string
	// Deleted counts the rows past their retention.
	Deleted int64
}

// SettleMCPOutbound ages every workspace's ledger, one workspace at a time in
// its own transaction: a draft past its expiry becomes expired and loses its
// envelope; a send in flight for longer than any send takes becomes
// uncertain, since nobody knows whether it left; and rows written more than
// 365 days ago go.
func SettleMCPOutbound(ctx context.Context, pool *pgxpool.Pool) (SettledOutbound, error) {
	var out SettledOutbound
	// The ledger forces row-level security; the connections, which carry
	// none, name every workspace that can have one.
	rows, err := pool.Query(ctx, `SELECT DISTINCT tenant_id FROM mcp_connections WHERE kind = 'content' ORDER BY tenant_id`)
	if err != nil {
		return out, fmt.Errorf("store: settle the ledgers: %w", err)
	}
	var tenants []uuid.UUID
	for rows.Next() {
		var tenant uuid.UUID
		if err := rows.Scan(&tenant); err != nil {
			rows.Close()
			return out, fmt.Errorf("store: settle the ledgers: %w", err)
		}
		tenants = append(tenants, tenant)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("store: settle the ledgers: %w", err)
	}
	var errs []error
	for _, tenant := range tenants {
		var settled SettledOutbound
		err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			var err error
			if settled.Expired, err = settledRows(ctx, tx, `UPDATE mcp_outbound SET status = 'expired', sealed = NULL, decided_at = expires_at
				WHERE status = 'pending' AND expires_at <= now() RETURNING connection_id::text, id::text`); err != nil {
				return err
			}
			if settled.Uncertain, err = settledRows(ctx, tx, `UPDATE mcp_outbound SET status = 'uncertain', decided_at = now()
				WHERE status = 'sending' AND created_at < now() - $1::interval RETURNING connection_id::text, id::text`, staleSending); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `DELETE FROM mcp_outbound WHERE created_at < now() - $1::interval`, outboundRetention)
			settled.Deleted = tag.RowsAffected()
			return err
		})
		if err != nil {
			// One workspace failing must not keep the rest from settling.
			errs = append(errs, err)
			continue
		}
		out.Expired = append(out.Expired, settled.Expired...)
		out.Uncertain = append(out.Uncertain, settled.Uncertain...)
		out.Deleted += settled.Deleted
	}
	if err := errors.Join(errs...); err != nil {
		return out, fmt.Errorf("store: settle the ledgers: %w", err)
	}
	return out, nil
}

func settledRows(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([][2]string, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var pair [2]string
		if err := rows.Scan(&pair[0], &pair[1]); err != nil {
			return nil, err
		}
		out = append(out, pair)
	}
	return out, rows.Err()
}
