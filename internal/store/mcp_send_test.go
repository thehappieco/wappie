package store_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Sending (docs/mcp-enclave.md §17): a content connection given under
// consent version 3 drafts for the person who consented and sends notes to
// the number's own chat. The ledger forces row-level security, and these
// tests run as the same ordinary role as the rest (NOSUPERUSER, NOBYPASSRLS,
// checked by newMCPFixture): a path that forgot its tenant transaction reads
// and writes nothing, and fails here.

// Chats of the fixture's number, and its own identity.
const (
	friendChat    = "5511911111111@s.whatsapp.net"
	quietChat     = "5511922222222@s.whatsapp.net"
	sendGroupChat = "120363000000000001@g.us"
	ownPN         = "5511900000000@s.whatsapp.net"
	ownLID        = "224437861388494@lid"
)

// roomy are limits that stay out of the way of a test about something else.
var roomy = store.SendLimits{DraftsPerHour: 30, DraftsPending: 20, PerDay: 20, PerChatPerDay: 5, MinInterval: time.Microsecond, TenantPerDay: 1000}

type sendFixture struct {
	*contentFixture
	// messages in the chats, by chat key.
	inbound map[string]uuid.UUID
}

// newSendFixture is the content fixture with a number that knows its own
// account, and chats: one where the other side wrote, one where only this
// number did, a group where others wrote, and the number's own chat.
func newSendFixture(t *testing.T) *sendFixture {
	t.Helper()
	ctx := context.Background()
	f := &sendFixture{contentFixture: newContentFixture(t), inbound: map[string]uuid.UUID{}}
	pn, err := types.ParseJID("5511900000000:12@s.whatsapp.net")
	if err != nil {
		t.Fatal(err)
	}
	lid, err := types.ParseJID("224437861388494:12@lid")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewDevices(f.pool).SetIdentity(ctx, f.tenant.String(), f.device.String(), wa.Identity{PN: pn, LID: lid}); err != nil {
		t.Fatal(err)
	}
	f.inbound[friendChat] = f.message(ctx, t, f.device, friendChat, false, false)
	f.message(ctx, t, f.device, quietChat, false, true)
	f.inbound[sendGroupChat] = f.message(ctx, t, f.device, sendGroupChat, true, false)
	f.message(ctx, t, f.device, ownPN, false, true)
	f.message(ctx, t, f.device, ownLID, false, true)
	return f
}

// message archives one text in a chat, from the other side or from this
// number, and returns its uid.
func (f *sendFixture) message(ctx context.Context, t *testing.T, device uuid.UUID, chat string, group, fromMe bool) uuid.UUID {
	t.Helper()
	uid := uuid.New()
	if _, err := store.NewMessages(f.pool).Insert(ctx, store.InsertMessage{
		UID: uid, TenantID: f.tenant, DeviceID: device, WAID: "wa-" + uid.String(), ChatKey: chat, IsGroup: group,
		SenderKey: "5511933333333@s.whatsapp.net", IsFromMe: fromMe, Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1},
	}); err != nil {
		t.Fatal(err)
	}
	return uid
}

// sendingConsent records and activates a version-3 connection that drafts,
// with whatever else mutate sets, by actor.
func (f *sendFixture) sendingConsent(ctx context.Context, t *testing.T, actor uuid.UUID, mutate func(*store.CreateMCPConnection)) (store.SendConnection, uuid.UUID, contentConsent) {
	t.Helper()
	c := f.prepareContent(ctx, t, actor)
	c.in.ConsentVersion, c.in.SendMode = store.SendConsentVersion, store.SendModeDraft
	if mutate != nil {
		mutate(&c.in)
	}
	conn, err := f.conns.Create(ctx, f.tenant, actor, c.in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	sc, err := f.conns.SendConnection(ctx, "enclave", conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	k, err := f.keys.VerifyScoped(ctx, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return sc, k.ID, c
}

func withSelf(in *store.CreateMCPConnection)   { in.SendSelf = true }
func withGroups(in *store.CreateMCPConnection) { in.SendGroups = true }

// draft records a draft to a chat of the fixture's number.
func (f *sendFixture) draft(ctx context.Context, conn store.SendConnection, key uuid.UUID, chat string, limits store.SendLimits) (uuid.UUID, error) {
	id := uuid.New()
	_, err := f.conns.CreateDraft(ctx, conn, key, store.NewDraft{ID: id, Device: f.device, ChatKey: chat, Epoch: 1, Sealed: []byte("sealed draft")}, limits)
	return id, err
}

func newRef() string { return strings.ReplaceAll(uuid.NewString(), "-", "")[:22] }

// selfSend starts an own-chat send.
func (f *sendFixture) selfSend(ctx context.Context, conn store.SendConnection, key uuid.UUID, ref string, limits store.SendLimits) (store.StartedSend, *store.Outbound, error) {
	return f.conns.StartSend(ctx, conn, key, store.NewSend{Kind: store.OutboundSelf, Device: f.device, ClientRef: ref, TextOK: true}, limits)
}

// ledger reads a row of the ledger in the workspace's transaction.
func (f *sendFixture) ledger(ctx context.Context, t *testing.T, id uuid.UUID) (status string, sealed bool, code string) {
	t.Helper()
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, sealed IS NOT NULL, coalesce(code, '') FROM mcp_outbound WHERE id=$1`, id).Scan(&status, &sealed, &code)
	})
	return status, sealed, code
}

func (f *sendFixture) refusals(ctx context.Context, t *testing.T, connection string) []string {
	t.Helper()
	var codes []string
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT code FROM mcp_outbound WHERE connection_id=$1 AND status='refused' ORDER BY created_at, id`, connection)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var code string
			if err := rows.Scan(&code); err != nil {
				return err
			}
			codes = append(codes, code)
		}
		return rows.Err()
	})
	return codes
}

// ---------------------------------------------------------------------------

// Version 3 carries sending, and only it does; the store refuses anything
// else as a backstop behind the handler, and the migration's CHECK stands
// behind the store for every writer.
func TestCreateSendingConnection(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()

	conn, _, _ := f.sendingConsent(ctx, t, f.owner, func(in *store.CreateMCPConnection) { withSelf(in); withGroups(in); in.Media = true })
	got := f.row(ctx, t, conn.ID)
	if got.ConsentVersion != 3 || got.SendMode != store.SendModeDraft || !got.SendSelf || !got.SendGroups || !got.Media || got.SendPausedAt != nil || got.SendChats != 0 {
		t.Fatalf("listed = %+v", got)
	}
	for name, mutate := range map[string]func(*store.CreateMCPConnection){
		"version 3 without sending": func(in *store.CreateMCPConnection) { in.ConsentVersion = 3 },
		"sending on version 2":      func(in *store.CreateMCPConnection) { in.ConsentVersion, in.SendMode = 2, store.SendModeDraft },
		"sending on version 1":      func(in *store.CreateMCPConnection) { in.SendMode = store.SendModeDraft },
		"own chat alone":            func(in *store.CreateMCPConnection) { in.ConsentVersion, in.SendSelf = 2, true },
		"groups alone":              func(in *store.CreateMCPConnection) { in.SendGroups = true },
		"direct before S3":          func(in *store.CreateMCPConnection) { in.ConsentVersion, in.SendMode = 3, store.SendModeDirect },
		"not a mode":                func(in *store.CreateMCPConnection) { in.ConsentVersion, in.SendMode = 3, "broadcast" },
		"version 4":                 func(in *store.CreateMCPConnection) { in.ConsentVersion, in.SendMode = 4, store.SendModeDraft },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.prepareContent(ctx, t, f.owner)
			mutate(&c.in)
			if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	_, prefix := f.provisionalKey(ctx, t, "meta")
	meta := consent(prefix)
	meta.SendMode = store.SendModeDraft
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, meta); err == nil {
		t.Fatal("a metadata connection took sending")
	}
	// The service account may read only, in every mode: a version-3
	// consent whose account may send is refused like any other.
	c := f.prepareContent(ctx, t, f.owner)
	if err := f.users.SetDevicePermission(ctx, f.tenant, f.owner, store.DevicePermission{DeviceID: f.device, UserID: c.service, Read: true, Send: true}); err != nil {
		t.Fatal(err)
	}
	c.in.ConsentVersion, c.in.SendMode, c.in.SendSelf = 3, store.SendModeDraft, true
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
		t.Fatalf("a service account that may send was accepted: %v", err)
	}

	// The CHECK: sending only on content of version 3 or later, the pause
	// and the rest only with it.
	v2, _ := f.consentMedia(ctx, t, false)
	for name, sql := range map[string]string{
		"send on version 2":   `UPDATE mcp_connections SET send_mode='draft' WHERE id=$1`,
		"own chat on its own": `UPDATE mcp_connections SET send_self=true WHERE id=$1`,
		"pause without send":  `UPDATE mcp_connections SET send_paused_at=now() WHERE id=$1`,
	} {
		_, err := f.pool.Exec(ctx, sql, v2.ID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "mcp_connections_send_coherent" {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// The status carries the row's sending while the connection is live; the
// switches, and whether only an active answer sends, are the caller's. A
// renewal renews the key, never the consent.
func TestStatusAndRenewKeepSending(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, _, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	answer, err := f.conns.Status(ctx, "enclave", conn.ID, allowAll)
	if err != nil || answer.Status != "active" || answer.SendMode != store.SendModeDraft || !answer.SendSelf || answer.SendPaused {
		t.Fatalf("status = %+v %v", answer, err)
	}
	if err := f.conns.SetSendPaused(ctx, f.tenant, f.owner, conn.ID, true); err != nil {
		t.Fatal(err)
	}
	if answer, _ := f.conns.Status(ctx, "enclave", conn.ID, nil); answer.Status != "reseal" || answer.SendMode != store.SendModeDraft || !answer.SendPaused {
		t.Fatalf("paused, content off = %+v", answer)
	}
	next := f.prepareContent(ctx, t, f.owner)
	if _, err := f.conns.Renew(ctx, f.tenant, f.owner, conn.ID, store.RenewMCPConnection{
		KeyPrefix: next.prefix, ServiceUserID: next.service, ReaderKID: "abcdefabcdefabcd", ReaderPublicKey: next.publicKey,
	}); err != nil {
		t.Fatal(err)
	}
	if got := f.row(ctx, t, conn.ID); got.ConsentVersion != 3 || got.SendMode != store.SendModeDraft || !got.SendSelf || got.SendPausedAt == nil {
		t.Fatalf("after renewal = %+v", got)
	}
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID); err != nil {
		t.Fatal(err)
	}
	if answer, _ := f.conns.Status(ctx, "enclave", conn.ID, allowAll); answer.Status != "revoked" || answer.SendMode != "" || answer.SendSelf {
		t.Fatalf("revoked = %+v", answer)
	}
}

// Which chats a draft may go to (docs/mcp-enclave.md §17.5), and a reply.
func TestDraftEligibility(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	other, err := store.NewDevices(f.pool).Create(ctx, f.tenant.String(), "other", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	otherDevice := uuid.MustParse(other.ID)
	f.archiveKey(ctx, t, otherDevice, 1)
	f.ownerReads(ctx, t, f.owner, otherDevice)
	f.message(ctx, t, otherDevice, "5511944444444@s.whatsapp.net", false, false)
	// The other half of the friend, addressed by LID: the friend wrote under
	// the phone number, and the same person counts.
	half := "88888888888888@lid"
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE chats SET chat_pn=$2 WHERE device_id=$1 AND chat_key=$2`, f.device, friendChat); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO chats (tenant_id, device_id, chat_key, chat_pn, is_group) VALUES ($1, $2, $3, $4, false)`,
			f.tenant, f.device, half, friendChat)
		return err
	})
	for _, chat := range []string{"status@broadcast", "123456789@broadcast", "120363000000000009@newsletter"} {
		f.message(ctx, t, f.device, chat, false, false)
	}

	plain, plainKey, _ := f.sendingConsent(ctx, t, f.owner, nil)
	groups, groupsKey, _ := f.sendingConsent(ctx, t, f.owner, withGroups)
	for name, tc := range map[string]struct {
		conn   store.SendConnection
		key    uuid.UUID
		device uuid.UUID
		chat   string
		want   error
	}{
		"the other side wrote":           {plain, plainKey, f.device, friendChat, nil},
		"the other half of the person":   {plain, plainKey, f.device, half, nil},
		"only this number wrote":         {plain, plainKey, f.device, quietChat, store.ErrChatNotEligible},
		"no such chat":                   {plain, plainKey, f.device, "5511955555555@s.whatsapp.net", store.ErrChatNotEligible},
		"own chat by phone number":       {plain, plainKey, f.device, ownPN, nil},
		"own chat by LID":                {plain, plainKey, f.device, ownLID, nil},
		"status":                         {plain, plainKey, f.device, "status@broadcast", store.ErrChatNotEligible},
		"a broadcast list":               {plain, plainKey, f.device, "123456789@broadcast", store.ErrChatNotEligible},
		"a channel":                      {plain, plainKey, f.device, "120363000000000009@newsletter", store.ErrChatNotEligible},
		"a group without groups":         {plain, plainKey, f.device, sendGroupChat, store.ErrGroupNotAllowed},
		"a group with groups":            {groups, groupsKey, f.device, sendGroupChat, nil},
		"a chat on another number":       {plain, plainKey, otherDevice, "5511944444444@s.whatsapp.net", store.ErrChatNotEligible},
		"the own chat's device suffixed": {plain, plainKey, f.device, "5511900000000:12@s.whatsapp.net", store.ErrChatNotEligible},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.conns.CreateDraft(ctx, tc.conn, tc.key, store.NewDraft{ID: uuid.New(), Device: tc.device, ChatKey: tc.chat, Epoch: 1, Sealed: []byte("x")}, roomy)
			if !errors.Is(err, tc.want) && (err != nil || tc.want != nil) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// A reply names a message of the same chat, or of the same person's
	// other half; anything else is not found.
	for name, tc := range map[string]struct {
		chat  string
		reply uuid.UUID
		want  error
	}{
		"in the chat":          {friendChat, f.inbound[friendChat], nil},
		"in the other half":    {half, f.inbound[friendChat], nil},
		"in another chat":      {friendChat, f.inbound[sendGroupChat], store.ErrReplyNotFound},
		"not a message at all": {friendChat, uuid.New(), store.ErrReplyNotFound},
	} {
		t.Run("reply "+name, func(t *testing.T) {
			reply := tc.reply
			_, err := f.conns.CreateDraft(ctx, plain, plainKey, store.NewDraft{ID: uuid.New(), Device: f.device, ChatKey: tc.chat, ReplyTo: &reply, Epoch: 1, Sealed: []byte("x")}, roomy)
			if !errors.Is(err, tc.want) && (err != nil || tc.want != nil) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// Twice the same id: the second is refused.
	id := uuid.New()
	in := store.NewDraft{ID: id, Device: f.device, ChatKey: friendChat, Epoch: 1, Sealed: []byte("x")}
	if _, err := f.conns.CreateDraft(ctx, plain, plainKey, in, roomy); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conns.CreateDraft(ctx, plain, plainKey, in, roomy); !errors.Is(err, store.ErrDraftExists) {
		t.Fatalf("a repeated draft id = %v", err)
	}
}

// Every draft and send is decided at the moment it is asked: the connection
// active and not paused, its key the one presented, and the person who
// consented still able to send on the number. The service account is never
// asked.
func TestSendingNeedsTheConsenterNow(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	if _, err := f.draft(ctx, conn, key, friendChat, roomy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.selfSend(ctx, conn, key, newRef(), roomy); err != nil {
		t.Fatal(err)
	}
	// Another key: a mix-up of connections inside the reader.
	if _, err := f.draft(ctx, conn, uuid.New(), friendChat, roomy); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("another key = %v", err)
	}
	// The person who consented loses send on the number.
	if err := f.users.SetDevicePermission(ctx, f.tenant, f.owner, store.DevicePermission{DeviceID: f.device, UserID: f.owner, Read: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.draft(ctx, conn, key, friendChat, roomy); !errors.Is(err, store.ErrSendNotAllowed) {
		t.Fatalf("a draft without the consenter's send = %v", err)
	}
	if _, _, err := f.selfSend(ctx, conn, key, newRef(), roomy); !errors.Is(err, store.ErrSendNotAllowed) {
		t.Fatalf("a send without the consenter's send = %v", err)
	}
	f.ownerReads(ctx, t, f.owner, f.device)
	// Paused, then not active.
	if err := f.conns.SetSendPaused(ctx, f.tenant, f.owner, conn.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.draft(ctx, conn, key, friendChat, roomy); !errors.Is(err, store.ErrSendNotAllowed) {
		t.Fatalf("paused = %v", err)
	}
	if err := f.conns.SetSendPaused(ctx, f.tenant, f.owner, conn.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Reseal(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.draft(ctx, conn, key, friendChat, roomy); !errors.Is(err, store.ErrMCPConnectionState) {
		t.Fatalf("resealed = %v", err)
	}
	// A connection without the own chat, or without a phone number, sends
	// nowhere of its own.
	drafts, draftsKey, _ := f.sendingConsent(ctx, t, f.owner, nil)
	if _, _, err := f.selfSend(ctx, drafts, draftsKey, newRef(), roomy); !errors.Is(err, store.ErrSendNotAllowed) {
		t.Fatalf("own chat not consented = %v", err)
	}
	selfConn, selfKey, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	setPN := func(pn any) {
		t.Helper()
		f.inTenant(ctx, t, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE devices SET pn=$2 WHERE id=$1`, f.device, pn)
			return err
		})
	}
	setPN(nil)
	if _, _, err := f.selfSend(ctx, selfConn, selfKey, newRef(), roomy); !errors.Is(err, store.ErrChatNotEligible) {
		t.Fatalf("a number with no phone number = %v", err)
	}
	// A text the rules refused is refused in its place, after the chat.
	setPN("5511900000000:12@s.whatsapp.net")
	if _, _, err := f.conns.StartSend(ctx, selfConn, selfKey, store.NewSend{Kind: store.OutboundSelf, Device: f.device, ClientRef: newRef()}, roomy); !errors.Is(err, store.ErrTextNotAllowed) {
		t.Fatalf("a refused text = %v", err)
	}
}

// The draft limits hold under concurrency: the connection's lock lets the
// drafts through one at a time, and the retry time is when a place frees.
func TestDraftLimitsUnderConcurrency(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, nil)
	pending := roomy
	pending.DraftsPending = 3
	made, limited := race(t, 10, func() error { _, err := f.draft(ctx, conn, key, friendChat, pending); return err })
	if made != 3 || limited != 7 {
		t.Fatalf("pending: %d made, %d limited", made, limited)
	}
	_, err := f.draft(ctx, conn, key, friendChat, pending)
	var rl *store.RateLimitError
	if !errors.As(err, &rl) || rl.RetryAt.Sub(time.Now().Add(store.DraftTTL)).Abs() > time.Minute {
		t.Fatalf("retry = %v", err)
	}

	// Per hour: decided drafts still count; refusals do not.
	conn2, key2, _ := f.sendingConsent(ctx, t, f.owner, nil)
	hourly := roomy
	hourly.DraftsPerHour = 4
	made, limited = race(t, 10, func() error { _, err := f.draft(ctx, conn2, key2, friendChat, hourly); return err })
	if made != 4 || limited != 6 {
		t.Fatalf("per hour: %d made, %d limited", made, limited)
	}
	drafts, _, err := f.conns.ListOutbound(ctx, f.tenant, conn2.ID, store.OutboundQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range drafts {
		if _, err := f.conns.DiscardDraft(ctx, f.tenant, f.owner, d.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.draft(ctx, conn2, key2, friendChat, hourly); !errors.As(err, &rl) || rl.RetryAt.Sub(time.Now().Add(time.Hour)).Abs() > time.Minute {
		t.Fatalf("after discarding = %v", err)
	}
	if _, err := f.conns.RecordRefusal(ctx, f.tenant, conn2.ID, store.Refusal{Kind: store.OutboundDraft, Device: f.device, ChatKey: friendChat, Code: "rate_limited"}); err != nil {
		t.Fatal(err)
	}
	hourly.DraftsPerHour = 5
	if _, err := f.draft(ctx, conn2, key2, friendChat, hourly); err != nil {
		t.Fatalf("a refusal counted as a draft: %v", err)
	}
}

// race runs n calls at once and counts those that passed and those a limit
// refused; anything else fails the test.
func race(t *testing.T, n int, call func() error) (passed, limited int) {
	t.Helper()
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := call()
			var rl *store.RateLimitError
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				passed++
			case errors.As(err, &rl):
				limited++
			default:
				t.Errorf("call: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	return passed, limited
}

// The send limits hold under concurrency: per connection a day, the interval
// between two sends, and the workspace's day across connections.
func TestSendLimitsUnderConcurrency(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	daily := roomy
	daily.PerDay = 3
	made, limited := race(t, 8, func() error { _, _, err := f.selfSend(ctx, conn, key, newRef(), daily); return err })
	if made != 3 || limited != 5 {
		t.Fatalf("per day: %d made, %d limited", made, limited)
	}

	spaced := roomy
	spaced.MinInterval = time.Hour
	conn2, key2, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	made, limited = race(t, 5, func() error { _, _, err := f.selfSend(ctx, conn2, key2, newRef(), spaced); return err })
	if made != 1 || limited != 4 {
		t.Fatalf("interval: %d made, %d limited", made, limited)
	}
	_, _, err := f.selfSend(ctx, conn2, key2, newRef(), spaced)
	var rl *store.RateLimitError
	if !errors.As(err, &rl) || rl.RetryAt.Sub(time.Now().Add(time.Hour)).Abs() > time.Minute {
		t.Fatalf("interval retry = %v", err)
	}

	// The workspace: two fresh connections, one day's budget of four between
	// them, already spent by the first two connections' four sends.
	workspace := roomy
	workspace.TenantPerDay = 6
	a, aKey, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	b, bKey, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	var mu sync.Mutex
	turn := 0
	made, limited = race(t, 8, func() error {
		mu.Lock()
		turn++
		c, k := a, aKey
		if turn%2 == 0 {
			c, k = b, bKey
		}
		mu.Unlock()
		_, _, err := f.selfSend(ctx, c, k, newRef(), workspace)
		return err
	})
	if made != 2 || limited != 6 {
		t.Fatalf("workspace: %d made, %d limited", made, limited)
	}
}

// The interval runs between the moments two sends passed the connection's
// lock: a send whose transaction began before the last send was recorded,
// and waited behind it, is not refused for having begun first, and is
// recorded when it passed, at least the interval after the last.
func TestSendIntervalRunsFromTheLock(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	type result struct {
		started store.StartedSend
		err     error
	}
	done := make(chan result, 1)
	var last time.Time
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM mcp_connections WHERE id=$1 FOR UPDATE`, conn.ID); err != nil {
			return err
		}
		go func() {
			started, _, err := f.selfSend(ctx, conn, key, newRef(), roomy)
			done <- result{started, err}
		}()
		// Asked from another session: this transaction's view of
		// pg_stat_activity is a snapshot that would miss a new connection.
		holder := tx.Conn().PgConn().PID()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			var waiting bool
			if err := f.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
				WHERE $1 = ANY(pg_blocking_pids(pid)))`, holder).Scan(&waiting); err != nil {
				return err
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("the send never waited on the connection's lock")
			}
		}
		// The send has begun; another is recorded before it gets the lock.
		return tx.QueryRow(ctx, `INSERT INTO mcp_outbound (id, tenant_id, connection_id, device_id, kind, status, client_ref, created_at)
			VALUES (uuidv7(), $1, $2, $3, 'self', 'sent', $4, clock_timestamp()) RETURNING created_at`,
			f.tenant, conn.ID, f.device, newRef()).Scan(&last)
	})
	r := <-done
	if r.err != nil {
		t.Fatalf("the send that waited = %v", r.err)
	}
	var at time.Time
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT created_at FROM mcp_outbound WHERE id=$1`, r.started.ID).Scan(&at)
	})
	if gap := at.Sub(last); gap < roomy.MinInterval {
		t.Fatalf("recorded %v after the last send", gap)
	}
}

// A reference already recorded answers what was recorded, and never makes a
// second send.
func TestSendReferenceAnswersTheRecord(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	ref := newRef()
	started, prior, err := f.selfSend(ctx, conn, key, ref, roomy)
	if err != nil || prior != nil || started.ChatKey != ownPN {
		t.Fatalf("first = %+v %v %v", started, prior, err)
	}
	// In flight: the same reference finds it sending.
	again, prior, err := f.selfSend(ctx, conn, key, ref, roomy)
	if err != nil || prior == nil || prior.Status != store.OutboundSending || prior.ID != started.ID || again.ID != uuid.Nil {
		t.Fatalf("in flight = %+v %+v %v", again, prior, err)
	}
	uid := uuid.New()
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := f.conns.FinishSend(ctx, f.tenant, started.ID, store.SendOutcome{Status: store.OutboundSent, MessageUID: &uid, WAID: "3EB0", At: at}); err != nil {
		t.Fatal(err)
	}
	// An outcome is never rewritten.
	if err := f.conns.FinishSend(ctx, f.tenant, started.ID, store.SendOutcome{Status: store.OutboundUncertain, At: at}); err != nil {
		t.Fatal(err)
	}
	_, prior, err = f.selfSend(ctx, conn, key, ref, roomy)
	if err != nil || prior == nil || prior.Status != store.OutboundSent || prior.MessageUID == nil || *prior.MessageUID != uid ||
		prior.WAID != "3EB0" || prior.DecidedAt == nil || !prior.DecidedAt.Equal(at) {
		t.Fatalf("sent = %+v %v", prior, err)
	}
	// Even over the limit, the recorded send answers.
	none := roomy
	none.PerDay = 1
	if _, prior, err = f.selfSend(ctx, conn, key, ref, none); err != nil || prior == nil {
		t.Fatalf("over the limit = %+v %v", prior, err)
	}
	var sends int
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM mcp_outbound WHERE connection_id=$1`, conn.ID).Scan(&sends)
	})
	if sends != 1 {
		t.Fatalf("ledger rows = %d", sends)
	}
}

// A person confirms a draft once. Who may, and when.
func TestClaimDraft(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, nil)
	allowed := func(uuid.UUID) bool { return true }
	claim := func(user, id uuid.UUID, chat string, sendAllowed func(uuid.UUID) bool) error {
		_, err := f.conns.ClaimDraft(ctx, f.tenant, user, id, f.device, chat, sendAllowed)
		return err
	}

	id, err := f.draft(ctx, conn, key, friendChat, roomy)
	if err != nil {
		t.Fatal(err)
	}
	someone, _ := transferOwner(t, f.archive, "admin")
	f.ownerReads(ctx, t, someone, f.device)
	for name, tc := range map[string]struct {
		user    uuid.UUID
		draft   uuid.UUID
		chat    string
		allowed func(uuid.UUID) bool
		want    error
	}{
		"another person, an admin who may send": {someone, id, friendChat, allowed, store.ErrOutboundNotFound},
		"no such draft":                         {f.owner, uuid.New(), friendChat, allowed, store.ErrOutboundNotFound},
		"another chat":                          {f.owner, id, quietChat, allowed, store.ErrDraftMismatch},
		"sending switched off":                  {f.owner, id, friendChat, func(uuid.UUID) bool { return false }, store.ErrSendNotAllowed},
		"no switch at all":                      {f.owner, id, friendChat, nil, store.ErrSendNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			if err := claim(tc.user, tc.draft, tc.chat, tc.allowed); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if status, sealed, _ := f.ledger(ctx, t, id); status != store.OutboundPending || !sealed {
		t.Fatalf("a refused claim changed the draft: %s %v", status, sealed)
	}
	// Twice at once: exactly one takes it, and its envelope goes.
	var mu sync.Mutex
	var won, lost int
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := claim(f.owner, id, friendChat, allowed)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, store.ErrDraftState):
				lost++
			default:
				t.Errorf("claim: %v", err)
			}
		}()
	}
	wg.Wait()
	if won != 1 || lost != 4 {
		t.Fatalf("%d took the draft, %d found it taken", won, lost)
	}
	if status, sealed, _ := f.ledger(ctx, t, id); status != store.OutboundSending || sealed {
		t.Fatalf("taken = %s %v", status, sealed)
	}
	uid := uuid.New()
	if err := f.conns.FinishDraft(ctx, f.tenant, id, store.DraftOutcome{Status: store.OutboundSent, MessageUID: &uid, WAID: "3EB1", Edited: true, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := f.conns.ListOutbound(ctx, f.tenant, conn.ID, store.OutboundQuery{Limit: 50})
	if err != nil || len(rows) != 1 || rows[0].Status != store.OutboundSent || !rows[0].Edited || rows[0].DecidedBy == nil || *rows[0].DecidedBy != f.owner {
		t.Fatalf("after sending = %+v %v", rows, err)
	}

	// Discarded, expired, and a consenter who lost send.
	discarded, _ := f.draft(ctx, conn, key, friendChat, roomy)
	if _, err := f.conns.DiscardDraft(ctx, f.tenant, f.owner, discarded); err != nil {
		t.Fatal(err)
	}
	if err := claim(f.owner, discarded, friendChat, allowed); !errors.Is(err, store.ErrDraftState) {
		t.Fatalf("discarded = %v", err)
	}
	if _, err := f.conns.DiscardDraft(ctx, f.tenant, f.owner, discarded); !errors.Is(err, store.ErrDraftState) {
		t.Fatalf("discarded twice = %v", err)
	}
	expired, _ := f.draft(ctx, conn, key, friendChat, roomy)
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_outbound SET expires_at=now()-interval '1 second' WHERE id=$1`, expired)
		return err
	})
	if err := claim(f.owner, expired, friendChat, allowed); !errors.Is(err, store.ErrDraftState) {
		t.Fatalf("expired = %v", err)
	}
	if o, err := f.conns.Draft(ctx, f.tenant, f.owner, expired); err != nil || o.Status != store.OutboundExpired || o.Sealed != nil {
		t.Fatalf("an expired draft reads as %+v %v", o, err)
	}
	lostSend, _ := f.draft(ctx, conn, key, friendChat, roomy)
	if err := f.users.SetDevicePermission(ctx, f.tenant, f.owner, store.DevicePermission{DeviceID: f.device, UserID: f.owner, Read: true}); err != nil {
		t.Fatal(err)
	}
	if err := claim(f.owner, lostSend, friendChat, allowed); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("without send = %v", err)
	}
	// Only the consenter reads a draft, or lists them.
	if _, err := f.conns.Draft(ctx, f.tenant, someone, lostSend); !errors.Is(err, store.ErrOutboundNotFound) {
		t.Fatalf("another person read a draft: %v", err)
	}
	if _, err := f.conns.PendingDrafts(ctx, f.tenant, someone, conn.ID); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("another person listed drafts: %v", err)
	}
	pending, err := f.conns.PendingDrafts(ctx, f.tenant, f.owner, conn.ID)
	if err != nil || len(pending) != 1 || pending[0].ID != lostSend || string(pending[0].Sealed) != "sealed draft" {
		t.Fatalf("pending = %+v %v", pending, err)
	}
}

// Every end of a connection (docs/mcp-enclave.md §15.7's paths) takes its
// waiting drafts with it, text and all; a send in flight is left to finish.
func TestEndingTakesTheDrafts(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	setup := func(t *testing.T, actor uuid.UUID) (store.SendConnection, contentConsent, uuid.UUID, uuid.UUID) {
		t.Helper()
		conn, key, c := f.sendingConsent(ctx, t, actor, withSelf)
		draft, err := f.draft(ctx, conn, key, friendChat, roomy)
		if err != nil {
			t.Fatal(err)
		}
		started, _, err := f.selfSend(ctx, conn, key, newRef(), roomy)
		if err != nil {
			t.Fatal(err)
		}
		return conn, c, draft, started.ID
	}
	check := func(t *testing.T, conn store.SendConnection, draft, sending uuid.UUID) {
		t.Helper()
		if got := f.row(ctx, t, conn.ID); got.Status != "revoked" && got.Status != "expired" {
			t.Fatalf("connection = %s", got.Status)
		}
		if status, sealed, _ := f.ledger(ctx, t, draft); status != store.OutboundRevoked || sealed {
			t.Fatalf("draft = %s, sealed %v", status, sealed)
		}
		if status, _, _ := f.ledger(ctx, t, sending); status != store.OutboundSending {
			t.Fatalf("the send in flight = %s", status)
		}
	}
	t.Run("console", func(t *testing.T) {
		conn, _, draft, sending := setup(t, f.owner)
		if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID); err != nil {
			t.Fatal(err)
		}
		check(t, conn, draft, sending)
	})
	t.Run("reader", func(t *testing.T) {
		conn, _, draft, sending := setup(t, f.owner)
		if err := f.conns.RevokeByID(ctx, "enclave", conn.ID, store.ReasonReuseDetected); err != nil {
			t.Fatal(err)
		}
		check(t, conn, draft, sending)
	})
	t.Run("janitor, expired", func(t *testing.T) {
		conn, _, draft, sending := setup(t, f.owner)
		if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET expires_at=now()-interval '1 minute' WHERE id=$1`, conn.ID); err != nil {
			t.Fatal(err)
		}
		if n, err := store.ExpireMCPConnections(ctx, f.pool, 20*time.Minute); err != nil || n != 1 {
			t.Fatalf("settled %d %v", n, err)
		}
		check(t, conn, draft, sending)
	})
	t.Run("service removed", func(t *testing.T) {
		conn, c, draft, sending := setup(t, f.owner)
		if err := f.users.RemoveMember(ctx, f.tenant, f.owner, c.service); err != nil {
			t.Fatal(err)
		}
		check(t, conn, draft, sending)
	})
	t.Run("service disabled", func(t *testing.T) {
		conn, c, draft, sending := setup(t, f.owner)
		if err := f.users.UpdateMember(ctx, f.tenant, f.owner, c.service, store.RoleService, "disabled"); err != nil {
			t.Fatal(err)
		}
		check(t, conn, draft, sending)
	})
	for _, removed := range []bool{true, false} {
		name := "consenter disabled"
		if removed {
			name = "consenter removed"
		}
		admin, _ := transferOwner(t, f.archive, "admin")
		f.ownerReads(ctx, t, admin, f.device)
		t.Run(name, func(t *testing.T) {
			conn, _, draft, sending := setup(t, admin)
			var err error
			if removed {
				err = f.users.RemoveMember(ctx, f.tenant, f.owner, admin)
			} else {
				err = f.users.UpdateMember(ctx, f.tenant, f.owner, admin, "admin", "disabled")
			}
			if err != nil {
				t.Fatal(err)
			}
			check(t, conn, draft, sending)
		})
	}
	t.Run("access lost", func(t *testing.T) {
		conn, c, draft, sending := setup(t, f.owner)
		if err := f.keys.Revoke(ctx, f.tenant.String(), c.prefix); err != nil {
			t.Fatal(err)
		}
		if answer, err := f.conns.Status(ctx, "enclave", conn.ID, allowAll); err != nil || answer.Status != "revoked" {
			t.Fatalf("status = %+v %v", answer, err)
		}
		check(t, conn, draft, sending)
	})
}

// The janitor: a waiting draft past its expiry loses its text, a send whose
// outcome never came is uncertain, and the ledger forgets after a year.
func TestSettleMCPOutbound(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	fresh, _ := f.draft(ctx, conn, key, friendChat, roomy)
	old, _ := f.draft(ctx, conn, key, friendChat, roomy)
	stale, _, err := f.selfSend(ctx, conn, key, newRef(), roomy)
	if err != nil {
		t.Fatal(err)
	}
	recent, _, err := f.selfSend(ctx, conn, key, newRef(), roomy)
	if err != nil {
		t.Fatal(err)
	}
	ancient, _ := f.draft(ctx, conn, key, friendChat, roomy)
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE mcp_outbound SET expires_at=now()-interval '1 second' WHERE id=$1`, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE mcp_outbound SET created_at=now()-interval '11 minutes' WHERE id=$1`, stale.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE mcp_outbound SET created_at=now()-interval '366 days', expires_at=now()-interval '365 days' WHERE id=$1`, ancient)
		return err
	})
	settled, err := store.SettleMCPOutbound(ctx, f.pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(settled.Expired) != 2 || len(settled.Uncertain) != 1 || settled.Uncertain[0] != [2]string{conn.ID, stale.ID.String()} || settled.Deleted != 1 {
		t.Fatalf("settled = %+v", settled)
	}
	for id, want := range map[uuid.UUID]string{fresh: "pending", old: "expired", stale.ID: "uncertain", recent.ID: "sending"} {
		if status, sealed, _ := f.ledger(ctx, t, id); status != want || sealed != (want == "pending") {
			t.Fatalf("%s = %s, sealed %v; want %s", id, status, sealed, want)
		}
	}
	var gone bool
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM mcp_outbound WHERE id=$1)`, ancient).Scan(&gone)
	})
	if !gone {
		t.Fatal("a row past retention was kept")
	}
}

// A draft is in flight from when a person claimed it, not from when the
// assistant wrote it, up to a day before: the janitor leaves a draft written
// long ago and claimed now to its send, whose outcome is then recorded, and
// makes one claimed more than ten minutes ago uncertain.
func TestSettleLeavesAClaimedDraftToItsSend(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, nil)
	late, err := f.draft(ctx, conn, key, friendChat, roomy)
	if err != nil {
		t.Fatal(err)
	}
	lost, err := f.draft(ctx, conn, key, friendChat, roomy)
	if err != nil {
		t.Fatal(err)
	}
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_outbound SET created_at=now()-interval '11 minutes' WHERE id = ANY($1)`, []uuid.UUID{late, lost})
		return err
	})
	for _, id := range []uuid.UUID{late, lost} {
		if _, err := f.conns.ClaimDraft(ctx, f.tenant, f.owner, id, f.device, friendChat, func(uuid.UUID) bool { return true }); err != nil {
			t.Fatal(err)
		}
	}
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_outbound SET decided_at=now()-interval '11 minutes' WHERE id=$1`, lost)
		return err
	})
	settled, err := store.SettleMCPOutbound(ctx, f.pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(settled.Uncertain) != 1 || settled.Uncertain[0] != [2]string{conn.ID, lost.String()} {
		t.Fatalf("uncertain = %+v", settled.Uncertain)
	}
	uid := uuid.New()
	if err := f.conns.FinishDraft(ctx, f.tenant, late, store.DraftOutcome{Status: store.OutboundSent, MessageUID: &uid, WAID: "3EB2", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[uuid.UUID]string{late: store.OutboundSent, lost: store.OutboundUncertain} {
		if status, _, _ := f.ledger(ctx, t, id); status != want {
			t.Fatalf("%s = %s, want %s", id, status, want)
		}
	}
	rows, _, err := f.conns.ListOutbound(ctx, f.tenant, conn.ID, store.OutboundQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == late && (row.MessageUID == nil || *row.MessageUID != uid) {
			t.Fatalf("the sent draft lost its message: %+v", row)
		}
	}
}

// A release puts a connection in reseal, and its drafts stay confirmable
// until they expire (docs/mcp-enclave.md §17.14); a connection that is no
// longer active or resealed confirms nothing.
func TestClaimDraftAfterARelease(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, nil)
	resealed, err := f.draft(ctx, conn, key, friendChat, roomy)
	if err != nil {
		t.Fatal(err)
	}
	ended, err := f.draft(ctx, conn, key, friendChat, roomy)
	if err != nil {
		t.Fatal(err)
	}
	setStatus := func(status string) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET status=$2 WHERE id=$1`, conn.ID, status); err != nil {
			t.Fatal(err)
		}
	}
	claim := func(id uuid.UUID) error {
		_, err := f.conns.ClaimDraft(ctx, f.tenant, f.owner, id, f.device, friendChat, func(uuid.UUID) bool { return true })
		return err
	}
	setStatus("reseal")
	if err := claim(resealed); err != nil {
		t.Fatalf("in reseal = %v", err)
	}
	setStatus("pending")
	if err := claim(ended); !errors.Is(err, store.ErrSendNotAllowed) {
		t.Fatalf("pending = %v", err)
	}
}

// A draft, a send or a refusal and a connection's end take their locks in
// one order (docs/mcp-enclave.md §17.19): the workspace's row, then the
// connection's. An end that holds the workspace while a draft waits goes on
// and commits, and the draft then reads the connection as ended: nothing
// deadlocks, and the end never loses to the draft.
func TestSendingAndEndingDoNotDeadlock(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		start func(store.SendConnection, uuid.UUID) error
		want  error
	}{
		{"draft", func(conn store.SendConnection, key uuid.UUID) error {
			_, err := f.draft(ctx, conn, key, friendChat, roomy)
			return err
		}, store.ErrMCPConnectionState},
		{"send", func(conn store.SendConnection, key uuid.UUID) error {
			_, _, err := f.selfSend(ctx, conn, key, newRef(), roomy)
			return err
		}, store.ErrMCPConnectionState},
		{"refusal", func(conn store.SendConnection, _ uuid.UUID) error {
			_, err := f.conns.RecordRefusal(ctx, f.tenant, conn.ID, store.Refusal{Kind: store.OutboundSelf, Device: f.device, Code: "text_not_allowed"})
			return err
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, key, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
			// An end, as every ending path takes its locks: the workspace's
			// row (lockWorkspaceAccess, lockWorkspaceManager), then, once the
			// draft is waiting, the connection's (endMCPConnectionTx).
			ending, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ending.Rollback(ctx) }()
			if _, err := ending.Exec(ctx, `SELECT id FROM tenants WHERE id=$1 FOR UPDATE`, f.tenant); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- tc.start(conn, key) }()
			waitForALockWait(ctx, t, f)
			if _, err := ending.Exec(ctx, `SELECT status FROM mcp_connections WHERE id=$1 FOR UPDATE`, conn.ID); err != nil {
				t.Fatalf("the end: %v", err)
			}
			if _, err := ending.Exec(ctx, `UPDATE mcp_connections SET status='revoked', revoked_at=now(), revoke_reason='console' WHERE id=$1`, conn.ID); err != nil {
				t.Fatalf("the end: %v", err)
			}
			if err := ending.Commit(ctx); err != nil {
				t.Fatalf("the end: %v", err)
			}
			if err := <-done; !errors.Is(err, tc.want) {
				t.Fatalf("%s after the end = %v, want %v", tc.name, err, tc.want)
			}
		})
	}

	// And the real paths, raced: the reader's revocation (endInTenant) and
	// the console's against a draft and a send of the same connection.
	for i := range 8 {
		conn, key, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
		errs := make(chan error, 3)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			if _, err := f.draft(ctx, conn, key, friendChat, roomy); err != nil && !errors.Is(err, store.ErrMCPConnectionState) {
				errs <- fmt.Errorf("draft: %w", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, _, err := f.selfSend(ctx, conn, key, newRef(), roomy); err != nil && !errors.Is(err, store.ErrMCPConnectionState) {
				errs <- fmt.Errorf("send: %w", err)
			}
		}()
		go func() {
			defer wg.Done()
			var err error
			if i%2 == 0 {
				err = f.conns.RevokeByID(ctx, "enclave", conn.ID, store.ReasonReader)
			} else {
				_, err = f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID)
			}
			if err != nil {
				errs <- fmt.Errorf("end: %w", err)
			}
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("round %d: %v", i, err)
		}
		if row := f.row(ctx, t, conn.ID); row.Status != "revoked" {
			t.Fatalf("round %d: the connection is %s", i, row.Status)
		}
	}
}

// waitForALockWait returns once another session of the test's database
// waits on a lock, and fails the test after five seconds.
func waitForALockWait(ctx context.Context, t *testing.T, f *sendFixture) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event_type = 'Lock'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("nothing waited on the end's lock")
}

// Refusals are recorded up to a hundred a connection a day; past that they
// are only counted, and a number that is not the connection's is not taken.
func TestRefusalsAreCapped(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, _, _ := f.sendingConsent(ctx, t, f.owner, nil)
	refusal := store.Refusal{Kind: store.OutboundSelf, Device: f.device, Code: "text_not_allowed"}
	for i := range 100 {
		if ok, err := f.conns.RecordRefusal(ctx, f.tenant, conn.ID, refusal); err != nil || !ok {
			t.Fatalf("refusal %d: %v %v", i, ok, err)
		}
	}
	if ok, err := f.conns.RecordRefusal(ctx, f.tenant, conn.ID, refusal); err != nil || ok {
		t.Fatalf("the hundred and first: %v %v", ok, err)
	}
	if n := len(f.refusals(ctx, t, conn.ID)); n != 100 {
		t.Fatalf("recorded %d", n)
	}
	refusal.Device = uuid.New()
	if _, err := f.conns.RecordRefusal(ctx, f.tenant, conn.ID, refusal); !errors.Is(err, store.ErrChatNotEligible) {
		t.Fatalf("another number: %v", err)
	}
}

// The ledger is a workspace's alone: outside its tenant transaction the
// ordinary role sees and changes nothing, and another workspace's
// transaction does not see it either.
func TestLedgerRowLevelSecurity(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, nil)
	if _, err := f.draft(ctx, conn, key, friendChat, roomy); err != nil {
		t.Fatal(err)
	}
	var outside int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM mcp_outbound`).Scan(&outside); err != nil || outside != 0 {
		t.Fatalf("outside a tenant: %d %v", outside, err)
	}
	if tag, err := f.pool.Exec(ctx, `UPDATE mcp_outbound SET status='discarded'`); err != nil || tag.RowsAffected() != 0 {
		t.Fatalf("an update outside a tenant: %v %v", tag, err)
	}
	foreign := uuid.MustParse(newTenant(t, f.pool, "Foreign"))
	var seen int
	if err := pgxTenant(ctx, f, foreign, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM mcp_outbound`).Scan(&seen)
	}); err != nil || seen != 0 {
		t.Fatalf("another workspace sees %d %v", seen, err)
	}
	_, err := f.pool.Exec(ctx, `INSERT INTO mcp_outbound (id, tenant_id, connection_id, device_id, chat_key, kind, status, code)
		VALUES (uuidv7(), $1, $2, $3, 'x', 'draft', 'refused', 'x')`, f.tenant, conn.ID, f.device)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("an insert outside a tenant: %v", err)
	}
}

func pgxTenant(ctx context.Context, f *sendFixture, tenant uuid.UUID, fn func(pgx.Tx) error) error {
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
		return err
	}
	return fn(tx)
}

// The ledger's pages, newest first, narrowed and continued.
func TestListOutboundPages(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	var ids []uuid.UUID
	for range 5 {
		id, err := f.draft(ctx, conn, key, friendChat, roomy)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if _, _, err := f.selfSend(ctx, conn, key, newRef(), roomy); err != nil {
		t.Fatal(err)
	}
	first, more, err := f.conns.ListOutbound(ctx, f.tenant, conn.ID, store.OutboundQuery{Limit: 4})
	if err != nil || len(first) != 4 || !more || first[0].Kind != store.OutboundSelf {
		t.Fatalf("first page = %d %v %v", len(first), more, err)
	}
	last := first[len(first)-1]
	rest, more, err := f.conns.ListOutbound(ctx, f.tenant, conn.ID, store.OutboundQuery{Limit: 4, Before: &store.OutboundCursor{CreatedAt: last.CreatedAt, ID: last.ID}})
	if err != nil || len(rest) != 2 || more || rest[1].ID != ids[0] {
		t.Fatalf("second page = %+v %v %v", rest, more, err)
	}
	pending, _, err := f.conns.ListOutbound(ctx, f.tenant, conn.ID, store.OutboundQuery{Limit: 50, Status: store.OutboundPending})
	if err != nil || len(pending) != 5 {
		t.Fatalf("pending = %d %v", len(pending), err)
	}
	for _, o := range pending {
		if o.Kind != store.OutboundDraft || o.Sealed == nil || o.ClientName != "Claude" {
			t.Fatalf("pending row = %+v", o)
		}
	}
	other := uuid.New()
	if rows, _, err := f.conns.ListOutbound(ctx, f.tenant, conn.ID, store.OutboundQuery{Limit: 50, Device: &other}); err != nil || len(rows) != 0 {
		t.Fatalf("another number = %d %v", len(rows), err)
	}
}

// The console's pause: the consenter, an owner or an admin pause; only the
// consenter takes it off; and a connection that cannot send has no pause.
func TestSendPause(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	admin, _ := transferOwner(t, f.archive, "admin")
	member, _ := transferOwner(t, f.archive, "member")
	conn, _, _ := f.sendingConsent(ctx, t, f.owner, nil)
	if err := f.conns.SetSendPaused(ctx, f.tenant, member, conn.ID, true); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("a member paused: %v", err)
	}
	if err := f.conns.SetSendPaused(ctx, f.tenant, admin, conn.ID, true); err != nil {
		t.Fatalf("an admin could not pause: %v", err)
	}
	if err := f.conns.SetSendPaused(ctx, f.tenant, admin, conn.ID, false); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("an admin unpaused: %v", err)
	}
	if f.row(ctx, t, conn.ID).SendPausedAt == nil {
		t.Fatal("not paused")
	}
	if err := f.conns.SetSendPaused(ctx, f.tenant, f.owner, conn.ID, false); err != nil || f.row(ctx, t, conn.ID).SendPausedAt != nil {
		t.Fatalf("unpause: %v", err)
	}
	text, _ := f.consentContent(ctx, t, f.owner)
	if err := f.conns.SetSendPaused(ctx, f.tenant, f.owner, text.ID, true); !errors.Is(err, store.ErrMCPConnectionState) {
		t.Fatalf("a connection without sending: %v", err)
	}
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.SetSendPaused(ctx, f.tenant, f.owner, conn.ID, true); !errors.Is(err, store.ErrMCPConnectionState) {
		t.Fatalf("an ended connection: %v", err)
	}
	if err := f.conns.SetSendPaused(ctx, f.tenant, f.owner, uuid.NewString(), true); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("no such connection: %v", err)
	}
	// Who may read a ledger: the consenter, an owner, an admin.
	if _, _, err := f.conns.ConsoleOutbound(ctx, f.tenant, member, conn.ID, store.OutboundQuery{Limit: 20}); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("a member read a ledger: %v", err)
	}
	if _, _, err := f.conns.ConsoleOutbound(ctx, f.tenant, admin, conn.ID, store.OutboundQuery{Limit: 20}); err != nil {
		t.Fatalf("an admin could not read a ledger: %v", err)
	}
}

// A key that a connection holds, or held, is known as one.
func TestHoldsAPIKey(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	_, key, _ := f.sendingConsent(ctx, t, f.owner, nil)
	metaKey, metaPrefix := f.provisionalKey(ctx, t, "meta")
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(metaPrefix)); err != nil {
		t.Fatal(err)
	}
	meta, err := f.keys.VerifyScoped(ctx, metaKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		key  uuid.UUID
		want bool
	}{"content": {key, true}, "metadata": {meta.ID, true}, "anything else": {uuid.New(), false}} {
		if held, err := f.conns.HoldsAPIKey(ctx, tc.key); err != nil || held != tc.want {
			t.Fatalf("%s: %v %v", name, held, err)
		}
	}
}

// Which archived messages a connection sent, for the "via" label.
func TestOutboundMessages(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	conn, key, _ := f.sendingConsent(ctx, t, f.owner, withSelf)
	started, _, err := f.selfSend(ctx, conn, key, newRef(), roomy)
	if err != nil {
		t.Fatal(err)
	}
	uid := uuid.New()
	if err := f.conns.FinishSend(ctx, f.tenant, started.ID, store.SendOutcome{Status: store.OutboundSent, MessageUID: &uid, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got, err := f.conns.OutboundMessages(ctx, f.tenant, f.device, []uuid.UUID{uid, uuid.New()})
	if err != nil || len(got) != 1 || got[0].MessageUID != uid || got[0].ConnectionID != conn.ID || got[0].ClientName != "Claude" || got[0].Kind != store.OutboundSelf {
		t.Fatalf("via = %+v %v", got, err)
	}
	if got, err := f.conns.OutboundMessages(ctx, f.tenant, uuid.New(), []uuid.UUID{uid}); err != nil || len(got) != 0 {
		t.Fatalf("another number = %+v %v", got, err)
	}
}

// 0044's down-step, exactly as its header documents it, run as the table
// owner under FORCE RLS: every connection that consented to sending revoked
// with its key and its service account stripped, 0043's cascade; the ledger,
// the list and the columns gone and version 44 forgotten; every other
// connection and every person's access untouched; and up again. 0045 comes
// down first, as the plan orders it.
func TestMigration0044DownStep(t *testing.T) {
	f := newSendFixture(t)
	ctx := context.Background()
	sending, key, sc := f.sendingConsent(ctx, t, f.owner, withSelf)
	if _, err := f.draft(ctx, sending, key, friendChat, roomy); err != nil {
		t.Fatal(err)
	}
	pendingSend := f.prepareContent(ctx, t, f.owner)
	pendingSend.in.ConsentVersion, pendingSend.in.SendMode = 3, store.SendModeDraft
	pending, err := f.conns.Create(ctx, f.tenant, f.owner, pendingSend.in)
	if err != nil {
		t.Fatal(err)
	}
	media, mc := f.consentMedia(ctx, t, true)
	text, tc := f.consentContent(ctx, t, f.owner)
	metaKey, metaPrefix := f.provisionalKey(ctx, t, "meta")
	meta, err := f.conns.Create(ctx, f.tenant, f.owner, consent(metaPrefix))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.pool.Exec(ctx, downStep(t, 45)); err != nil {
		t.Fatalf("0045 down-step: %v", err)
	}
	if _, err := f.pool.Exec(ctx, downStep(t, 44)); err != nil {
		t.Fatalf("down-step: %v", err)
	}
	var version int
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 43 {
		t.Fatalf("ledger at %d %v", version, err)
	}
	var tables, columns, constraints int
	if err := f.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name IN ('mcp_outbound','mcp_send_chats')),
		(SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='mcp_connections'
		   AND column_name IN ('send_mode','send_self','send_groups','send_paused_at')),
		(SELECT count(*) FROM pg_constraint WHERE conname='mcp_connections_send_coherent' AND connamespace=current_schema()::regnamespace)`).
		Scan(&tables, &columns, &constraints); err != nil || tables+columns+constraints != 0 {
		t.Fatalf("left: %d tables, %d columns, %d constraints %v", tables, columns, constraints, err)
	}
	for name, c := range map[string]contentConsent{"sending": sc, "pending sending": pendingSend} {
		if _, err := f.keys.Verify(ctx, c.key); !errors.Is(err, store.ErrInvalidKey) {
			t.Fatalf("the %s key survived: %v", name, err)
		}
		if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
			t.Fatalf("the %s service account kept %+v", name, tr)
		}
	}
	for name, key := range map[string]string{"media": mc.key, "text": tc.key, "metadata": metaKey} {
		if _, err := f.keys.Verify(ctx, key); err != nil {
			t.Fatalf("the %s key was revoked: %v", name, err)
		}
	}
	if tr := f.trace(ctx, t, f.owner); tr.grants != 1 || tr.memberships != 1 {
		t.Fatalf("the owner's access changed: %+v", tr)
	}
	want := map[string]string{sending.ID: "revoked", pending.ID: "revoked", media.ID: "active", text.ID: "active", meta.ID: "pending"}
	rows, err := f.pool.Query(ctx, `SELECT id::text, status, coalesce(consent_version, 0) FROM mcp_connections`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, status string
		var version int
		if err := rows.Scan(&id, &status, &version); err != nil {
			t.Fatal(err)
		}
		if status != want[id] || id == sending.ID && version != 3 {
			t.Fatalf("%s: %s version %d, want %s", id, status, version, want[id])
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if ids, err := f.conns.Unnotified(ctx, "enclave", 100); err != nil || len(ids) != 2 {
		t.Fatalf("unnotified = %v %v", ids, err)
	}

	if err := migrate.Run(ctx, f.pool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("re-applying 0044: %v", err)
	}
	listed, err := f.conns.List(ctx, f.tenant)
	if err != nil || len(listed) != 5 {
		t.Fatalf("list after re-applying = %+v %v", listed, err)
	}
	for _, l := range listed {
		if l.SendMode != "" || l.SendSelf || l.SendPausedAt != nil {
			t.Fatalf("row %s came back with sending", l.ID)
		}
		if l.ID == sending.ID && (l.ConsentVersion != 3 || l.Status != "revoked") {
			t.Fatalf("the sending row came back as %+v", l)
		}
	}
}
