package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// A group message that also carried a Signal sender key used to arrive twice
// under one message id: the key first, classified as "unsupported" and written,
// then the real message -- rejected as a duplicate of the placeholder that had
// taken its row. 661 group messages on one installation were replaced that way.
//
// The classifier no longer stores those keys, but the placeholders are already
// written, and while they hold the (device, chat, wa_id) slot no history sync
// can put the real message back. So a row carrying nothing gives way to one
// carrying something.
//
// The dangerous version of this fix overwrites real messages. These tests are
// mostly about what must NOT be replaced.

func stub(t *testing.T, m *store.Messages, tenant, device uuid.UUID, chat, waID string) uuid.UUID {
	t.Helper()
	return stubAs(t, m, placeholder(tenant, device, chat, waID))
}

// placeholder is the row a sender key took, before the real message.
func placeholder(tenant, device uuid.UUID, chat, waID string) store.InsertMessage {
	return store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: waID, ChatKey: chat, ChatPN: chat,
		SenderKey: stubSender, SenderPN: stubSender,
		Kind: domain.KindMessage, Type: domain.TypeUnsupported,
		Source: domain.SourceLive, TS: stubTS,
		Unsupported: "senderKeyDistributionMessage",
	}
}

func stubAs(t *testing.T, m *store.Messages, in store.InsertMessage) uuid.UUID {
	t.Helper()
	res, err := m.Insert(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return res.UID
}

// stubTS is when the placeholder and its real message were sent.
var stubTS = time.Now().Truncate(time.Second)

// stubSender sent the placeholder and its real message.
const stubSender = "5511988887777@s.whatsapp.net"

// realMessage is the message a placeholder took the slot of, sealed to uid.
func realMessage(uid, tenant, device uuid.UUID, chat, waID, body string) store.InsertMessage {
	return store.InsertMessage{
		UID: uid, TenantID: tenant, DeviceID: device,
		WAID: waID, ChatKey: chat, ChatPN: chat,
		SenderKey: stubSender, SenderPN: stubSender,
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: stubTS, ContentKeyID: 1, BodySealed: []byte(body),
	}
}

func only(t *testing.T, m *store.Messages, tenant, device uuid.UUID, chat string) store.Row {
	t.Helper()
	rows, err := m.Page(context.Background(), tenant, device, []string{chat}, store.Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	return rows[0]
}

func TestARealMessageReplacesTheStubThatStoleItsPlace(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	uid := stub(t, m, tenant, device, chat, waID)
	// The real message, arriving second, under the same id, sealed to the
	// placeholder's uid (DS51).
	res, err := m.Insert(context.Background(), realMessage(uid, tenant, device, chat, waID, "a mensagem de verdade"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Filled || !res.Duplicate || res.UID != uid {
		t.Errorf("result = %+v, want the placeholder's row filled", res)
	}

	row := only(t, m, tenant, device, chat)
	if row.UID != uid {
		t.Errorf("uid = %v, want the placeholder's %v", row.UID, uid)
	}
	if row.Type != domain.TypeText {
		t.Errorf("type = %s, want text — the placeholder is still holding the row", row.Type)
	}
	if string(row.BodySealed) != "a mensagem de verdade" {
		t.Errorf("body = %q, want the real message", row.BodySealed)
	}
	if row.Unsupported != "" {
		t.Errorf("unsupported_field = %q, want it cleared", row.Unsupported)
	}
}

func TestARealMessageIsNeverOverwritten(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	insert(t, m, tenant, device, chat, waID, domain.KindMessage, time.Now(), "o original")
	// The same message again, as a history sync delivers it, with a different
	// body. Idempotency is the whole point of the conflict clause: the second
	// copy must change nothing.
	insert(t, m, tenant, device, chat, waID, domain.KindMessage, time.Now(), "uma cópia diferente")

	if body := string(only(t, m, tenant, device, chat).BodySealed); body != "o original" {
		t.Errorf("body = %q, want the first one stored", body)
	}
}

func TestAStubIsNotReplacedByAnotherStub(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	stub(t, m, tenant, device, chat, waID)
	stub(t, m, tenant, device, chat, waID)

	row := only(t, m, tenant, device, chat)
	if row.Type != domain.TypeUnsupported {
		t.Errorf("type = %s, want it left alone", row.Type)
	}
	if row.Unsupported != "senderKeyDistributionMessage" {
		t.Errorf("unsupported_field = %q, want the name kept", row.Unsupported)
	}
}

func TestAnEmptyMessageDoesNotClearAStub(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	stub(t, m, tenant, device, chat, waID)

	// Something classified but carrying nothing — a control row, say. It has no
	// content to contribute, so replacing the placeholder with it would trade
	// one empty row for another and lose the field name that says what happened.
	_, err := m.Insert(context.Background(), store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: waID, ChatKey: chat, ChatPN: chat,
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: time.Now().Truncate(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	if row := only(t, m, tenant, device, chat); row.Unsupported != "senderKeyDistributionMessage" {
		t.Errorf("unsupported_field = %q; an empty message took the row", row.Unsupported)
	}
}

// TestAFillSealedToAnotherUIDWritesNothing (DS51): the row keeps the
// placeholder's uid, and a sealed value opens only under the uid it was
// sealed to. A message sealed to another uid would read as tampered there,
// so it fills nothing and is told the placeholder's uid.
func TestAFillSealedToAnotherUIDWritesNothing(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	uid := stub(t, m, tenant, device, chat, waID)
	in := realMessage(uuid.New(), tenant, device, chat, waID, "selada para outra linha")
	in.Media = &store.InsertMedia{MediaType: "image", MimeType: "image/jpeg", MediaKeySealed: []byte("key")}
	_, err := m.Insert(context.Background(), in)
	var fill *store.PlaceholderError
	if !errors.As(err, &fill) || fill.UID != uid {
		t.Fatalf("err = %v, want a PlaceholderError naming %v", err, uid)
	}

	row := only(t, m, tenant, device, chat)
	if row.Type != domain.TypeUnsupported || len(row.BodySealed) != 0 || row.Media != nil {
		t.Errorf("row = %s, body %q, media %v: a fill sealed to another uid was written",
			row.Type, row.BodySealed, row.Media)
	}
}

// TestAFillKeepsItsAttachment (DS51): the attachment's row is written
// with the fill, under the placeholder's uid, and the chat list stops
// saying "unsupported" about it.
func TestAFillKeepsItsAttachment(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	uid := stub(t, m, tenant, device, chat, waID)
	if got := chatFor(t, m, tenant, device, chat).LastType; got != string(domain.TypeUnsupported) {
		t.Fatalf("chat last_type = %q before the fill, want unsupported", got)
	}
	in := realMessage(uid, tenant, device, chat, waID, "a legenda")
	in.Type = domain.TypeImage
	in.Media = &store.InsertMedia{
		MediaType: "image", MimeType: "image/jpeg", FileLength: 42,
		MediaKeySealed: []byte("key"), ThumbSealed: []byte("thumb"),
	}
	res, err := m.Insert(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Filled {
		t.Fatalf("result = %+v, want filled", res)
	}

	row := only(t, m, tenant, device, chat)
	if row.Type != domain.TypeImage {
		t.Errorf("type = %s, want image", row.Type)
	}
	if row.Media == nil {
		t.Fatal("no media row: the fill dropped the attachment")
	}
	if string(row.Media.MediaKeySealed) != "key" || string(row.Media.ThumbSealed) != "thumb" {
		t.Errorf("media = %+v", row.Media)
	}
	if row.Media.DownloadStatus != "pending" {
		t.Errorf("download_status = %q, want pending", row.Media.DownloadStatus)
	}
	if got := chatFor(t, m, tenant, device, chat).LastType; got != string(domain.TypeImage) {
		t.Errorf("chat last_type = %q, want image", got)
	}
}

// TestOnlyItsSenderFillsAPlaceholder (DS51): a fill opens cleanly now, so
// content from anyone but the placeholder's sender must not land in it.
// Another member reusing the id, a contact reusing the id of my message,
// or a message with no sender is a plain duplicate: nothing is filled,
// and no PlaceholderError asks for a second seal.
func TestOnlyItsSenderFillsAPlaceholder(t *testing.T) {
	const other = "5511977776666@s.whatsapp.net"
	for _, c := range []struct {
		name        string
		placeholder func(in *store.InsertMessage)
		message     func(in *store.InsertMessage)
	}{
		{"another member", nil, func(in *store.InsertMessage) {
			in.SenderKey, in.SenderPN = other, other
		}},
		{"no sender", nil, func(in *store.InsertMessage) {
			in.SenderKey, in.SenderPN = "", ""
		}},
		{"a contact reusing my message's id", func(in *store.InsertMessage) {
			in.IsFromMe, in.SenderKey, in.SenderPN = true, "", ""
		}, func(in *store.InsertMessage) {
			in.SenderKey, in.SenderPN = other, other
		}},
		{"the same sender, marked as mine", nil, func(in *store.InsertMessage) {
			in.IsFromMe = true
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, tenant, device := chatFixture(t)
			ctx := context.Background()
			const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"
			p := placeholder(tenant, device, chat, waID)
			if c.placeholder != nil {
				c.placeholder(&p)
			}
			uid := stubAs(t, m, p)
			for _, sealedTo := range []uuid.UUID{uuid.New(), uid} {
				in := realMessage(sealedTo, tenant, device, chat, waID, "de outra pessoa")
				c.message(&in)
				res, err := m.Insert(ctx, in)
				if err != nil {
					t.Fatalf("sealed to %v: %v, want a plain duplicate", sealedTo, err)
				}
				if !res.Duplicate || res.Filled || res.UID != uid {
					t.Errorf("sealed to %v: %+v, want a plain duplicate of the placeholder", sealedTo, res)
				}
			}
			if row := only(t, m, tenant, device, chat); row.Type != domain.TypeUnsupported || len(row.BodySealed) != 0 {
				t.Errorf("row = %s, body %q: another sender's message filled the placeholder", row.Type, row.BodySealed)
			}
		})
	}
}

// TestItsSenderFillsAPlaceholderUnderEitherName (DS51): a history sync may
// name the sender by the other half, LID or phone number. One half both
// sides know is enough. My own messages match on is_from_me alone: only
// my devices send them, and older rows of mine have no sender.
func TestItsSenderFillsAPlaceholderUnderEitherName(t *testing.T) {
	const lid, pn = "123456789012345@lid", "5511988887777@s.whatsapp.net"
	for _, c := range []struct {
		name        string
		placeholder func(in *store.InsertMessage)
		message     func(in *store.InsertMessage)
	}{
		{"by phone number, stored by LID", func(in *store.InsertMessage) {
			in.SenderKey, in.SenderLID, in.SenderPN = lid, lid, pn
		}, func(in *store.InsertMessage) {
			in.SenderKey, in.SenderLID, in.SenderPN = pn, "", pn
		}},
		{"by LID, stored by phone number", func(in *store.InsertMessage) {
			in.SenderKey, in.SenderLID, in.SenderPN = pn, "", pn
		}, func(in *store.InsertMessage) {
			in.SenderKey, in.SenderLID, in.SenderPN = lid, lid, pn
		}},
		{"by LID only", func(in *store.InsertMessage) {
			in.SenderKey, in.SenderLID, in.SenderPN = lid, lid, ""
		}, func(in *store.InsertMessage) {
			in.SenderKey, in.SenderLID, in.SenderPN = lid, lid, ""
		}},
		{"mine, with no sender stored", func(in *store.InsertMessage) {
			in.IsFromMe, in.SenderKey, in.SenderPN = true, "", ""
		}, func(in *store.InsertMessage) {
			in.IsFromMe = true
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, tenant, device := chatFixture(t)
			const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"
			p := placeholder(tenant, device, chat, waID)
			c.placeholder(&p)
			uid := stubAs(t, m, p)
			in := realMessage(uid, tenant, device, chat, waID, "a mensagem de verdade")
			c.message(&in)
			res, err := m.Insert(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Filled {
				t.Errorf("result = %+v, want the placeholder filled", res)
			}
			if row := only(t, m, tenant, device, chat); row.Type != domain.TypeText {
				t.Errorf("type = %s, want text", row.Type)
			}
		})
	}
}

// TestAProtocolPlaceholderIsFilled (DS51): the browser's reproject retypes
// a sender key's placeholder as protocol (MarkProtocol). That is the row
// fillStub exists for, so the real message still fills it.
func TestAProtocolPlaceholderIsFilled(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"
	uid := stub(t, m, tenant, device, chat, waID)
	if err := m.MarkProtocol(context.Background(), tenant, device, uid); err != nil {
		t.Fatal(err)
	}
	res, err := m.Insert(context.Background(), realMessage(uid, tenant, device, chat, waID, "a mensagem de verdade"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Filled || res.UID != uid {
		t.Errorf("result = %+v, want the protocol placeholder filled", res)
	}
	if row := only(t, m, tenant, device, chat); row.Type != domain.TypeText || string(row.BodySealed) != "a mensagem de verdade" {
		t.Errorf("row = %s, body %q", row.Type, row.BodySealed)
	}
	if got := chatFor(t, m, tenant, device, chat).LastType; got != string(domain.TypeText) {
		t.Errorf("chat last_type = %q, want text", got)
	}
}

// TestAFillLeavesANewerPreviewAlone (DS51): the chat list shows the newest
// message by timestamp. Filling an older placeholder must not change it.
func TestAFillLeavesANewerPreviewAlone(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"
	uid := stub(t, m, tenant, device, chat, waID)
	newer := placeholder(tenant, device, chat, "3AD9FC72C86E3D46A831")
	newer.TS = stubTS.Add(time.Minute)
	stubAs(t, m, newer)

	res, err := m.Insert(context.Background(), realMessage(uid, tenant, device, chat, waID, "a mensagem de verdade"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Filled {
		t.Fatalf("result = %+v, want filled", res)
	}
	if got := chatFor(t, m, tenant, device, chat).LastType; got != string(domain.TypeUnsupported) {
		t.Errorf("chat last_type = %q, want the newer placeholder's unsupported", got)
	}
}

// TestASealForAGonePlaceholderWritesNothing (DS51): a message sealed to a
// placeholder's uid, after a purge deleted the placeholder. A new row
// under that uid would give a deleted row's uid to another row, so
// nothing is written and the caller seals again to a fresh uid.
func TestASealForAGonePlaceholderWritesNothing(t *testing.T) {
	m, tenant, device, pool := chatFixtureWithPool(t)
	ctx := context.Background()
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"
	lastSeq := func() int64 {
		t.Helper()
		var seq int64
		if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT last_seq FROM tenants WHERE id = $1`, tenant).Scan(&seq)
		}); err != nil {
			t.Fatal(err)
		}
		return seq
	}
	before := lastSeq()

	in := realMessage(uuid.New(), tenant, device, chat, waID, "a mensagem de verdade")
	in.FillsPlaceholder = true
	if _, err := m.Insert(ctx, in); !errors.Is(err, store.ErrPlaceholderGone) {
		t.Fatalf("err = %v, want ErrPlaceholderGone", err)
	}
	rows, err := m.Page(ctx, tenant, device, []string{chat}, store.Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("%d rows stored under a gone placeholder's uid", len(rows))
	}
	if after := lastSeq(); after != before {
		t.Errorf("last_seq %d, then %d: a sequence was taken", before, after)
	}
}

// TestAFillTakesTheWorkspaceFirst: a reset takes the workspace's row, then
// deletes messages. A fill that locked its message first and then waited
// for the workspace would deadlock with it. The update's statement
// trigger (storage_lock) takes the workspace first, so the fill holds
// nothing on the message while it waits.
func TestAFillTakesTheWorkspaceFirst(t *testing.T) {
	w := newKeyWorld(t)
	m := store.NewMessages(w.pool)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"
	uid := stub(t, m, w.tenant, w.device, chat, waID)

	type result struct {
		res store.InsertResult
		err error
	}
	done := make(chan result, 1)
	err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		// What the reset holds first.
		if _, err := tx.Exec(ctx, `SELECT id FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
			return err
		}
		go func() {
			res, err := m.Insert(ctx, realMessage(uid, w.tenant, w.device, chat, waID, "a mensagem de verdade"))
			done <- result{res, err}
		}()
		for {
			waiting, err := w.backends.Waiting(ctx, w.pool)
			if err != nil {
				return err
			}
			if waiting {
				break
			}
			select {
			case r := <-done:
				return fmt.Errorf("the fill did not wait for the workspace: %+v, %w", r.res, r.err)
			case <-time.After(10 * time.Millisecond):
			}
		}
		// The reset's delete would lock the row now.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM messages WHERE uid = $1 FOR UPDATE NOWAIT`, uid); err != nil {
			return fmt.Errorf("the waiting fill holds the message's row: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || !r.res.Filled {
		t.Fatalf("after the workspace was free: %+v, %v; want filled", r.res, r.err)
	}
}
