package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The chat list carries the newest message of each conversation so a client can
// draw a preview without one request per row — five hundred round trips to
// paint a sidebar. What is easy to get wrong is *which* row that is, and the
// failure is quiet: the list shows the second-newest message and looks like a
// client that has stopped updating.

func chatFixture(t *testing.T) (*store.Messages, uuid.UUID, uuid.UUID) {
	t.Helper()
	m, tenant, device, _ := chatFixtureWithPool(t)
	return m, tenant, device
}

// chatFixtureWithPool also hands back the pool, for the stores that are built
// separately from Messages.
func chatFixtureWithPool(t *testing.T) (*store.Messages, uuid.UUID, uuid.UUID, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	tenantID := newTenant(t, pool, "acme")
	dev, err := store.NewDevices(pool).Create(context.Background(), tenantID, "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	return store.NewMessages(pool), uuid.MustParse(tenantID), uuid.MustParse(dev.ID), pool
}

func insert(t *testing.T, m *store.Messages, tenant, device uuid.UUID,
	chatKey, waID string, kind domain.Kind, at time.Time, body string) store.InsertResult {
	t.Helper()
	res, err := m.Insert(context.Background(), store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: waID, ChatKey: chatKey, ChatPN: chatKey,
		TS: at.Truncate(time.Second), Kind: kind, Type: domain.TypeText,
		Source: domain.SourceLive, ContentKeyID: 1, BodySealed: []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func chatFor(t *testing.T, m *store.Messages, tenant, device uuid.UUID, chatKey string) store.ChatRow {
	t.Helper()
	rows, err := m.Chats(context.Background(), tenant, device, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rows {
		if c.ChatKey == chatKey {
			return c
		}
	}
	t.Fatalf("no chat %s in the list", chatKey)
	return store.ChatRow{}
}

func TestTheChatListCarriesTheNewestMessage(t *testing.T) {
	messages, tenant, device := chatFixture(t)
	const chat = "5511999999999@s.whatsapp.net"
	now := time.Now()

	insert(t, messages, tenant, device, chat, "A1", domain.KindMessage, now.Add(-2*time.Minute), "primeira")
	last := insert(t, messages, tenant, device, chat, "A2", domain.KindMessage, now, "última")

	got := chatFor(t, messages, tenant, device, chat)
	if got.LastUID != last.UID {
		t.Fatalf("the preview points at %s, want the newest row %s", got.LastUID, last.UID)
	}
	if string(got.LastBodySealed) != "última" {
		t.Fatalf("the preview body is %q", got.LastBodySealed)
	}
	if got.LastBodyKeyID != 1 {
		t.Fatalf("the preview key id is %d, so a client could not open it", got.LastBodyKeyID)
	}
}

// The preview follows the newest row by sequence, not by whatever last_seq
// happened to be written. A control row is the newest thing that happened, and
// a list that skipped it would keep showing text that has since been edited or
// deleted.
func TestTheNewestRowMayBeAControlRow(t *testing.T) {
	messages, tenant, device := chatFixture(t)
	const chat = "5511999999999@s.whatsapp.net"
	now := time.Now()

	insert(t, messages, tenant, device, chat, "A1", domain.KindMessage, now.Add(-time.Minute), "antes")
	edit := insert(t, messages, tenant, device, chat, "A2", domain.KindEdit, now, "depois")

	got := chatFor(t, messages, tenant, device, chat)
	if got.LastUID != edit.UID {
		t.Fatalf("the preview points at %s, want the edit %s", got.LastUID, edit.UID)
	}
	if got.LastKind != string(domain.KindEdit) {
		t.Fatalf("last_kind is %q; without it a client cannot tell an edit from a message",
			got.LastKind)
	}
}

func TestAConversationWithNothingToPreview(t *testing.T) {
	messages, tenant, device := chatFixture(t)
	const chat = "5511999999999@s.whatsapp.net"

	// A revoke carries no body. The row must still be named, so the client can
	// say "apagou" rather than showing the previous message as if it stood.
	res, err := messages.Insert(context.Background(), store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: "D1", ChatKey: chat, ChatPN: chat,
		TS: time.Now().Truncate(time.Second), Kind: domain.KindDelete, Type: domain.TypeText,
		Source: domain.SourceLive,
	})
	if err != nil {
		t.Fatal(err)
	}

	got := chatFor(t, messages, tenant, device, chat)
	if got.LastUID != res.UID {
		t.Fatalf("the preview points at %s, want %s", got.LastUID, res.UID)
	}
	if len(got.LastBodySealed) != 0 {
		t.Fatalf("a revoke came back with a body: %q", got.LastBodySealed)
	}
	if got.LastBodyKeyID != 0 {
		t.Fatalf("a row with no body reported key %d", got.LastBodyKeyID)
	}
}

func TestEachConversationPreviewsItsOwnNewest(t *testing.T) {
	messages, tenant, device := chatFixture(t)
	const one = "5511911111111@s.whatsapp.net"
	const two = "5511922222222@s.whatsapp.net"
	now := time.Now()

	insert(t, messages, tenant, device, one, "A1", domain.KindMessage, now.Add(-3*time.Minute), "um antigo")
	insert(t, messages, tenant, device, two, "B1", domain.KindMessage, now.Add(-2*time.Minute), "dois antigo")
	insert(t, messages, tenant, device, one, "A2", domain.KindMessage, now.Add(-time.Minute), "um novo")
	insert(t, messages, tenant, device, two, "B2", domain.KindMessage, now, "dois novo")

	// The lateral is per chat. A join written against the whole table would
	// give every row the same preview, which reads as plausible until two
	// conversations show the same line.
	if body := string(chatFor(t, messages, tenant, device, one).LastBodySealed); body != "um novo" {
		t.Fatalf("chat one previews %q", body)
	}
	if body := string(chatFor(t, messages, tenant, device, two).LastBodySealed); body != "dois novo" {
		t.Fatalf("chat two previews %q", body)
	}
}
