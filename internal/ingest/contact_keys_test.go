package ingest_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waSyncAction"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
)

// routerWithClock is f.router with the sealers reading now.
func (f *fixture) routerWithClock(t *testing.T, now func() time.Time) *ingest.Router {
	t.Helper()
	r, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(string) (ingest.DeviceInfo, bool) {
			return ingest.DeviceInfo{TenantID: f.tenant}, true
		},
		Keys: f.keys, KeyStore: f.keys, Now: now,
		Messages: store.NewMessages(f.pool),
		Contacts: store.NewContacts(f.pool),
		Bus:      f.bus,
		Log:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestContactNamesAcrossContentKeys: each name of a contact arrives on its
// own, and the content key is replaced between them here, as after 15
// minutes. Every name still opens, each with the key its row names for it
// (DS50). Before, the row named only the newest write's key, and the
// names written earlier no longer opened.
func TestContactNamesAcrossContentKeys(t *testing.T) {
	f := newFixture(t)
	c := &clock{now: time.Now()}
	r := f.routerWithClock(t, c.Now)
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	go r.RunHistory(ctx)
	dev := f.device.String()

	r.Handle(ctx, dev, &events.Contact{JID: contactJID, Action: &waSyncAction.ContactAction{
		FullName: proto.String("José Silva"),
	}})
	c.advance(seal.MaxKeyAge)
	r.Handle(ctx, dev, &events.BusinessName{JID: contactJID, NewBusinessName: "Padaria do Zé"})
	c.advance(seal.MaxKeyAge)
	// The last through the history worker, as a bootstrap's names come.
	r.Handle(ctx, dev, &events.HistorySync{Data: &waHistorySync.HistorySync{
		SyncType: waHistorySync.HistorySync_PUSH_NAME.Enum(),
		Pushnames: []*waHistorySync.Pushname{
			{ID: proto.String(contactJID.String()), Pushname: proto.String("zé")},
		},
	}})

	var row store.ContactRow
	for deadline := time.Now().Add(15 * time.Second); len(row.PushNameSealed) == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the PUSH_NAME chunk named nobody")
		}
		row = f.contact(t, contactJID.String())
	}

	// The key each name was sealed under, as its envelope states it.
	under := func(sealed []byte) uint32 {
		t.Helper()
		id, _, err := seal.ContentKeyID(sealed)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	full, business, push := under(row.FullNameSealed), under(row.BusinessNameSealed), under(row.PushNameSealed)
	if full == business || business == push {
		t.Fatalf("names sealed under content keys %d, %d, %d: the sealer did not take a new key",
			full, business, push)
	}
	if row.ContentKeyID != push {
		t.Errorf("content_key_id = %d, want %d, the newest write's", row.ContentKeyID, push)
	}
	for _, n := range []struct {
		kind   seal.Kind
		id     uint32
		under  uint32
		sealed []byte
		want   string
	}{
		{seal.KindFullName, row.FullNameKeyID, full, row.FullNameSealed, "José Silva"},
		{seal.KindBusinessName, row.BusinessNameKeyID, business, row.BusinessNameSealed, "Padaria do Zé"},
		{seal.KindPushName, row.PushNameKeyID, push, row.PushNameSealed, "zé"},
	} {
		if n.id != n.under {
			t.Errorf("%s names content key %d, it was sealed under %d", n.kind, n.id, n.under)
			continue
		}
		if got := f.open(t, row.UID, n.kind, n.id, n.sealed); string(got) != n.want {
			t.Errorf("%s opened to %q, want %q", n.kind, got, n.want)
		}
	}
}

// TestImportedNamesShareOneContentKey: ImportContacts seals all of a
// contact's names in one call, so they share the content key the row
// names, and a reader that opens every name with content_key_id, as all
// did before DS50, still reads them. The clock moves past a key's age
// each time a sealer reads it, so every seal call takes a new key: sealed
// one name at a time, each name was under its own key.
func TestImportedNamesShareOneContentKey(t *testing.T) {
	f := newFixture(t)
	c := &clock{now: time.Now()}
	r := f.routerWithClock(t, func() time.Time {
		c.advance(seal.MaxKeyAge)
		return c.Now()
	})
	ctx := context.Background()
	dev := f.device.String()

	uid := store.ContactUID(f.device, "5511900000000@s.whatsapp.net")
	_, first, _, err := r.SealFor(ctx, f.tenant, f.device, uid, seal.KindPushName, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	_, second, _, err := r.SealFor(ctx, f.tenant, f.device, uid, seal.KindPushName, []byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("two seal calls shared content key %d: the clock does not force a new one", first)
	}

	n, err := r.ImportContacts(ctx, dev, map[types.JID]types.ContactInfo{
		contactJID: {Found: true, PushName: "zé", FullName: "José Silva", BusinessName: "Padaria do Zé"},
	})
	if err != nil || n != 1 {
		t.Fatalf("ImportContacts = %d, %v; want 1 contact", n, err)
	}
	row := f.contact(t, contactJID.String())
	for _, n := range []struct {
		kind   seal.Kind
		id     uint32
		sealed []byte
		want   string
	}{
		{seal.KindPushName, row.PushNameKeyID, row.PushNameSealed, "zé"},
		{seal.KindFullName, row.FullNameKeyID, row.FullNameSealed, "José Silva"},
		{seal.KindBusinessName, row.BusinessNameKeyID, row.BusinessNameSealed, "Padaria do Zé"},
	} {
		if n.id != row.ContentKeyID {
			t.Errorf("%s is under content key %d, the row names %d", n.kind, n.id, row.ContentKeyID)
			continue
		}
		if got := f.open(t, row.UID, n.kind, row.ContentKeyID, n.sealed); string(got) != n.want {
			t.Errorf("%s opened to %q, want %q", n.kind, got, n.want)
		}
	}
}
