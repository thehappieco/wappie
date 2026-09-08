package ingest_test

import (
	"context"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waSyncAction"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
)

var contactJID = types.JID{User: "5511977776666", Server: types.DefaultUserServer}

func (f *fixture) contact(t *testing.T, key string) store.ContactRow {
	t.Helper()
	rows, err := store.NewContacts(f.pool).List(context.Background(), f.tenant, f.device, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rows {
		if c.ContactKey == key {
			return c
		}
	}
	t.Fatalf("no contact %s among %d", key, len(rows))
	return store.ContactRow{}
}

// TestThreeKindsOfNameAreKeptApart.
//
// They are three different claims: what someone calls themselves, what this
// account saved them as, and what WhatsApp verified about a business. A reader
// that could not tell them apart would have to guess which it was showing, and
// the right choice depends on what the reader is for.
func TestThreeKindsOfNameAreKeptApart(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	dev := f.device.String()

	r.Handle(ctx, dev, &events.PushName{JID: contactJID, NewPushName: "zé da esquina"})
	r.Handle(ctx, dev, &events.Contact{JID: contactJID, Action: &waSyncAction.ContactAction{
		FullName: proto.String("José Silva"),
	}})
	r.Handle(ctx, dev, &events.BusinessName{JID: contactJID, NewBusinessName: "Padaria do Zé"})

	c := f.contact(t, contactJID.String())
	for _, want := range []struct {
		kind   seal.Kind
		sealed []byte
		text   string
	}{
		{seal.KindPushName, c.PushNameSealed, "zé da esquina"},
		{seal.KindFullName, c.FullNameSealed, "José Silva"},
		{seal.KindBusinessName, c.BusinessNameSealed, "Padaria do Zé"},
	} {
		if len(want.sealed) == 0 {
			t.Fatalf("%s was not stored", want.kind)
		}
		got := f.open(t, c.UID, want.kind, c.ContentKeyID, want.sealed)
		if string(got) != want.text {
			t.Errorf("%s opened as %q, want %q", want.kind, got, want.text)
		}
	}
}

// TestANameIsNeverErasedByOneThatWasNotStated.
//
// A push name arrives with every message a contact sends and says nothing about
// the address book. Letting it clear a saved name would lose the better of the
// two on the next message.
func TestANameIsNeverErasedByOneThatWasNotStated(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	dev := f.device.String()

	r.Handle(ctx, dev, &events.Contact{JID: contactJID, Action: &waSyncAction.ContactAction{
		FullName: proto.String("José Silva"),
	}})
	r.Handle(ctx, dev, &events.PushName{JID: contactJID, NewPushName: "zé"})

	c := f.contact(t, contactJID.String())
	if len(c.FullNameSealed) == 0 {
		t.Fatal("the saved name was erased by a push name that said nothing about it")
	}
	if got := f.open(t, c.UID, seal.KindFullName, c.ContentKeyID, c.FullNameSealed); string(got) != "José Silva" {
		t.Fatalf("saved name = %q", got)
	}
}

// TestNamesAreNotLegibleInTheDatabase. A dump that revealed who the identifiers
// belong to would hand over most of what a social graph is.
func TestNamesAreNotLegibleInTheDatabase(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	r.Handle(context.Background(), f.device.String(),
		&events.PushName{JID: contactJID, NewPushName: "um nome secreto"})

	c := f.contact(t, contactJID.String())
	if string(c.PushNameSealed) == "um nome secreto" {
		t.Fatal("the name is in the database in the clear")
	}
	if len(c.PushNameSealed) == 0 {
		t.Fatal("the name was not stored at all")
	}
}

// TestABootstrapNamesEveryoneAtOnce.
//
// This is where the bulk arrives. Without it a re-paired archive shows hundreds
// of conversations as bare phone numbers, because nothing on the live path
// carries a name until the person sends something.
func TestABootstrapNamesEveryoneAtOnce(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	go r.RunHistory(ctx)

	sync := &waHistorySync.HistorySync{
		SyncType: waHistorySync.HistorySync_PUSH_NAME.Enum(),
		Pushnames: []*waHistorySync.Pushname{
			{ID: proto.String(contactJID.String()), Pushname: proto.String("Zé")},
			{ID: proto.String("5511911112222@s.whatsapp.net"), Pushname: proto.String("Maria")},
		},
	}
	r.Handle(ctx, f.device.String(), &events.HistorySync{Data: sync})

	contacts := store.NewContacts(f.pool)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := contacts.List(ctx, f.tenant, f.device, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a PUSH_NAME chunk named nobody")
}

// TestAnAvatarIsSealedAndBoundToItsContact.
//
// Profile pictures are the one thing here that arrives unencrypted: WhatsApp
// serves them over plain HTTP to anyone with the URL. So unlike message media
// there is no ciphertext to keep, and the bytes are sealed on the way in.
func TestAnAvatarIsSealedAndBoundToItsContact(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	contacts := store.NewContacts(f.pool)

	picture := []byte("\xFF\xD8\xFF a face, in bytes")
	uid := store.ContactUID(f.device, contactJID.String())
	sealed, keyID, err := r.SealFor(ctx, f.tenant, f.device, uid, seal.KindAvatar, picture)
	if err != nil {
		t.Fatal(err)
	}
	if err := contacts.SetAvatar(ctx, f.tenant, f.device,
		contactJID.String(), "pic-1", sealed, keyID); err != nil {
		t.Fatal(err)
	}

	got, gotKey, gotUID, err := contacts.Avatar(ctx, f.tenant, f.device, contactJID.String())
	if err != nil {
		t.Fatal(err)
	}
	if gotUID != uid {
		t.Fatalf("uid = %s, want %s", gotUID, uid)
	}
	opened := f.open(t, gotUID, seal.KindAvatar, gotKey, got)
	if string(opened) != string(picture) {
		t.Fatal("the picture did not survive the round trip")
	}

	// And it does not open against a different contact.
	other := store.ContactUID(f.device, "5511911112222@s.whatsapp.net")
	blob, err := f.keys.SealedContentKey(ctx, f.tenant, f.device, gotKey)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := seal.OpenContentKey(f.priv, f.tenant, f.device, gotKey, blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ck.Open(seal.KindAvatar, f.tenant, other, got); err == nil {
		t.Fatal("a contact's picture opened against a different contact")
	}
}

// TestAContactWithNoPictureIsNotAskedForever. Recording the check is what lets
// the queue make progress: without it the same few are asked on every pass and
// the ones never asked never get a turn.
func TestAContactWithNoPictureIsNotAskedForever(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	contacts := store.NewContacts(f.pool)

	if err := contacts.Upsert(ctx, store.ContactName{
		TenantID: f.tenant, DeviceID: f.device,
		ContactKey: contactJID.String(), ContactPN: contactJID.String(),
	}); err != nil {
		t.Fatal(err)
	}

	pending, err := contacts.NeedAvatar(ctx, f.tenant, f.device, time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("got %d contacts needing a picture, want 1", len(pending))
	}

	if err := contacts.TouchAvatar(ctx, f.tenant, f.device, contactJID.String()); err != nil {
		t.Fatal(err)
	}
	if pending, err = contacts.NeedAvatar(ctx, f.tenant, f.device, time.Hour, 10); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatal("a contact just asked about is queued again immediately")
	}
}

// TestAChangedPictureIsQueuedRatherThanFetched.
//
// events.Picture arrives on whatsmeow's event goroutine, which is the goroutine
// reading the socket: fetching a face there stops the device receiving anything
// — messages, receipts, connection events — for as long as the HTTP request
// takes. That is the same reason history sync is ingested off it, and it is a
// stall nothing reports, because the device looks connected the whole time.
//
// So the handler only marks the row. Two consequences are asserted here because
// both are easy to break: the old picture stays on screen until a new one
// actually arrives, and the row goes back into the worker's queue.
func TestAChangedPictureIsQueuedRatherThanFetched(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	contacts := store.NewContacts(f.pool)

	if err := contacts.SetAvatar(ctx, f.tenant, f.device,
		contactJID.String(), "pic-1", []byte("sealed face"), 1); err != nil {
		t.Fatal(err)
	}

	// With a device suffix, as the event can carry it. A contact is a person.
	changed := contactJID
	changed.Device = 3
	r.Handle(ctx, f.device.String(), &events.Picture{
		JID: changed, Author: contactJID, Timestamp: time.Now(), PictureID: "pic-2",
	})

	c := f.contact(t, contactJID.String())
	if c.AvatarChecked != nil {
		t.Error("the picture was not marked for refetching, so the stale face is permanent")
	}
	if !c.HasAvatar {
		t.Error("the stored picture was dropped; the reader draws a placeholder until the " +
			"paced worker gets around to this row")
	}

	pending, err := contacts.NeedAvatar(ctx, f.tenant, f.device, 7*24*time.Hour, 50)
	if err != nil {
		t.Fatal(err)
	}
	var queued bool
	for _, row := range pending {
		if row.ContactKey == contactJID.String() {
			queued = true
		}
	}
	if !queued {
		t.Error("a contact whose picture changed is not in the worker's queue")
	}
}
