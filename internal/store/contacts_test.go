package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func contactFixture(t *testing.T) (*pgxpool.Pool, uuid.UUID, uuid.UUID, *store.Contacts) {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	tenantID := newTenant(t, pool, "acme")
	dev, err := store.NewDevices(pool).Create(context.Background(), tenantID, "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	return pool, uuid.MustParse(tenantID), uuid.MustParse(dev.ID), store.NewContacts(pool)
}

// TestSomeReturnsOnlyWhatWasAskedFor covers the read behind contacts.resolve.
//
// The failure it guards against is quiet in exactly the wrong way: a query that
// matched too broadly would still render a correct sidebar, because a client
// indexes what it gets by key and ignores the rest. It would just move the
// whole contact table over the socket every time a conversation appeared.
func TestSomeReturnsOnlyWhatWasAskedFor(t *testing.T) {
	_, tenant, device, contacts := contactFixture(t)
	ctx := context.Background()

	for _, key := range []string{"1@s.whatsapp.net", "2@s.whatsapp.net", "3@s.whatsapp.net"} {
		if err := contacts.Upsert(ctx, store.ContactName{
			TenantID: tenant, DeviceID: device,
			ContactKey: key, ContactPN: key,
			ContentKeyID:   1,
			PushNameSealed: []byte("sealed"),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// One that exists, one that never did. An absent key is an ordinary
	// answer, not an error: a client asks about identifiers it has seen on
	// messages, and nothing promises a contact row was ever written for them.
	rows, err := contacts.Some(ctx, tenant, device,
		[]string{"2@s.whatsapp.net", "404@s.whatsapp.net"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ContactKey != "2@s.whatsapp.net" {
		t.Fatalf("Some returned %+v, want just the one asked for that exists", rows)
	}

	if empty, err := contacts.Some(ctx, tenant, device, nil); err != nil || empty != nil {
		t.Fatalf("Some(nil) = %v, %v; want no rows and no error", empty, err)
	}
}

// TestInvalidateAvatarKeepsThePicture is the whole point of the column choice.
//
// events.Picture says a face changed. Clearing avatar_sealed there would be the
// obvious reading and is wrong: the worker is paced, so the row would render a
// placeholder for however long the refetch takes — a visible regression caused
// by learning that a *better* picture exists. Only the check time is cleared,
// which moves the row to the front of the queue and leaves the old face on
// screen until a new one arrives.
func TestInvalidateAvatarKeepsThePicture(t *testing.T) {
	_, tenant, device, contacts := contactFixture(t)
	ctx := context.Background()
	const key = "5511999999999@s.whatsapp.net"

	if err := contacts.SetAvatar(ctx, tenant, device, key, "pic-1", []byte("sealed face"), 7, nil); err != nil {
		t.Fatal(err)
	}
	before, err := contacts.Some(ctx, tenant, device, []string{key})
	if err != nil || len(before) != 1 {
		t.Fatalf("Some = %v, %v", before, err)
	}
	if before[0].AvatarChecked == nil {
		t.Fatal("SetAvatar left avatar_checked_at null; the worker would ask again forever")
	}

	if err := contacts.InvalidateAvatar(ctx, tenant, device, key); err != nil {
		t.Fatal(err)
	}
	after, err := contacts.Some(ctx, tenant, device, []string{key})
	if err != nil || len(after) != 1 {
		t.Fatalf("Some = %v, %v", after, err)
	}
	if after[0].AvatarChecked != nil {
		t.Error("invalidating did not clear the check time, so the row never gets re-asked")
	}
	if !after[0].HasAvatar {
		t.Error("invalidating dropped the stored picture; the reader now draws a placeholder")
	}
	if after[0].AvatarID != "pic-1" {
		t.Errorf("avatar id = %q, want it kept so WhatsApp can answer 'unchanged'", after[0].AvatarID)
	}

	// NeedAvatar is the worker's queue, and the row has to be back in it.
	pending, err := contacts.NeedAvatar(ctx, tenant, device, 7*24*time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	var queued bool
	for _, row := range pending {
		if row.ContactKey == key {
			queued = true
		}
	}
	if !queued {
		t.Error("an invalidated contact is not in the worker's queue, so the new picture never arrives")
	}
}

// TestInvalidateAvatarFindsTheOtherHalfOfAnIdentity.
//
// contact_key is whichever identifier Address.Primary chose when the row was
// written — the LID, when both halves are known. events.Picture can name the
// phone number instead, and a WHERE on contact_key alone then updates nothing.
// Postgres reports success, pgx reports success, nothing logs. The symptom is a
// profile picture that stays stale for the seven days of the staleness window,
// because that event is the only thing that can shorten it.
func TestInvalidateAvatarFindsTheOtherHalfOfAnIdentity(t *testing.T) {
	_, tenant, device, contacts := contactFixture(t)
	ctx := context.Background()
	const lid = "42631895773279@lid"
	const pn = "5511999999999@s.whatsapp.net"

	if err := contacts.Upsert(ctx, store.ContactName{
		TenantID: tenant, DeviceID: device,
		ContactKey: lid, ContactLID: lid, ContactPN: pn,
		ContentKeyID: 1, PushNameSealed: []byte("sealed"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := contacts.SetAvatar(ctx, tenant, device, lid, "pic-1", []byte("face"), 1, nil); err != nil {
		t.Fatal(err)
	}

	// Named by the half that is NOT the key.
	if err := contacts.InvalidateAvatar(ctx, tenant, device, pn); err != nil {
		t.Fatal(err)
	}
	rows, err := contacts.Some(ctx, tenant, device, []string{lid})
	if err != nil || len(rows) != 1 {
		t.Fatalf("Some = %v, %v", rows, err)
	}
	if rows[0].AvatarChecked != nil {
		t.Error("a picture event naming the phone number left the LID-keyed row untouched, " +
			"silently, so the stale face stays for the whole staleness window")
	}
	if !rows[0].HasAvatar {
		t.Error("the stored picture was dropped")
	}
}

// TestContactNamesUnderTwoContentKeys: a contact's names are written one
// at a time, and a content key is replaced after 1000 seals or 15 minutes.
// A name sealed under one key stays readable after another name of the
// same contact is sealed under the next. The row's content_key_id is the
// newest write's key, so it no longer opens the first name. Each name's
// own key id, read from its envelope, does (DS50).
func TestContactNamesUnderTwoContentKeys(t *testing.T) {
	pool, tenant, device, contacts := contactFixture(t)
	ctx := context.Background()
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := store.NewKeys(pool)
	if err := keys.CreateArchiveKey(ctx, tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.NewSealer(tenant, device, pub, 1, keys)
	if err != nil {
		t.Fatal(err)
	}
	const key = "5511977776666@s.whatsapp.net"
	uid := store.ContactUID(device, key)

	// write seals one name and stores it alone, as ingest does for each
	// name event, then makes the sealer take a new content key.
	write := func(kind seal.Kind, name string) uint32 {
		t.Helper()
		out, id, err := sealer.SealAll(ctx, uid, map[seal.Kind][]byte{kind: []byte(name)})
		if err != nil {
			t.Fatal(err)
		}
		in := store.ContactName{TenantID: tenant, DeviceID: device, ContactKey: key, ContactPN: key,
			ContentKeyID: id, ArchiveKey: pub.Bytes()}
		switch kind {
		case seal.KindPushName:
			in.PushNameSealed = out[kind]
		case seal.KindFullName:
			in.FullNameSealed = out[kind]
		case seal.KindBusinessName:
			in.BusinessNameSealed = out[kind]
		}
		if err := contacts.Upsert(ctx, in); err != nil {
			t.Fatal(err)
		}
		if err := sealer.Rotate(ctx); err != nil {
			t.Fatal(err)
		}
		return id
	}
	push := write(seal.KindPushName, "zé")
	full := write(seal.KindFullName, "José Silva")
	business := write(seal.KindBusinessName, "Padaria do Zé")
	if push == full || full == business {
		t.Fatalf("content keys %d, %d, %d: the sealer did not take a new key", push, full, business)
	}
	// A write with no name, as EnsureIdentity makes, changes no key.
	if err := contacts.Upsert(ctx, store.ContactName{TenantID: tenant, DeviceID: device, ContactKey: key}); err != nil {
		t.Fatal(err)
	}

	open := func(t *testing.T, id uint32, kind seal.Kind, sealed []byte) string {
		t.Helper()
		blob, err := keys.SealedContentKey(ctx, tenant, device, id)
		if err != nil {
			t.Fatalf("%s names content key %d: %v", kind, id, err)
		}
		ck, err := seal.OpenContentKey(priv, tenant, device, id, blob)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ck.Open(kind, tenant, uid, sealed)
		if err != nil {
			t.Fatalf("%s does not open with content key %d: %v", kind, id, err)
		}
		return string(got)
	}
	listed, err := contacts.List(ctx, tenant, device, 10)
	if err != nil {
		t.Fatal(err)
	}
	some, err := contacts.Some(ctx, tenant, device, []string{key})
	if err != nil {
		t.Fatal(err)
	}
	paged, err := contacts.Page(ctx, tenant, device, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	for name, rows := range map[string][]store.ContactRow{"List": listed, "Some": some, "Page": paged} {
		t.Run(name, func(t *testing.T) {
			if len(rows) != 1 {
				t.Fatalf("%d rows, want 1", len(rows))
			}
			c := rows[0]
			if c.ContentKeyID != business {
				t.Errorf("content_key_id = %d, want %d, the newest write's", c.ContentKeyID, business)
			}
			for _, n := range []struct {
				kind   seal.Kind
				id     uint32
				want   uint32
				sealed []byte
				name   string
			}{
				{seal.KindPushName, c.PushNameKeyID, push, c.PushNameSealed, "zé"},
				{seal.KindFullName, c.FullNameKeyID, full, c.FullNameSealed, "José Silva"},
				{seal.KindBusinessName, c.BusinessNameKeyID, business, c.BusinessNameSealed, "Padaria do Zé"},
			} {
				if n.id != n.want {
					t.Errorf("%s names content key %d, want %d", n.kind, n.id, n.want)
				}
				if got := open(t, n.id, n.kind, n.sealed); got != n.name {
					t.Errorf("%s opened to %q, want %q", n.kind, got, n.name)
				}
			}
		})
	}
}
