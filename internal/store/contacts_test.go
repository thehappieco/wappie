package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

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

	if err := contacts.SetAvatar(ctx, tenant, device, key, "pic-1", []byte("sealed face"), 7); err != nil {
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
	if err := contacts.SetAvatar(ctx, tenant, device, lid, "pic-1", []byte("face"), 1); err != nil {
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
