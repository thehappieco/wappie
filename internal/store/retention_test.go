package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Retention and erasure are the two ways rows leave the archive on purpose.
// Both have to take the attachment objects with them — but only the objects
// nothing else still names, because a forwarded file is one object under
// several rows.

type archive struct {
	pool     *pgxpool.Pool
	tenant   uuid.UUID
	device   uuid.UUID
	messages *store.Messages
	media    *store.Media
}

type row struct {
	ts     time.Time
	chat   string
	sender string
	object string
}

func newArchive(t *testing.T) *archive {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	tenant := uuid.MustParse(newTenant(t, pool, "acme"))
	dev, err := store.NewDevices(pool).Create(context.Background(), tenant.String(), "phone", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	return &archive{
		pool: pool, tenant: tenant, device: uuid.MustParse(dev.ID),
		messages: store.NewMessages(pool), media: store.NewMedia(pool),
	}
}

func (a *archive) insert(t *testing.T, r row) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	uid := uuid.New()
	in := store.InsertMessage{
		UID: uid, TenantID: a.tenant, DeviceID: a.device,
		WAID: "wa-" + uid.String(), Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: r.ts, ChatKey: r.chat, SenderKey: r.sender,
		BodySealed: []byte{1},
	}
	if r.object != "" {
		in.Type = domain.TypeImage
		in.Media = &store.InsertMedia{MediaType: "image", FileEncSHA256: []byte(r.object)}
	}
	if _, err := a.messages.Insert(ctx, in); err != nil {
		t.Fatal(err)
	}
	if r.object != "" {
		if err := a.media.MarkDone(ctx, a.tenant, uid, r.object, 10); err != nil {
			t.Fatal(err)
		}
	}
	return uid
}

func (a *archive) count(t *testing.T, table string) int64 {
	t.Helper()
	var n int64
	err := pg.InTenantTx(context.Background(), a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		// table is one of two literals in this file, never input.
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAPurgeTakesOldRowsAndOnlyTheOrphanedObjects(t *testing.T) {
	a := newArchive(t)
	old := time.Now().Add(-40 * 24 * time.Hour)
	recent := time.Now().Add(-time.Hour)
	chat := "5511999990000@s.whatsapp.net"

	a.insert(t, row{ts: old, chat: chat, object: "t/obj-old-only"})
	a.insert(t, row{ts: old, chat: chat, object: "t/obj-shared"})
	a.insert(t, row{ts: recent, chat: chat, object: "t/obj-shared"}) // forwarded later: same bytes
	a.insert(t, row{ts: recent, chat: chat})

	counts, err := store.Purge(context.Background(), a.pool, a.tenant, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if counts.Messages != 2 {
		t.Errorf("messages purged = %d, want 2", counts.Messages)
	}
	if a.count(t, "messages") != 2 || a.count(t, "media") != 1 {
		t.Errorf("left %d messages and %d media rows, want 2 and 1", a.count(t, "messages"), a.count(t, "media"))
	}
	// The object the recent row still names must not be offered for
	// deletion; the one only the old row named must.
	if !slices.Equal(counts.ObjectKeys, []string{"t/obj-old-only"}) {
		t.Errorf("objects to remove = %v, want only the orphan", counts.ObjectKeys)
	}
}

func TestErasureRemovesOnePersonAcrossTheArchive(t *testing.T) {
	a := newArchive(t)
	now := time.Now()
	person := "5511999990000@s.whatsapp.net"
	other := "5511888880000@s.whatsapp.net"
	group := "120363000000000000@g.us"

	a.insert(t, row{ts: now, chat: person, object: "t/theirs"}) // a direct message with them
	a.insert(t, row{ts: now, chat: group, sender: person})      // what they said in a group
	a.insert(t, row{ts: now, chat: group, sender: other})       // what somebody else said there
	a.insert(t, row{ts: now, chat: other, object: "t/theirs"})  // the same file, forwarded elsewhere
	a.insert(t, row{ts: now, chat: other})

	counts, err := store.Erase(context.Background(), a.pool, a.tenant, []string{person})
	if err != nil {
		t.Fatal(err)
	}
	if counts.Messages != 2 {
		t.Errorf("messages erased = %d, want the direct chat and their group message", counts.Messages)
	}
	if a.count(t, "messages") != 3 {
		t.Errorf("%d messages left, want 3", a.count(t, "messages"))
	}
	if len(counts.ObjectKeys) != 0 {
		t.Errorf("an object another chat still holds was offered for deletion: %v", counts.ObjectKeys)
	}
	if _, err := store.Erase(context.Background(), a.pool, a.tenant, nil); err == nil {
		t.Error("an erasure with no identifier should be refused, not erase nothing")
	}
}

func TestHousekeepingForgetsDeadSessionsAfterAGrace(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant := uuid.MustParse(newTenant(t, pool, "acme"))
	users := store.NewUsers(pool)
	user, err := users.Create(ctx, store.NewUser{
		TenantID: tenant, Email: "a@example.com", AuthKey: "k", KDFSalt: make([]byte, 16),
		KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("w"),
	})
	if err != nil {
		t.Fatal(err)
	}
	live, _, err := users.StartSession(ctx, user, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	dead, _, err := users.StartSession(ctx, user, "old phone")
	if err != nil {
		t.Fatal(err)
	}
	if err := users.EndSession(ctx, dead); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() - interval '60 days' WHERE revoked_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	sessions, _, err := store.Housekeeping(ctx, pool, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("forgot %d sessions, want the one revoked two months ago", sessions)
	}
	if _, err := users.Session(ctx, live); err != nil {
		t.Fatal("the live session was swept too")
	}
}
