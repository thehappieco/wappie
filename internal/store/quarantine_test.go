package store_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/domain"
	"whatserver2/internal/ledger"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// A deleted number ("excluído", 0050) keeps its row for 30 days, hidden by a
// restrictive policy from everything outside the quarantine scope. These
// tests are about that isolation: what the policy refuses, what still runs
// over a workspace that holds an excluded number, and that the scope never
// outlives its transaction.

// linkedNumber creates a number that has paired and connected. A number
// with no identity is not excluded when deleted: it is still the hard
// delete of a pairing that never finished.
func linkedNumber(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID, label, pn, lid string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	devices := store.NewDevices(pool)
	dev, err := devices.Create(ctx, tenant.String(), label, wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err := devices.SetIdentity(ctx, tenant.String(), dev.ID, wa.Identity{
		PN:  types.JID{User: pn, Server: types.DefaultUserServer},
		LID: types.JID{User: lid, Server: types.HiddenUserServer},
	}); err != nil {
		t.Fatal(err)
	}
	if err := devices.SetStatus(ctx, tenant.String(), dev.ID, wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(dev.ID)
}

// excludeNumber marks a number deleted the way the deletion does, in SQL
// with the scope on: 30 days on the database's clock, and paused.
func excludeNumber(t *testing.T, pool *pgxpool.Pool, tenant, device uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error {
			tag, err := tx.Exec(ctx, `UPDATE devices SET deleted_at=clock_timestamp(),
				purge_after=clock_timestamp()+interval '30 days', paused=true WHERE id=$1 AND deleted_at IS NULL`, device)
			if err == nil && tag.RowsAffected() != 1 {
				err = errors.New("no live number to exclude")
			}
			return err
		})
	})
}

func inTenantTx(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID, fn func(pgx.Tx) error) {
	t.Helper()
	if err := pg.InTenantTx(ctx, pool, tenant.String(), fn); err != nil {
		t.Fatal(err)
	}
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func TestQuarantinePolicy(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant := uuid.MustParse(newTenant(t, pool, "acme"))
	device := linkedNumber(t, pool, tenant, "Vendas", "5511912345678", "42631895773279")
	devices := store.NewDevices(pool)
	uid := uuid.New()
	if _, err := store.NewMessages(pool).Insert(ctx, store.InsertMessage{UID: uid, TenantID: tenant, DeviceID: device,
		WAID: "first", ChatKey: "chat", Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive,
		TS: time.Now(), BodySealed: []byte{1}}); err != nil {
		t.Fatal(err)
	}

	// What a stale process would still write for the number. Each runs in its
	// own transaction, since a refused one aborts it.
	writes := []struct{ table, sql string }{
		{"messages", `INSERT INTO messages(tenant_id,device_id,seq,wa_id,chat_key,kind,type,source)
			VALUES($1,$2,(SELECT coalesce(max(seq),0)+1 FROM messages),$3::text,'chat','message','text','live')`},
		{"chats", `INSERT INTO chats(tenant_id,device_id,chat_key) VALUES($1,$2,$3::text)`},
		{"contacts", `INSERT INTO contacts(tenant_id,device_id,contact_key,uid) VALUES($1,$2,$3::text,uuidv7())`},
	}
	write := func(sql, key string) error {
		return pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, tenant, device, key)
			return err
		})
	}
	attach := func(waID string) error {
		return pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO media(message_uid,tenant_id,media_type)
				SELECT uid,tenant_id,'image' FROM messages WHERE device_id=$1 AND wa_id=$2`, device, waID)
			return err
		})
	}
	// The positive control: the live number takes every one of them.
	for _, w := range writes {
		if err := write(w.sql, "live"); err != nil {
			t.Fatalf("a live number refused a %s row: %v", w.table, err)
		}
	}
	if err := attach("live"); err != nil {
		t.Fatalf("a live number refused an attachment: %v", err)
	}

	// Without the scope, a row cannot become excluded: WITH CHECK refuses it.
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET deleted_at=clock_timestamp(),
			purge_after=clock_timestamp()+interval '30 days', paused=true WHERE id=$1`, device)
		return err
	})
	if sqlState(err) != "42501" {
		t.Fatalf("excluding a number without the scope: %v", err)
	}
	if got, err := devices.Get(ctx, tenant.String(), device.String()); err != nil || got.Paused {
		t.Fatalf("a refused exclusion changed the number: %+v %v", got, err)
	}

	// Every CHECK of the deletion's shape, with the scope on.
	for name, set := range map[string]string{
		"a deletion with no purge date": `deleted_at=clock_timestamp(), paused=true`,
		"a purge date with no deletion": `purge_after=clock_timestamp()`,
		"an excluded number not paused": `deleted_at=clock_timestamp(), purge_after=clock_timestamp()+interval '30 days', paused=false`,
		"a purge started on a live one": `purge_started_at=clock_timestamp()`,
		"a fingerprint with no id":      `wa_leftover='{"jid":"5511912345678@s.whatsapp.net"}'`,
		"a fingerprint that is a list":  `wa_leftover='["jid","registration_id"]'`,
	} {
		err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return store.WithQuarantineForTest(ctx, tx, func() error {
				_, err := tx.Exec(ctx, `UPDATE devices SET `+set+` WHERE id=$1`, device)
				return err
			})
		})
		if sqlState(err) != "23514" {
			t.Errorf("%s: %v", name, err)
		}
	}
	inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error {
			_, err := tx.Exec(ctx, `UPDATE devices SET wa_leftover='{"jid":"5511912345678@s.whatsapp.net","registration_id":7}' WHERE id=$1`, device)
			return err
		})
	})

	excludeNumber(t, pool, tenant, device)
	if _, err := devices.Get(ctx, tenant.String(), device.String()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an excluded number is still found: %v", err)
	}
	inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
		var hidden, seen bool
		if err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM devices WHERE id=$1)`, device).Scan(&hidden); err != nil {
			return err
		}
		if err := store.WithQuarantineForTest(ctx, tx, func() error {
			return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1 AND deleted_at IS NOT NULL AND paused)`, device).Scan(&seen)
		}); err != nil {
			return err
		}
		if !hidden || !seen {
			t.Fatalf("hidden without the scope %v, seen with it %v", hidden, seen)
		}
		return nil
	})

	// A stale process can no longer archive into it.
	for _, w := range writes {
		if err := write(w.sql, "stale"); sqlState(err) != "WS002" {
			t.Errorf("a %s row for an excluded number: %v", w.table, err)
		}
	}
	if err := attach("first"); sqlState(err) != "WS002" {
		t.Errorf("an attachment for an excluded number: %v", err)
	}

	// The identity is free for a new link while the old row waits, and still
	// unique among live rows.
	insertLive := func(label string) error {
		return pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO devices(tenant_id,label,pn,lid,status) VALUES($1,$2,'5511912345678@s.whatsapp.net','42631895773279@lid','online')`, tenant, label)
			return err
		})
	}
	if err := insertLive("linked again"); err != nil {
		t.Fatalf("the phone linked again while its old row is excluded: %v", err)
	}
	if err := insertLive("twice"); sqlState(err) != "23505" {
		t.Fatalf("two live rows with one identity: %v", err)
	}
}

// excludedArchive is a workspace with a live number and an excluded one,
// each with rows in every archive table.
type excludedArchive struct {
	pool               *pgxpool.Pool
	tenant, owner      uuid.UUID
	live, excluded     uuid.UUID
	messages           *store.Messages
	media              *store.Media
	pending, stuck     map[uuid.UUID][]uuid.UUID
	contacts, chatKeys map[uuid.UUID]string
}

// The fourteen tables archive_device_owner guards (0036's thirteen and
// ai_derived), each with how to count one number's rows.
var archiveTables = map[string]string{
	"device_archive_keys": `SELECT count(*) FROM device_archive_keys WHERE device_id=$1`,
	"device_key_grants":   `SELECT count(*) FROM device_key_grants WHERE device_id=$1`,
	"content_keys":        `SELECT count(*) FROM content_keys WHERE device_id=$1`,
	"chats":               `SELECT count(*) FROM chats WHERE device_id=$1`,
	"messages":            `SELECT count(*) FROM messages WHERE device_id=$1`,
	"media":               `SELECT count(*) FROM media d JOIN messages m ON m.uid=d.message_uid WHERE m.device_id=$1`,
	"events":              `SELECT count(*) FROM events WHERE device_id=$1`,
	"receipts":            `SELECT count(*) FROM receipts WHERE device_id=$1`,
	"contacts":            `SELECT count(*) FROM contacts WHERE device_id=$1`,
	"group_participants":  `SELECT count(*) FROM group_participants WHERE device_id=$1`,
	"group_changes":       `SELECT count(*) FROM group_changes WHERE device_id=$1`,
	"device_permissions":  `SELECT count(*) FROM device_permissions WHERE device_id=$1`,
	"reader_preferences":  `SELECT count(*) FROM reader_preferences WHERE device_id=$1`,
	"ai_derived":          `SELECT count(*) FROM ai_derived WHERE device_id=$1`,
}

func newExcludedArchive(t *testing.T) *excludedArchive {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	tenant := uuid.MustParse(newTenant(t, pool, "acme"))
	owner, err := store.NewUsers(pool).Create(ctx, store.NewUser{TenantID: tenant, Email: "owner@example.test", Role: "owner",
		AuthKey: "test", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	a := &excludedArchive{pool: pool, tenant: tenant, owner: owner.ID,
		messages: store.NewMessages(pool), media: store.NewMedia(pool),
		pending: map[uuid.UUID][]uuid.UUID{}, stuck: map[uuid.UUID][]uuid.UUID{},
		contacts: map[uuid.UUID]string{}, chatKeys: map[uuid.UUID]string{}}
	// Seeded in this order on purpose: the excluded number's pending
	// downloads are the oldest, so they would fill a claim's LIMIT first.
	a.excluded = linkedNumber(t, pool, tenant, "Suporte", "5511900000001", "100000000000001")
	a.live = linkedNumber(t, pool, tenant, "Vendas", "5511900000002", "100000000000002")
	a.seed(t, a.excluded, "100000000000011", "5511911111111", 5)
	a.seed(t, a.live, "100000000000022", "5511922222222", 1)
	for _, device := range []uuid.UUID{a.excluded, a.live} {
		inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
			for table, count := range archiveTables {
				var n int
				if err := tx.QueryRow(ctx, count, device).Scan(&n); err != nil {
					return err
				}
				if n == 0 {
					t.Fatalf("no %s row seeded for %s", table, device)
				}
			}
			return nil
		})
	}
	return a
}

// seed writes rows for one number in every archive table: a group sender
// and a chat known only by LID, and a contact known only by phone number,
// all of which the linking pass would fill in; a chat with no identity yet;
// an old message for retention; a stored attachment, pending ones and one
// stuck mid-download.
func (a *excludedArchive) seed(t *testing.T, device uuid.UUID, lid, pn string, pending int) {
	t.Helper()
	ctx := context.Background()
	old := time.Now().Add(-40 * 24 * time.Hour)
	chat := lid + "@lid"
	a.chatKeys[device] = chat
	a.contacts[device] = pn + "@s.whatsapp.net"
	insert := func(waID string, ts time.Time, media *store.InsertMedia) uuid.UUID {
		t.Helper()
		uid := uuid.New()
		in := store.InsertMessage{UID: uid, TenantID: a.tenant, DeviceID: device, WAID: waID,
			ChatKey: chat, ChatLID: chat, SenderKey: chat, SenderLID: chat,
			Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceHistory, TS: ts, BodySealed: []byte{1}}
		if media != nil {
			in.Type, in.Media = domain.TypeImage, media
		}
		if _, err := a.messages.Insert(ctx, in); err != nil {
			t.Fatal(err)
		}
		return uid
	}
	insert("old", old, nil)
	stored := insert("stored", time.Now(), &store.InsertMedia{MediaType: "image", FileEncSHA256: []byte(device.String() + "/stored")})
	if err := a.media.MarkDone(ctx, a.tenant, stored, device.String()+"/object", 10); err != nil {
		t.Fatal(err)
	}
	for i := range pending {
		a.pending[device] = append(a.pending[device], insert("pending-"+string(rune('a'+i)), time.Now(),
			&store.InsertMedia{MediaType: "image", FileEncSHA256: []byte(device.String() + "/pending-" + string(rune('a'+i)))}))
	}
	stuck := insert("stuck", time.Now(), &store.InsertMedia{MediaType: "image", FileEncSHA256: []byte(device.String() + "/stuck")})
	a.stuck[device] = []uuid.UUID{stuck}
	if _, err := store.NewReceipts(a.pool).Insert(ctx, store.InsertReceipt{TenantID: a.tenant, DeviceID: device, ChatKey: chat,
		ReaderKey: chat, ReaderLID: chat, WAIDs: []string{"stored"}, Kind: domain.ReceiptRead, TS: time.Now()}); err != nil {
		t.Fatal(err)
	}
	inTenantTx(ctx, t, a.pool, a.tenant, func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO contacts(tenant_id,device_id,contact_key,contact_pn,uid) VALUES($1,$2,$3,$3,uuidv7())`, []any{a.contacts[device]}},
			{`INSERT INTO group_participants(tenant_id,device_id,chat_key,participant_key) VALUES($1,$2,'group@g.us','member')`, nil},
			{`INSERT INTO group_changes(tenant_id,device_id,chat_key,ts,action) VALUES($1,$2,'group@g.us',now(),'snapshot')`, nil},
			{`INSERT INTO device_archive_keys(tenant_id,device_id,epoch,public_key) VALUES($1,$2,1,decode(repeat('ab',32),'hex'))`, nil},
			{`INSERT INTO content_keys(tenant_id,device_id,id,epoch,sealed_key) VALUES($1,$2,1,1,'\x01')`, nil},
			{`INSERT INTO device_key_grants(tenant_id,device_id,user_id,epoch,sealed_dsk,granted_by) VALUES($1,$2,$3,1,'\x01',$3)`, []any{a.owner}},
			{`INSERT INTO device_permissions(tenant_id,device_id,user_id,can_read) VALUES($1,$2,$3,true)
			  ON CONFLICT (tenant_id,device_id,user_id) DO UPDATE SET can_read=true`, []any{a.owner}},
			{`INSERT INTO reader_preferences(tenant_id,user_id,device_id) VALUES($1,$3,$2)`, []any{a.owner}},
			{`INSERT INTO ai_derived(message_uid,feature,tenant_id,device_id,epoch,result_sealed,dedupe_tag)
			  VALUES($3,'image',$1,$2,1,'\x01',decode(repeat('cd',32),'hex'))`, []any{stored}},
			// A chat from before chat identities, for the boot's backfill.
			{`UPDATE chats SET uid=NULL WHERE tenant_id=$1 AND device_id=$2`, nil},
			// A download whose worker died two hours ago.
			{`UPDATE media SET download_status='downloading', claimed_at=now()-interval '2 hours'
			  WHERE tenant_id=$1 AND message_uid=$3 AND message_uid IN (SELECT uid FROM messages WHERE device_id=$2)`, []any{stuck}},
		} {
			if _, err := tx.Exec(ctx, q.sql, append([]any{a.tenant, device}, q.args...)...); err != nil {
				return err
			}
		}
		return nil
	})
}

// storedBy is what a live number stores, as its owner's breakdown shows it.
func (a *excludedArchive) storedBy(t *testing.T, device uuid.UUID) store.StorageBytes {
	t.Helper()
	usage, err := store.NewStorage(a.pool).UsageDetailed(context.Background(), a.tenant, a.owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range usage.Breakdown.Devices {
		if d.DeviceID == device.String() {
			if d.ArchiveBytes == 0 || d.ObjectBytes != 10 {
				t.Fatalf("%s stores %+v", device, d.StorageBytes)
			}
			return d.StorageBytes
		}
	}
	t.Fatalf("%s is not in the breakdown", device)
	return store.StorageBytes{}
}

// addsUp checks that a breakdown never names the excluded number and that
// its buckets add up to the workspace's total.
func addsUp(t *testing.T, usage store.StorageUsage, excluded uuid.UUID) {
	t.Helper()
	b := usage.Breakdown
	sum := b.Shared.UsedBytes + b.Unassigned.UsedBytes + b.Excluded.UsedBytes + b.Other.UsedBytes
	for _, d := range b.Devices {
		if d.DeviceID == excluded.String() {
			t.Fatal("the breakdown names the excluded number")
		}
		sum += d.UsedBytes
	}
	if sum != usage.UsedBytes {
		t.Fatalf("the breakdown does not add up: %d of %d", sum, usage.UsedBytes)
	}
}

func (a *excludedArchive) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	ctx := context.Background()
	var n int
	inTenantTx(ctx, t, a.pool, a.tenant, func(tx pgx.Tx) error { return tx.QueryRow(ctx, sql, args...).Scan(&n) })
	return n
}

// Every boot step and every janitor step that works across a workspace runs
// with an excluded number in it, and none of them fails, writes into it, or
// stops working for the workspace's other number.
func TestBootAndJanitorWithExcludedNumber(t *testing.T) {
	a := newExcludedArchive(t)
	ctx := context.Background()
	devices := store.NewDevices(a.pool)
	storage := store.NewStorage(a.pool)
	excludedBytes := a.storedBy(t, a.excluded)
	// A uid lookup finds each number's message while both are live, and then
	// only the live one's: the messages table has no device policy, so the
	// join to devices is all that hides it.
	uids := map[uuid.UUID]uuid.UUID{a.excluded: a.pending[a.excluded][0], a.live: a.pending[a.live][0]}
	for device, uid := range uids {
		if got, err := a.messages.Get(ctx, a.tenant, uid); err != nil || got.DeviceID != device {
			t.Fatalf("a live number's message: %+v %v", got, err)
		}
	}
	excludeNumber(t, a.pool, a.tenant, a.excluded)
	if _, err := a.messages.Get(ctx, a.tenant, uids[a.excluded]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("an excluded number's message by uid: %v", err)
	}
	if _, err := a.messages.Get(ctx, a.tenant, uids[a.live]); err != nil {
		t.Fatalf("the live number's message by uid: %v", err)
	}

	// Boot: the resume list, the LID linking pass and the chat identities.
	listed, err := devices.List(ctx, a.tenant.String())
	if err != nil || len(listed) != 1 || listed[0].ID != a.live.String() {
		t.Fatalf("resume would list %+v %v", listed, err)
	}
	if _, err := a.pool.Exec(ctx, `CREATE TABLE whatsmeow_lid_map (lid text PRIMARY KEY, pn text NOT NULL UNIQUE)`); err != nil {
		t.Fatal(err)
	}
	lidMap(t, a.pool, map[string]string{
		"100000000000011": "5511911111111", "100000000000022": "5511922222222",
	})
	linked, err := store.LinkPhoneNumbers(ctx, a.pool, a.tenant)
	if err != nil {
		t.Fatalf("linking with an excluded number: %v", err)
	}
	if linked.Messages == 0 || linked.Chats != 1 || linked.Contacts != 1 {
		t.Fatalf("the live number was not linked: %+v", linked)
	}
	if n := a.count(t, `SELECT count(*) FROM messages WHERE device_id=$1 AND sender_pn IS NOT NULL`, a.excluded); n != 0 {
		t.Fatalf("%d excluded messages were linked", n)
	}
	backfilled, err := a.messages.BackfillChatUIDs(ctx, a.tenant)
	if err != nil || backfilled != 1 {
		t.Fatalf("chat identities with an excluded number: %d %v", backfilled, err)
	}
	if n := a.count(t, `SELECT count(*) FROM chats WHERE device_id=$1 AND uid IS NULL`, a.excluded); n != 1 {
		t.Fatalf("the excluded number's chat was written: %d left without an identity", n)
	}

	// Downloads: the excluded number's five pending attachments are older
	// and more than the LIMIT, and still never crowd out the live one's.
	claimed, err := a.media.Claim(ctx, a.tenant, 2)
	if err != nil {
		t.Fatalf("claim with an excluded number: %v", err)
	}
	if len(claimed) != 1 || claimed[0].MessageUID != a.pending[a.live][0] {
		t.Fatalf("claimed %+v, want the live number's one pending attachment", claimed)
	}
	swept, err := a.media.Sweep(ctx, a.tenant, time.Hour)
	if err != nil || swept != 1 {
		t.Fatalf("sweep with an excluded number: %d %v", swept, err)
	}
	if n := a.count(t, `SELECT count(*) FROM media WHERE message_uid=$1 AND download_status='downloading'`, a.stuck[a.excluded][0]); n != 1 {
		t.Fatal("the sweep wrote the excluded number's attachment")
	}

	// Reconcile rebuilds the excluded number's records too: its bytes stay
	// stored and charged until the purge, in their own bucket.
	before, err := storage.Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	after, err := storage.Reconcile(ctx, a.tenant)
	if err != nil {
		t.Fatalf("reconcile with an excluded number: %v", err)
	}
	if after.ArchiveBytes != before.ArchiveBytes || after.ObjectBytes != before.ObjectBytes {
		t.Fatalf("reconcile changed the totals: %+v, was %+v", after, before)
	}
	detailed, err := storage.UsageDetailed(ctx, a.tenant, a.owner)
	if err != nil {
		t.Fatal(err)
	}
	if detailed.Breakdown.Excluded != excludedBytes {
		t.Fatalf("the excluded bucket holds %+v, the number stored %+v", detailed.Breakdown.Excluded, excludedBytes)
	}
	addsUp(t, detailed, a.excluded)
	stats, err := devices.Stats(ctx, a.tenant.String())
	if err != nil || len(stats) != 1 || stats[0].DeviceID != a.live.String() {
		t.Fatalf("stats with an excluded number: %+v %v", stats, err)
	}

	// A reset would skip the hidden row and leave it with no archive, so it
	// refuses, and changes nothing.
	messagesBefore := a.count(t, `SELECT count(*) FROM messages`)
	for _, keep := range []bool{false, true} {
		if _, err := store.ResetArchive(ctx, a.pool, a.tenant, keep); !errors.Is(err, store.ErrExcludedNumbers) {
			t.Fatalf("reset (keep devices %v) with an excluded number: %v", keep, err)
		}
	}
	if n := a.count(t, `SELECT count(*) FROM messages`); n != messagesBefore {
		t.Fatalf("a refused reset removed %d messages", messagesBefore-n)
	}

	// Retention and erasure only delete, so they keep running on the
	// excluded number (its window is a promise too).
	purged, err := store.Purge(ctx, a.pool, a.tenant, time.Now().Add(-30*24*time.Hour))
	if err != nil || purged.Messages != 2 {
		t.Fatalf("retention with an excluded number: %+v %v", purged, err)
	}
	erased, err := store.Erase(ctx, a.pool, a.tenant, []string{a.contacts[a.excluded]})
	if err != nil || erased.Contacts != 1 {
		t.Fatalf("erasure with an excluded number: %+v %v", erased, err)
	}

	// The orphan pass deletes what nothing names, and only that; the
	// deleted numbers' housekeeping and the ledger's export run too.
	if err := storage.ReserveObject(ctx, a.tenant, "orphan", 5); err != nil {
		t.Fatal(err)
	}
	orphans, err := storage.UnreferencedObjects(ctx, a.tenant, 1000)
	if err != nil || !slices.Contains(orphans, "orphan") {
		t.Fatalf("orphans with an excluded number: %q %v", orphans, err)
	}
	var removed []string
	for _, key := range orphans {
		if err := storage.DeleteObject(ctx, a.tenant, key, func(_ context.Context, key string) error {
			removed = append(removed, key)
			return nil
		}); err != nil {
			t.Fatalf("the orphan pass with an excluded number: %v", err)
		}
	}
	if !slices.Contains(removed, "orphan") || slices.Contains(removed, a.excluded.String()+"/object") || slices.Contains(removed, a.live.String()+"/object") {
		t.Fatalf("the orphan pass deleted a referenced object: %q", removed)
	}
	if _, err := store.DeletionHousekeeping(ctx, a.pool, a.tenant); err != nil {
		t.Fatalf("housekeeping with an excluded number: %v", err)
	}
	if _, err := store.ExportLedger(ctx, a.pool, a.tenant, &ledger.File{Path: filepath.Join(t.TempDir(), "ledger.jsonl")}); err != nil {
		t.Fatalf("the ledger's export with an excluded number: %v", err)
	}

	// The live number keeps archiving.
	if _, err := a.messages.Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: a.tenant, DeviceID: a.live, WAID: "after",
		ChatKey: a.chatKeys[a.live], Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive,
		TS: time.Now(), BodySealed: []byte{1}}); err != nil {
		t.Fatalf("the live number after all of it: %v", err)
	}
}

// Only an owner sees what the deleted numbers still store: an admin, an
// owner disabled since, and anyone else get the same totals with those bytes
// folded into Unassigned. The live role decides, read in the breakdown's own
// transaction, so every route that shows it, core's and the cloud's, folds
// alike.
func TestStorageBreakdownFoldsExcludedForNonOwners(t *testing.T) {
	a := newExcludedArchive(t)
	ctx := context.Background()
	users := store.NewUsers(a.pool)
	member := func(email, role string) uuid.UUID {
		t.Helper()
		u, err := users.Create(ctx, store.NewUser{TenantID: a.tenant, Email: email, Role: role,
			AuthKey: "test", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	admin := member("admin@example.test", "admin")
	disabled := member("disabled@example.test", "owner")
	inTenantTx(ctx, t, a.pool, a.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET status='disabled' WHERE tenant_id=$1 AND user_id=$2`, a.tenant, disabled)
		return err
	})
	excludedBytes := a.storedBy(t, a.excluded)
	excludeNumber(t, a.pool, a.tenant, a.excluded)

	storage := store.NewStorage(a.pool)
	owner, err := storage.UsageDetailed(ctx, a.tenant, a.owner)
	if err != nil {
		t.Fatal(err)
	}
	if owner.Breakdown.Excluded != excludedBytes || owner.Breakdown.Other != (store.StorageBytes{}) {
		t.Fatalf("the owner's excluded bucket holds %+v (other %+v), the number stored %+v", owner.Breakdown.Excluded, owner.Breakdown.Other, excludedBytes)
	}
	addsUp(t, owner, a.excluded)
	for name, viewer := range map[string]uuid.UUID{"an admin": admin, "a disabled owner": disabled, "nobody": uuid.Nil} {
		got, err := storage.UsageDetailed(ctx, a.tenant, viewer)
		if err != nil {
			t.Fatal(err)
		}
		// The bytes move to the unlabelled other line, never into the
		// uploads in progress.
		b := got.Breakdown
		if b.Excluded != (store.StorageBytes{}) || b.Other != excludedBytes || b.Unassigned != owner.Breakdown.Unassigned ||
			b.Shared != owner.Breakdown.Shared || got.UsedBytes != owner.UsedBytes {
			t.Fatalf("%s's breakdown %+v, the owner's %+v", name, b, owner.Breakdown)
		}
		addsUp(t, got, a.excluded)
	}
}

// The enclave reads an AI authorization's numbers and its stored results
// through no devices policy of their own. An excluded number is none of the
// row's numbers and has no results, even while a connection whose key names
// it is still active.
func TestEnclaveSeesNoExcludedNumber(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	dev, err := store.NewDevices(f.pool).Create(ctx, f.tenant.String(), "second", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	excluded := uuid.MustParse(dev.ID)
	f.archiveKey(ctx, t, excluded, 1)
	f.ownerReads(ctx, t, f.owner, excluded)
	conn, _ := f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil, withDevices(f.device, excluded))
	results := map[uuid.UUID]store.AIDerived{}
	for _, device := range []uuid.UUID{f.device, excluded} {
		results[device] = f.derived(t, f.message(ctx, t, device, domain.TypePTT, false), device, "audio")
		if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, results[device], false); err != nil {
			t.Fatal(err)
		}
	}
	tags := []store.AIDedupeTag{{DeviceID: f.device, Tag: results[f.device].DedupeTag}, {DeviceID: excluded, Tag: results[excluded].DedupeTag}}
	seen := func(when string, want ...uuid.UUID) {
		t.Helper()
		row, err := f.conns.ReaderRow(ctx, "enclave", conn.ID)
		if err != nil {
			t.Fatal(err)
		}
		byTag, err := f.ai.AIDerivedByTags(ctx, f.tenant, "audio", tags)
		if err != nil {
			t.Fatal(err)
		}
		if len(row.Devices) != len(want) || len(byTag) != len(want) {
			t.Fatalf("%s: the row's numbers %v and the results by tag %+v, want %v", when, row.Devices, byTag, want)
		}
		for _, device := range []uuid.UUID{f.device, excluded} {
			items, err := f.ai.AIDerivedFor(ctx, f.tenant, device, []uuid.UUID{results[device].MessageUID})
			if err != nil {
				t.Fatal(err)
			}
			if live := slices.Contains(want, device); row.Devices[device] != live || (len(items) == 1) != live {
				t.Fatalf("%s: %s is the row's %v, with %d results", when, device, row.Devices[device], len(items))
			}
		}
	}
	// The positive control: both numbers while both are live.
	seen("before the deletion", f.device, excluded)
	excludeNumber(t, f.pool, f.tenant, excluded)
	seen("after it", f.device)
}

// The scope is transaction-local: whatever a scope function does, success
// or failure, the next transaction on the same connection sees no excluded
// row. Each pool has one connection, so every call reuses it.
func TestScopeNeverOutlivesTx(t *testing.T) {
	for _, name := range []string{"api", "history"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			// One connection, with the statement timeout each pool has.
			timeout := map[string]string{"api": "15000", "history": "300000"}[name]
			pool := pgtest.FreshWith(t, migrate.Run, func(c *pgxpool.Config) {
				c.MaxConns = 1
				c.ConnConfig.RuntimeParams["statement_timeout"] = timeout
			})
			tenant := uuid.MustParse(newTenant(t, pool, "acme"))
			device := linkedNumber(t, pool, tenant, "Suporte", "5511900000001", "100000000000001")
			if _, err := store.NewMessages(pool).Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: tenant, DeviceID: device,
				WAID: "one", ChatKey: "chat", Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive,
				TS: time.Now(), BodySealed: []byte{1}}); err != nil {
				t.Fatal(err)
			}
			excludeNumber(t, pool, tenant, device)
			storage := store.NewStorage(pool)
			forced := errors.New("forced")
			var backend int
			if err := pool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backend); err != nil {
				t.Fatal(err)
			}
			closed := func(when string) {
				t.Helper()
				var setting string
				var pid int
				if err := pool.QueryRow(ctx, `SELECT coalesce(current_setting('app.device_quarantine', true), ''), pg_backend_pid()`).Scan(&setting, &pid); err != nil {
					t.Fatal(err)
				}
				if pid != backend {
					t.Fatalf("%s: another connection (%d, was %d) proves nothing", when, pid, backend)
				}
				if setting != "" {
					t.Fatalf("%s: the scope outlived its transaction: %q", when, setting)
				}
				if _, err := store.NewDevices(pool).Get(ctx, tenant.String(), device.String()); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("%s: the excluded number is visible: %v", when, err)
				}
			}

			// The helper itself: closed again inside the transaction, after
			// fn returns and after fn fails, and gone with a rollback after an
			// error from the database.
			inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
				if err := store.WithQuarantineForTest(ctx, tx, func() error { return nil }); err != nil {
					return err
				}
				if err := store.WithQuarantineForTest(ctx, tx, func() error { return forced }); !errors.Is(err, forced) {
					t.Fatalf("fn's error: %v", err)
				}
				var setting string
				var n int
				if err := tx.QueryRow(ctx, `SELECT current_setting('app.device_quarantine', true), (SELECT count(*) FROM devices WHERE id=$1)`, device).Scan(&setting, &n); err != nil {
					return err
				}
				if setting != "" || n != 0 {
					t.Fatalf("the scope stayed open in its transaction: %q, %d rows", setting, n)
				}
				return nil
			})
			closed("after the helper")
			err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
				return store.WithQuarantineForTest(ctx, tx, func() error {
					_, err := tx.Exec(ctx, `SELECT 1/0`)
					return err
				})
			})
			if sqlState(err) != "22012" {
				t.Fatalf("a failed statement inside the scope: %v", err)
			}
			closed("after a failed statement")

			// Every caller of the scope, on success and on failure.
			if _, err := storage.Reconcile(ctx, tenant); err != nil {
				t.Fatal(err)
			}
			closed("after reconcile")
			if _, err := pool.Exec(ctx, `CREATE FUNCTION refuse_reconcile() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
				RAISE EXCEPTION 'forced' USING ERRCODE='P0001'; END $$;
				CREATE TRIGGER refuse_reconcile BEFORE UPDATE ON group_changes FOR EACH STATEMENT EXECUTE FUNCTION refuse_reconcile()`); err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Reconcile(ctx, tenant); sqlState(err) != "P0001" {
				t.Fatalf("a reconcile that fails inside the scope: %v", err)
			}
			closed("after a failed reconcile")
			if _, err := pool.Exec(ctx, `DROP TRIGGER refuse_reconcile ON group_changes; DROP FUNCTION refuse_reconcile()`); err != nil {
				t.Fatal(err)
			}
			if _, err := storage.UsageDetailed(ctx, tenant, uuid.Nil); err != nil {
				t.Fatal(err)
			}
			closed("after the storage breakdown")
			if _, err := store.ResetArchive(ctx, pool, tenant, false); !errors.Is(err, store.ErrExcludedNumbers) {
				t.Fatalf("reset: %v", err)
			}
			closed("after a refused reset")
		})
	}
}

// The quarantine has one door in Go. The setting's name appears in
// store/quarantine.go and in 0050 only, and only the functions decision
// 0038's plan names (section 4.1) open the scope; tests reach it through
// WithQuarantineForTest. Test files are not scanned.
func TestQuarantineScopeHasOneDoor(t *testing.T) {
	// The callers of withQuarantine, by function name (with its receiver's
	// type for a method).
	allowed := map[string]bool{
		"Devices.Quarantine": true, "Devices.Recover": true, "Devices.RecoverCheck": true,
		"Devices.GetExcluded": true, "Devices.ListDeleted": true, "Devices.RecordUnlink": true,
		"Devices.StillExcluded": true, "Devices.LeftoverSessions": true, "Devices.DueDeletions": true,
		"PurgeDevice": true, "strandCheckTx": true, "anyExcludedTx": true, "excludedDevicesTx": true,
		"Storage.Reconcile": true, "ReplayLedger": true,
		// The operator's list of deleted numbers (whatserverd devices
		// list-deleted), which has no owner to check.
		"Devices.ListAllDeleted": true,
		// The contract's access snapshot, which lists a deleted number
		// until its purge (README 8).
		"Contract.Snapshot": true,
		// The contract's events: a replayed row, which keeps no label,
		// takes its deleted number's until the purge (the plan's 4.11).
		"replayedLabelsTx": true,
	}
	const guc = "app.device_quarantine"
	var found []string
	for _, root := range []string{"../../cmd", "../../internal"} {
		files, err := goFiles(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			src, callers, err := scopeCallers(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(src, guc) && path != "../../internal/store/quarantine.go" {
				t.Errorf("%s names %s: only store/quarantine.go may", path, guc)
			}
			for _, caller := range callers {
				if !strings.HasPrefix(path, "../../internal/store/") || !allowed[caller] {
					t.Errorf("%s: %s opens the quarantine scope", path, caller)
				}
				found = append(found, caller)
			}
		}
	}
	slices.Sort(found)
	if !slices.Contains(found, "Storage.Reconcile") || !slices.Contains(found, "anyExcludedTx") || !slices.Contains(found, "excludedDevicesTx") {
		t.Fatalf("the scan found no caller it knows: %v", found)
	}
	migrations, err := migrate.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if strings.Contains(m.SQL, guc) && m.Version != 50 {
			t.Errorf("%04d_%s names %s", m.Version, m.Name, guc)
		}
	}
}

func goFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// scopeCallers reads a Go file and names each function in it that opens the
// quarantine scope. Any other use of withQuarantine, a function value or a
// second declaration, is named too, so the scope cannot be reached around
// the list.
func scopeCallers(path string) (string, []string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		return "", nil, err
	}
	var callers []string
	called := map[*ast.Ident]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			typ := fn.Recv.List[0].Type
			if star, ok := typ.(*ast.StarExpr); ok {
				typ = star.X
			}
			if id, ok := typ.(*ast.Ident); ok {
				name = id.Name + "." + name
			}
		}
		if fn.Name.Name == "withQuarantine" && fn.Recv == nil && path == "../../internal/store/quarantine.go" {
			called[fn.Name] = true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "withQuarantine" {
					called[id] = true
					callers = append(callers, name)
				}
			}
			return true
		})
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "withQuarantine" && !called[id] {
			callers = append(callers, "a use of withQuarantine that is not a call")
		}
		return true
	})
	return string(src), callers, nil
}
