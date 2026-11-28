package datacheck_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/blob"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/datacheck"
	"whatserver2/internal/domain"
	"whatserver2/internal/media"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Recognisable seeds: none of them may appear in anything the check writes.
const (
	workspaceName = "Workspace Label Omega"
	otherName     = "Other Workspace Sigma"
	deviceLabel   = "Recognisable Label Zeta"
	keylessLabel  = "Keyless Label Kappa"
	orphanLabel   = "Orphan Label Theta"
	devicePN      = "5511987654321"
	deviceLID     = "246813579024680"
	pushName      = "Recognisable Push Name"
	contactPN     = "5521912345678"
	senderPN      = "5531998877665"
	ownerEmail    = "seed-owner@label.test"
	personEmail   = "seed-person@label.test"
	bodyText      = "segredo texto reconhecivel"
	contactName   = "Nome Reconhecivel Contato"
	fileName      = "arquivo-reconhecivel.pdf"
	otherEmail    = "seed-other@label.test"
)

var secrets = []string{workspaceName, otherName, deviceLabel, keylessLabel, orphanLabel, devicePN, deviceLID,
	pushName, contactPN, senderPN, ownerEmail, personEmail, otherEmail, bodyText, contactName, fileName, "s.whatsapp.net", "g.us"}

// world is a seeded installation: two workspaces, three numbers, keys,
// grants, messages, media and objects.
type world struct {
	pool                     *pgxpool.Pool
	tenant, other            uuid.UUID
	owner, person            uuid.UUID
	device, keyless, orphan  uuid.UUID
	bucket                   *memBucket
	keys                     *store.Keys
	directChat, groupChat    string
	firstDirect              uuid.UUID
	mediaKey, missingKey     string
	messages                 *store.Messages
	pub1                     seal.PublicKey
	directMessages, allTexts int
}

func seed(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	w := &world{pool: pool, bucket: newMemBucket(), keys: store.NewKeys(pool), messages: store.NewMessages(pool)}
	w.directChat, w.groupChat = devicePN+"@s.whatsapp.net", "120363000000000001@g.us"
	for _, s := range []struct {
		id   *uuid.UUID
		name string
	}{{&w.tenant, workspaceName}, {&w.other, otherName}} {
		if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id`, s.name).Scan(s.id); err != nil {
			t.Fatal(err)
		}
	}
	users, devices := store.NewUsers(pool), store.NewDevices(pool)
	account := func(tenant uuid.UUID, email, role string) uuid.UUID {
		t.Helper()
		pub, _, err := seal.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		u, err := users.Create(ctx, store.NewUser{TenantID: tenant, Email: email, Role: role, AuthKey: "test",
			KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: pub.Bytes(), WrappedUSK: []byte("wrapped")})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	w.owner, w.person = account(w.tenant, ownerEmail, "owner"), account(w.tenant, personEmail, "admin")
	account(w.other, otherEmail, "owner")
	if _, err := pool.Exec(ctx, `INSERT INTO platform_wraps (user_id, product_key_id, wrap) VALUES ($1, 'recognisable:7', decode('03' || repeat('ab', 60), 'hex'))`, w.owner); err != nil {
		t.Fatal(err)
	}
	number := func(tenant uuid.UUID, label string) uuid.UUID {
		t.Helper()
		d, err := devices.Create(ctx, tenant.String(), label, wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		return uuid.MustParse(d.ID)
	}
	w.device, w.keyless = number(w.tenant, deviceLabel), number(w.tenant, keylessLabel)
	w.orphan = number(w.other, orphanLabel)
	w.exec(t, w.tenant, `UPDATE devices SET pn = $2, lid = $3, push_name = $4 WHERE id = $1`, w.device, devicePN, deviceLID, pushName)

	var err error
	if w.pub1, _, err = seal.GenerateKeyPair(); err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, w.device, 1, w.pub1); err != nil {
		t.Fatal(err)
	}
	for _, u := range []uuid.UUID{w.owner, w.person} {
		w.grant(t, u, 1)
		if err := users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: w.device, UserID: u, Read: true}); err != nil {
			t.Fatal(err)
		}
	}
	// The other workspace's number has a key nobody holds.
	orphanPub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.other, w.orphan, 1, orphanPub); err != nil {
		t.Fatal(err)
	}
	ck, err := w.keys.CreateContentKey(ctx, w.tenant, w.device, 1, func(uint32) ([]byte, error) { return []byte("sealed content key"), nil })
	if err != nil {
		t.Fatal(err)
	}

	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	insert := func(chat string, group bool, kind domain.Kind, i int, m *store.InsertMedia) uuid.UUID {
		t.Helper()
		in := store.InsertMessage{UID: uuid.New(), TenantID: w.tenant, DeviceID: w.device,
			WAID: fmt.Sprintf("WA%03d", i), ChatKey: chat, IsGroup: group,
			SenderKey: senderPN + "@s.whatsapp.net", SenderPN: senderPN,
			TS: at.Add(time.Duration(i) * time.Minute), Kind: kind, Type: domain.TypeText,
			Source: domain.SourceLive, ContentKeyID: ck, BodySealed: []byte(bodyText), Media: m}
		if !group {
			in.ChatPN = devicePN
		}
		res, err := w.messages.Insert(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return res.UID
	}
	for i := range 3 {
		uid := insert(w.directChat, false, domain.KindMessage, i, nil)
		if i == 0 {
			w.firstDirect = uid
		}
	}
	insert(w.directChat, false, domain.KindEdit, 3, nil)
	w.directMessages = 4
	insert(w.groupChat, true, domain.KindMessage, 4, nil)

	// Two attachments: one stored (its object is content-addressed), one
	// whose row names an object the bucket lacks.
	cipher := []byte("ciphertext of an attachment")
	sum := sha256.Sum256(cipher)
	withMedia := func(i int, enc []byte) uuid.UUID {
		return insert(w.directChat, false, domain.KindMessage, i, &store.InsertMedia{MediaType: "document",
			MimeType: "application/pdf", FileLength: int64(len(cipher)), FileEncSHA256: enc,
			MediaKeySealed: []byte("media key"), FileNameSealed: []byte(fileName)})
	}
	stored := withMedia(5, sum[:])
	w.mediaKey = media.ObjectKey(w.tenant, sum[:])
	w.storeObject(t, stored, w.mediaKey, cipher)
	gone := sha256.Sum256([]byte("never uploaded"))
	lost := withMedia(6, gone[:])
	w.missingKey = media.ObjectKey(w.tenant, gone[:])
	w.storeObject(t, lost, w.missingKey, nil)
	w.directMessages += 2
	w.allTexts = 7

	if err := store.NewContacts(pool).Upsert(ctx, store.ContactName{TenantID: w.tenant, DeviceID: w.device,
		ContactKey: contactPN + "@s.whatsapp.net", ContactPN: contactPN, ContentKeyID: ck,
		PushNameSealed: []byte(contactName)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewReceipts(pool).Insert(ctx, store.InsertReceipt{TenantID: w.tenant, DeviceID: w.device,
		ChatKey: w.directChat, ReaderKey: devicePN + "@s.whatsapp.net", ReaderPN: devicePN, WAIDs: []string{"WA000"},
		Kind: domain.ReceiptRead, TS: at.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := store.NewGroups(pool).Record(ctx, w.tenant, w.device, w.groupChat, store.GroupChange{TS: at,
		ActorKey: senderPN + "@s.whatsapp.net", ActorPN: senderPN, Action: store.ChangeAdd,
		SubjectKey: contactPN + "@s.whatsapp.net", SubjectPN: contactPN}); err != nil {
		t.Fatal(err)
	}
	// An object under the workspace that no row names, and one under no
	// workspace.
	w.bucket.put(w.tenant.String()+"/ab/"+strings.Repeat("ab", 32), []byte("orphan bytes"))
	w.bucket.put("stray/object", []byte("stray"))
	return w
}

func (w *world) exec(t *testing.T, tenant uuid.UUID, q string, args ...any) {
	t.Helper()
	if err := pg.InTenantTx(context.Background(), w.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), q, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func (w *world) grant(t *testing.T, user uuid.UUID, epoch uint16) {
	t.Helper()
	fp, err := w.keys.ArchiveKeyFingerprintAt(context.Background(), w.tenant, w.device, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.PutGrant(context.Background(), store.Grant{TenantID: w.tenant, DeviceID: w.device, UserID: user,
		Epoch: epoch, SealedDSK: []byte("grant for " + user.String()), Fingerprint: fp}, &w.owner); err != nil {
		t.Fatal(err)
	}
}

// storeObject records an attachment's object as the media worker does, and
// puts its bytes in the bucket unless they are nil.
func (w *world) storeObject(t *testing.T, uid uuid.UUID, key string, data []byte) {
	t.Helper()
	ctx := context.Background()
	m := store.NewMedia(w.pool)
	size := int64(len("ciphertext of an attachment"))
	if err := m.ReserveObject(ctx, w.tenant, key, size); err != nil {
		t.Fatal(err)
	}
	if err := m.StoreReservedObject(ctx, w.tenant, uid, key, size, func() error {
		if data != nil {
			w.bucket.put(key, data)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// run takes a manifest as the command does: one read-only transaction,
// rolled back.
func (w *world) run(t *testing.T, workspace string, objects bool) (*datacheck.Manifest, []byte, string) {
	t.Helper()
	ctx := context.Background()
	tx, err := datacheck.Begin(ctx, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read only
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	if err := os.WriteFile(ledger, []byte("{\"a\":1}\n{\"b\":2}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := datacheck.Collect(ctx, tx, datacheck.Options{Workspace: workspace,
		Files: map[string]string{"deletion_ledger": ledger, "token_stops": filepath.Join(dir, "absent")}})
	if err != nil {
		t.Fatal(err)
	}
	var sums bytes.Buffer
	if objects {
		if err := datacheck.CheckObjects(ctx, tx, w.bucket, m, datacheck.ObjectOutput{Sums: &sums}); err != nil {
			t.Fatal(err)
		}
	}
	j, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return m, j, sums.String()
}

func compare(t *testing.T, before, after []byte, exp datacheck.Expectations) ([]datacheck.Difference, string) {
	t.Helper()
	diffs, err := datacheck.Compare(before, after, exp)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := datacheck.WriteReport(&b, diffs); err != nil {
		t.Fatal(err)
	}
	return diffs, b.String()
}

// TestManifestCountsTheSeededData: the manifest counts exactly what was
// seeded, per workspace and per number, with the keys, grants and the read
// check's numbers by id.
func TestManifestCountsTheSeededData(t *testing.T) {
	w := seed(t)
	m, _, _ := w.run(t, "", false)
	ws := m.Workspaces[w.tenant.String()]
	// Each account also has its personal workspace.
	if ws == nil || m.Workspaces[w.other.String()] == nil || len(m.Workspaces) != 5 {
		t.Fatalf("workspaces: %v", m.Workspaces)
	}
	d := ws.Devices[w.device.String()]
	if d == nil || !d.Present {
		t.Fatal("the seeded number is missing")
	}
	if got := d.Messages.ByKind; got["message"] != int64(w.allTexts-1) || got["edit"] != 1 {
		t.Fatalf("messages by kind: %v", got)
	}
	if *d.Messages.MinTS != "2026-11-20 10:00:00+00" || *d.Messages.MaxTS != "2026-11-20 10:06:00+00" || d.Messages.NullTS != 0 {
		t.Fatalf("message times: %s %s %d", *d.Messages.MinTS, *d.Messages.MaxTS, d.Messages.NullTS)
	}
	want := map[string]int64{"messages": 7, "chats": 2, "contacts": 1, "group_participants": 1, "receipts": 1,
		"group_changes": 1, "events": 0, "media": 2, "ai_derived": 0, "device_permissions": 2, "reader_preferences": 0}
	for name, n := range want {
		tb := d.Tables[name]
		if tb == nil {
			t.Fatalf("no %s table", name)
		}
		if name == "events" {
			continue // the store's own events; counted, not seeded here
		}
		if tb.Count != n {
			t.Errorf("%s: %d rows, want %d", name, tb.Count, n)
		}
	}
	if d.Tables["messages"].MaxSeq == nil || d.Tables["messages"].Nulls["sender_pn"] != 0 {
		t.Fatalf("messages: %+v", d.Tables["messages"])
	}
	if d.Tables["chats"].Nulls["chat_pn"] != 1 { // the group chat
		t.Fatalf("chats nulls: %v", d.Tables["chats"].Nulls)
	}
	// Each chat is named by its first message's uid, never by its derived
	// (and predictable) chat uid.
	if len(d.ChatOrder) != 2 || d.ChatOrder[w.firstDirect.String()] == "" {
		t.Fatalf("chat order: %v", d.ChatOrder)
	}
	if d.Tables["chats"].Columns["uid"] == "" || d.Tables["messages"].Columns["sender_pn"] == "" || d.Tables["contacts"].Columns["contact_lid"] == "" {
		t.Fatalf("the backfilled columns' digests: %+v %+v", d.Tables["chats"], d.Tables["contacts"])
	}
	if got := d.Media["pending"].Count + d.Media["done"].Count; got != 2 {
		t.Fatalf("media: %v", d.Media)
	}
	if ck := d.ContentKeys["1"]; ck.Count != 1 {
		t.Fatalf("content keys: %v", d.ContentKeys)
	}
	fp := store.ArchiveKeyFingerprint(w.pub1.Bytes())
	if k := d.ArchiveKeys["1"]; k.Fingerprint != fp || k.RetiredAt != nil {
		t.Fatalf("archive key: %+v", k)
	}
	if len(d.Grants) != 2 {
		t.Fatalf("grants: %v", d.Grants)
	}
	for _, u := range []uuid.UUID{w.owner, w.person} {
		g, ok := d.Grants[u.String()+":1"]
		if !ok || g.Fingerprint == nil || *g.Fingerprint != fp {
			t.Fatalf("grant of %s: %+v", u, g)
		}
		sum := sha256.Sum256([]byte("grant for " + u.String()))
		if g.SealedDSKSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("the grant's hash is not its sealed key's")
		}
	}
	if !slices.Equal(ws.ReadCheck.Keyless, []string{w.keyless.String()}) || len(ws.ReadCheck.Orphan) != 0 {
		t.Fatalf("read check: %+v", ws.ReadCheck)
	}
	if o := m.Workspaces[w.other.String()].ReadCheck; !slices.Equal(o.Orphan, []string{w.orphan.String()}) {
		t.Fatalf("the other workspace's read check: %+v", o)
	}
	if u := ws.Users[w.owner.String()]; u.PublicKeySHA256 == "" || len(u.PlatformWraps) != 1 {
		t.Fatalf("the owner's keys: %+v", u)
	}
	if ws.StorageObjects.Count != 2 || ws.Inventory["messages"].Count != 7 {
		t.Fatalf("storage: %+v %+v", ws.StorageObjects, ws.Inventory)
	}
	if f := m.Files["deletion_ledger"]; !f.Present || f.Lines != 2 {
		t.Fatalf("ledger: %+v", f)
	}
	if f := m.Files["token_stops"]; f.Present {
		t.Fatalf("an absent stop record: %+v", f)
	}
	if len(m.Schema) == 0 || m.Excluded["mcp_outbound"] == "" {
		t.Fatal("schema or exclusions missing")
	}
}

// TestManifestIsStableAndShowsEveryChange: two runs over the same data give
// the same manifest; a changed clear column changes only that table's row
// digest, a changed sealed column only its ciphertext digest, and compare
// says so and exits on it.
func TestManifestIsStableAndShowsEveryChange(t *testing.T) {
	w := seed(t)
	_, first, _ := w.run(t, "", false)
	_, second, _ := w.run(t, "", false)
	if diffs, report := compare(t, first, second, datacheck.Expectations{}); len(diffs) != 0 {
		t.Fatalf("two runs differ:\n%s", report)
	}

	// A split column changes its own digest only, not the row digest.
	w.exec(t, w.tenant, `UPDATE messages SET sender_pn = '5531000000000' WHERE wa_id = 'WA001'`)
	_, pnChanged, _ := w.run(t, "", false)
	prefix := "workspaces/" + w.tenant.String() + "/devices/" + w.device.String() + "/tables/messages/"
	if diffs, report := compare(t, first, pnChanged, datacheck.Expectations{}); datacheck.Unexpected(diffs) == 0 ||
		!strings.Contains(report, "unexpected "+prefix+"columns/sender_pn") || strings.Contains(report, prefix+"rows") {
		t.Fatalf("a changed sender_pn:\n%s", report)
	}
	w.exec(t, w.tenant, `UPDATE messages SET sender_pn = $1 WHERE wa_id = 'WA001'`, senderPN)

	w.exec(t, w.tenant, `UPDATE messages SET is_forwarded = NOT is_forwarded WHERE wa_id = 'WA001'`)
	_, changed, _ := w.run(t, "", false)
	diffs, report := compare(t, first, changed, datacheck.Expectations{})
	rows := prefix + "rows"
	if datacheck.Unexpected(diffs) == 0 || !strings.Contains(report, "unexpected "+rows) || strings.Contains(report, "columns/sender_pn") {
		t.Fatalf("a changed clear column went unseen:\n%s", report)
	}
	for _, d := range diffs {
		if strings.HasSuffix(d.Path, "/ciphertext") {
			t.Fatalf("a clear change moved a ciphertext digest: %s", report)
		}
	}
	// Declared, it passes.
	diffs, report = compare(t, first, changed, datacheck.Expectations{Allow: []string{"workspaces/*/devices/*/tables/messages/rows",
		"workspaces/*/inventory/**", "workspaces/*/fields/storage_archive_bytes"}})
	if n := datacheck.Unexpected(diffs); n != 0 {
		t.Fatalf("%d unexpected after declaring it:\n%s", n, report)
	}

	w.exec(t, w.tenant, `UPDATE messages SET body_sealed = 'another ciphertext' WHERE wa_id = 'WA002'`)
	_, sealed, _ := w.run(t, "", false)
	_, report = compare(t, changed, sealed, datacheck.Expectations{})
	if !strings.Contains(report, "/tables/messages/ciphertext") || strings.Contains(report, "/tables/messages/rows") {
		t.Fatalf("a sealed change:\n%s", report)
	}
}

// TestSeqOffsetIsDeclaredExactly: renumbering every seq of a workspace by
// one offset (as a move or an import does, plan 2.5) leaves the seq digests
// and the per-chat order digests equal and moves each max seq by exactly
// the offset; seq-offset accepts that offset and no other.
func TestSeqOffsetIsDeclaredExactly(t *testing.T) {
	w := seed(t)
	_, before, _ := w.run(t, "", false)
	// The seeded chats were never read through: the 0 a renumbering keeps.
	var unread int
	if err := pg.InTenantTx(context.Background(), w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM chats WHERE read_through_seq = 0`).Scan(&unread)
	}); err != nil || unread == 0 {
		t.Fatalf("no chat with read_through_seq 0 (%d): %v", unread, err)
	}
	const offset = 1000000
	for _, q := range []string{
		`UPDATE messages SET seq = seq + 1000000 WHERE tenant_id = $1`,
		`UPDATE receipts SET seq = seq + 1000000 WHERE tenant_id = $1`,
		`UPDATE events SET seq = seq + 1000000 WHERE tenant_id = $1`,
		// device_transfer's own rule: a 0 ("none yet") stays 0.
		`UPDATE chats SET last_seq = CASE WHEN last_seq > 0 THEN last_seq + 1000000 ELSE 0 END,
			read_through_seq = CASE WHEN read_through_seq > 0 THEN read_through_seq + 1000000 ELSE 0 END WHERE tenant_id = $1`,
	} {
		w.exec(t, w.tenant, q, w.tenant)
	}
	_, shifted, _ := w.run(t, "", false)
	if diffs, report := compare(t, before, shifted, datacheck.Expectations{}); datacheck.Unexpected(diffs) == 0 {
		t.Fatalf("a renumbering passed as equal:\n%s", report)
	}
	diffs, report := compare(t, before, shifted, datacheck.Expectations{Kind: datacheck.ExpectSeqOffset, Offset: offset})
	if !strings.Contains(report, "last_seq must be raised") {
		t.Fatalf("a last_seq left below the imported seqs passed:\n%s", report)
	}
	for _, d := range diffs {
		if !d.Declared && !strings.HasSuffix(d.Path, "/last_seq") {
			t.Fatalf("unexpected besides last_seq:\n%s", report)
		}
	}
	if _, err := w.pool.Exec(context.Background(), `UPDATE tenants SET last_seq = last_seq + 1000000 WHERE id = $1`, w.tenant); err != nil {
		t.Fatal(err)
	}
	_, raised, _ := w.run(t, "", false)
	if diffs, report := compare(t, before, raised, datacheck.Expectations{Kind: datacheck.ExpectSeqOffset, Offset: offset}); datacheck.Unexpected(diffs) != 0 {
		t.Fatalf("an exact renumbering:\n%s", report)
	}
	if diffs, report := compare(t, before, raised, datacheck.Expectations{Kind: datacheck.ExpectSeqOffset, Offset: offset + 1}); datacheck.Unexpected(diffs) == 0 {
		t.Fatalf("the wrong offset passed:\n%s", report)
	}
	// A message moved to another place in its chat's order is not a renumbering.
	w.exec(t, w.tenant, `UPDATE messages SET seq = seq + 500 WHERE wa_id = 'WA000'`)
	_, reordered, _ := w.run(t, "", false)
	if diffs, report := compare(t, before, reordered, datacheck.Expectations{Kind: datacheck.ExpectSeqOffset, Offset: offset}); datacheck.Unexpected(diffs) == 0 {
		t.Fatalf("a reordering passed:\n%s", report)
	}
}

// TestKeyChangeNeedsEveryHolderAtTheNewEpoch: a new epoch passes key-change
// only when every holder of the old one holds the new one, at the new key's
// fingerprint, and the old key and grants are kept.
func TestKeyChangeNeedsEveryHolderAtTheNewEpoch(t *testing.T) {
	w := seed(t)
	_, before, _ := w.run(t, "", false)
	pub2, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(context.Background(), w.tenant, w.device, 2, pub2); err != nil {
		t.Fatal(err)
	}
	w.grant(t, w.owner, 2)
	_, partial, _ := w.run(t, "", false)
	diffs, report := compare(t, before, partial, datacheck.Expectations{Kind: datacheck.ExpectKeyChange})
	if datacheck.Unexpected(diffs) != 1 || !strings.Contains(report, w.person.String()+":2") {
		t.Fatalf("a holder left behind:\n%s", report)
	}
	w.grant(t, w.person, 2)
	_, full, _ := w.run(t, "", false)
	if diffs, report := compare(t, before, full, datacheck.Expectations{Kind: datacheck.ExpectKeyChange}); datacheck.Unexpected(diffs) != 0 {
		t.Fatalf("a complete key change:\n%s", report)
	}
	if diffs, report := compare(t, before, full, datacheck.Expectations{}); datacheck.Unexpected(diffs) == 0 {
		t.Fatalf("a key change passed as equal:\n%s", report)
	}
	// Losing a grant of the old epoch is never declared.
	w.exec(t, w.tenant, `DELETE FROM device_key_grants WHERE user_id = $1 AND epoch = 1`, w.person)
	_, lost, _ := w.run(t, "", false)
	if diffs, report := compare(t, before, lost, datacheck.Expectations{Kind: datacheck.ExpectKeyChange}); datacheck.Unexpected(diffs) == 0 {
		t.Fatalf("a removed grant passed:\n%s", report)
	}
}

// TestObjectsAreListedHashedAndCrossChecked: every object is read and
// hashed; the stored attachment matches its key and its rows; the object no
// row names, the row whose object is gone, a corrupted object and an object
// under no workspace are each reported; the sums are sha256sum's lines.
func TestObjectsAreListedHashedAndCrossChecked(t *testing.T) {
	w := seed(t)
	m, _, sums := w.run(t, "", true)
	o := m.Objects
	s := o.Workspaces[w.tenant.String()]
	if s == nil || s.Count != 2 || s.HashMismatch != 1 || s.NotInDatabase != 1 || s.Missing != 1 || s.SizeMismatch != 0 || s.NoStorageRow != 0 {
		t.Fatalf("workspace objects: %+v", s)
	}
	if o.Other == nil || o.Other.Count != 1 || o.Other.Unrecognised != 1 || o.Other.NotInDatabase != 1 {
		t.Fatalf("other objects: %+v", o.Other)
	}
	if e := o.Workspaces[w.other.String()]; e == nil || e.Count != 0 {
		t.Fatalf("the other workspace: %+v", e)
	}
	if o.Total.Count != 3 || o.Problems() != 4 {
		t.Fatalf("total %+v, %d problems", o.Total, o.Problems())
	}
	lines := strings.Split(strings.TrimSuffix(sums, "\n"), "\n")
	if len(lines) != 3 || !slices.IsSorted(keysOf(lines)) {
		t.Fatalf("sums: %q", sums)
	}
	cipher := sha256.Sum256([]byte("ciphertext of an attachment"))
	if want := hex.EncodeToString(cipher[:]) + "  " + w.mediaKey; !slices.Contains(lines, want) {
		t.Fatalf("no line %q in %q", want, sums)
	}

	// A corrupted copy of the stored attachment is a mismatch too.
	w.bucket.put(w.mediaKey, []byte("ciphertext of an attachmenT"))
	m, _, _ = w.run(t, "", true)
	if s := m.Objects.Workspaces[w.tenant.String()]; s.HashMismatch != 2 {
		t.Fatalf("a corrupted object: %+v", s)
	}

	// One workspace's prefix only.
	m, _, sums = w.run(t, w.tenant.String(), true)
	if m.Objects.Prefix != w.tenant.String()+"/" || m.Objects.Other != nil || strings.Count(sums, "\n") != 2 {
		t.Fatalf("prefix scope: %+v %q", m.Objects, sums)
	}
}

func keysOf(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		_, k, _ := strings.Cut(l, "  ")
		out[i] = k
	}
	return out
}

// TestNothingRecognisableInTheOutput: no label, phone number, LID, e-mail,
// workspace name, push name or content appears in the manifest, its
// summary, the object sums, or a comparison's report.
func TestNothingRecognisableInTheOutput(t *testing.T) {
	w := seed(t)
	m, before, sums := w.run(t, "", true)
	var summary bytes.Buffer
	if err := datacheck.WriteSummary(&summary, m); err != nil {
		t.Fatal(err)
	}
	w.exec(t, w.tenant, `UPDATE messages SET sender_pn = $1 WHERE wa_id = 'WA001'`, senderPN+"9")
	_, after, _ := w.run(t, "", true)
	_, report := compare(t, before, after, datacheck.Expectations{})
	for name, out := range map[string]string{"manifest": string(before), "summary": summary.String(), "sums": sums, "report": report} {
		for _, s := range secrets {
			if strings.Contains(strings.ToLower(out), strings.ToLower(s)) {
				t.Errorf("the %s holds %q", name, s)
			}
		}
	}
	// The chat uid store.ChatUID derives is predictable from the number's
	// id and the chat key, so it must not name a chat.
	for _, chat := range []string{w.directChat, w.groupChat} {
		if uid := store.ChatUID(w.device, chat).String(); strings.Contains(string(before), uid) || strings.Contains(report, uid) {
			t.Errorf("the output names a chat by its derived uid %s", uid)
		}
	}
	if !strings.Contains(summary.String(), w.device.String()) {
		t.Fatalf("the summary does not name the number by id:\n%s", summary.String())
	}
}

// TestOnlyAReadOnlySnapshotIsAccepted: Collect refuses a transaction that
// could write, and the one Begin gives cannot.
func TestOnlyAReadOnlySnapshotIsAccepted(t *testing.T) {
	w := seed(t)
	ctx := context.Background()
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := datacheck.Collect(ctx, tx, datacheck.Options{}); !errors.Is(err, datacheck.ErrNotReadOnly) {
		t.Fatalf("a writable transaction: %v", err)
	}
	_ = tx.Rollback(ctx)

	ro, err := datacheck.Begin(ctx, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Rollback(ctx) //nolint:errcheck // read only
	if _, err := ro.Exec(ctx, `UPDATE tenants SET last_seq = last_seq + 1`); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("a write in the check's transaction: %v", err)
	}
}

// TestOneWorkspaceScope: -workspace limits the manifest to that workspace;
// an unknown one is refused.
func TestOneWorkspaceScope(t *testing.T) {
	w := seed(t)
	m, _, _ := w.run(t, w.other.String(), false)
	if m.Scope != w.other.String() || len(m.Workspaces) != 1 || m.Workspaces[w.other.String()] == nil || m.ReaderState != nil {
		t.Fatalf("scope: %s %v", m.Scope, m.Workspaces)
	}
	ctx := context.Background()
	tx, err := datacheck.Begin(ctx, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read only
	if _, err := datacheck.Collect(ctx, tx, datacheck.Options{Workspace: uuid.NewString()}); !errors.Is(err, datacheck.ErrNoWorkspace) {
		t.Fatalf("an unknown workspace: %v", err)
	}
}

// memBucket is an object store in memory. Only the test puts objects: the
// check sees it as a datacheck.ObjectStore, which cannot write.
type memBucket struct {
	objects map[string][]byte
}

func newMemBucket() *memBucket { return &memBucket{objects: map[string][]byte{}} }

func (b *memBucket) put(key string, data []byte) { b.objects[key] = data }

func (b *memBucket) List(ctx context.Context, prefix, after string, fn func(blob.ObjectInfo) error) error {
	keys := make([]string, 0, len(b.objects))
	for k := range b.objects {
		if strings.HasPrefix(k, prefix) && k > after {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		if err := fn(blob.ObjectInfo{Key: k, Size: int64(len(b.objects[k]))}); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (b *memBucket) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	data, ok := b.objects[key]
	if !ok {
		return nil, 0, blob.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), int64(len(data)), nil
}

// TestDeletedNumbersAreShown: a number in its quarantine (deleted, awaiting
// its purge) is in the manifest with its devices fields, read as the
// server's role, which the device_quarantine policy (0050) would otherwise
// hide it from.
func TestDeletedNumbersAreShown(t *testing.T) {
	w := seed(t)
	ctx := context.Background()
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', 'on', true)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE devices SET deleted_at = now(), purge_after = now() + interval '30 days', paused = true WHERE id = $1`, w.keyless)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The test's role is subject to RLS: a plain read does not see it.
	var seen int
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id = $1`, w.keyless).Scan(&seen)
	}); err != nil || seen != 0 {
		t.Fatalf("the deleted number is visible without the scope (%d): %v", seen, err)
	}
	m, _, _ := w.run(t, "", false)
	d := m.Workspaces[w.tenant.String()].Devices[w.keyless.String()]
	if d == nil || !d.Present || d.Fields["deleted_at"] == nil || d.Fields["purge_after"] == nil || *d.Fields["paused"] != "true" {
		t.Fatalf("the deleted number: %+v", d)
	}
	// The read check counts live numbers only.
	if rc := m.Workspaces[w.tenant.String()].ReadCheck; len(rc.Keyless) != 0 {
		t.Fatalf("read check: %+v", rc)
	}
}

// TestASchemaWithoutANewColumn: a split column the schema lacks (a binary
// newer than the schema) is listed as absent and covered by no digest,
// and the manifest after the column appears compares as a migration; a
// missing column of any other kind stops the check.
func TestASchemaWithoutANewColumn(t *testing.T) {
	w := seed(t)
	ctx := context.Background()
	_, with, _ := w.run(t, "", false)
	if _, err := w.pool.Exec(ctx, `ALTER TABLE contacts DROP COLUMN contact_lid`); err != nil {
		t.Fatal(err)
	}
	m, without, _ := w.run(t, "", false)
	if a := m.Digests["contacts"].Absent; !slices.Equal(a, []string{"contact_lid"}) {
		t.Fatalf("absent: %v", a)
	}
	ct := m.Workspaces[w.tenant.String()].Devices[w.device.String()].Tables["contacts"]
	if _, ok := ct.Columns["contact_lid"]; ok || ct.Count != 1 {
		t.Fatalf("contacts without the column: %+v", ct)
	}
	if diffs, report := compare(t, without, with, datacheck.Expectations{Kind: datacheck.ExpectMigration}); datacheck.Unexpected(diffs) != 0 {
		t.Fatalf("the column added:\n%s", report)
	}
	if diffs, report := compare(t, with, without, datacheck.Expectations{Kind: datacheck.ExpectMigration}); datacheck.Unexpected(diffs) == 0 {
		t.Fatalf("the column dropped passed:\n%s", report)
	}

	if _, err := w.pool.Exec(ctx, `ALTER TABLE contacts DROP COLUMN avatar_checked_at`); err != nil {
		t.Fatal(err)
	}
	tx, err := datacheck.Begin(ctx, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read only
	if _, err := datacheck.Collect(ctx, tx, datacheck.Options{}); !errors.Is(err, datacheck.ErrSchema) {
		t.Fatalf("a clear column missing: %v", err)
	}
}

// TestAFileWithNoPathIsAnError: an unset ledger path is not "absent".
func TestAFileWithNoPathIsAnError(t *testing.T) {
	w := seed(t)
	ctx := context.Background()
	tx, err := datacheck.Begin(ctx, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read only
	if _, err := datacheck.Collect(ctx, tx, datacheck.Options{Files: map[string]string{"deletion_ledger": ""}}); !errors.Is(err, datacheck.ErrNoFilePath) {
		t.Fatalf("an empty path: %v", err)
	}
}
