package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// A relink links a logged-out number again into the same row: these test
// its store side. Fictional accounts only.

// loggedOutNumber is a number the phone logged out: an archive key at epoch
// 1, its owner's grant, its stored identity under device 3, and no session.
func (w *delWorld) loggedOutNumber(t *testing.T, label, pn, lid string) (uuid.UUID, wa.Identity) {
	t.Helper()
	ctx := context.Background()
	w.pns++
	id := wa.Identity{
		PN:  types.JID{User: pn, Device: 3, Server: types.DefaultUserServer},
		LID: types.JID{User: lid, Device: 3, Server: types.HiddenUserServer},
	}
	dev, err := w.devices.Create(ctx, w.tenant.String(), label, wa.ModeActive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(dev.ID)
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), dev.ID, id); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.SetStatus(ctx, w.tenant.String(), dev.ID, wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.SetStatus(ctx, w.tenant.String(), dev.ID, wa.StatusLoggedOut, "unlinked (logged out)"); err != nil {
		t.Fatal(err)
	}
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	w.reads(t, w.owner, device)
	return device, id
}

// execOne runs one statement in the workspace that must change one row.
func (w *delWorld) execOne(t *testing.T, query string, args ...any) {
	t.Helper()
	ctx := context.Background()
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, query, args...)
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("the statement changed no row")
		}
		return err
	})
}

func newLink(id wa.Identity) wa.Identity {
	return wa.Identity{
		PN:       types.JID{User: id.PN.User, Device: 8, Server: types.DefaultUserServer},
		LID:      types.JID{User: id.LID.User, Device: 8, Server: types.HiddenUserServer},
		PushName: "Loja",
	}
}

// putSession stores a whatsmeow session row under jid, as PutDevice does.
func (w *delWorld) putSession(t *testing.T, jid string) {
	t.Helper()
	if _, err := w.pool.Exec(context.Background(), `INSERT INTO whatsmeow_device (jid, registration_id) VALUES ($1, 7)`, jid); err != nil {
		t.Fatal(err)
	}
}

func (w *delWorld) seen(t *testing.T, device uuid.UUID) store.RelinkSeen {
	t.Helper()
	row, err := w.devices.RelinkRow(context.Background(), w.tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	return store.RelinkSeen{PauseSeq: row.PauseSeq}
}

// rowSnapshot is every column of a number a relink must leave, and the
// rows that hang off it.
type rowSnapshot struct {
	ID, Tenant, ArchiveTenant, Label, ReceiptMode string
	Epoch                                         int
	Keys, Grants, Permissions, Messages, Chats    int
}

func (w *delWorld) snapshot(t *testing.T, device uuid.UUID) rowSnapshot {
	t.Helper()
	var s rowSnapshot
	w.scoped(t, func(tx pgx.Tx) error {
		ctx := context.Background()
		if err := tx.QueryRow(ctx, `SELECT id::text, tenant_id::text, archive_tenant_id::text, label, receipt_mode, current_epoch
			FROM devices WHERE id = $1`, device).Scan(&s.ID, &s.Tenant, &s.ArchiveTenant, &s.Label, &s.ReceiptMode, &s.Epoch); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM device_archive_keys WHERE device_id = $1),
			(SELECT count(*) FROM device_key_grants WHERE device_id = $1),
			(SELECT count(*) FROM device_permissions WHERE device_id = $1),
			(SELECT count(*) FROM messages WHERE device_id = $1),
			(SELECT count(*) FROM chats WHERE device_id = $1)`, device).
			Scan(&s.Keys, &s.Grants, &s.Permissions, &s.Messages, &s.Chats)
	})
	return s
}

func TestRelinkRowAndKeyHeld(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	device, id := w.loggedOutNumber(t, "Loja", "155501000101", "100000000000101")
	row, err := w.devices.RelinkRow(ctx, w.tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != wa.StatusLoggedOut || row.Identity.PN != id.PN || row.Identity.LID != id.LID ||
		row.Epoch != 1 || row.ReceiptMode != wa.ModeActive {
		t.Fatalf("row %+v", row)
	}
	other := uuid.MustParse(newTenant(t, w.pool, "other"))
	if _, err := w.devices.RelinkRow(ctx, other, device); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another workspace's read = %v, want not found", err)
	}
	if held, err := w.devices.KeyHeld(ctx, w.tenant, device); err != nil || !held {
		t.Fatalf("KeyHeld with the owner's grant = %v, %v", held, err)
	}
	// A suspended person whose membership stands still holds the key.
	w.execOne(t, `UPDATE users SET status = 'disabled' WHERE id = $1`, w.owner)
	if held, err := w.devices.KeyHeld(ctx, w.tenant, device); err != nil || !held {
		t.Fatalf("KeyHeld with a suspended holder = %v, %v", held, err)
	}
	// An expiring membership does not.
	w.execOne(t, `UPDATE workspace_memberships SET expires_at = now() + interval '1 day' WHERE user_id = $1`, w.owner)
	if held, err := w.devices.KeyHeld(ctx, w.tenant, device); err != nil || held {
		t.Fatalf("KeyHeld with an expiring membership only = %v, %v", held, err)
	}
	// A number with no key at all.
	bare, err := w.devices.Create(ctx, w.tenant.String(), "bare", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := w.devices.KeyHeld(ctx, w.tenant, uuid.MustParse(bare.ID)); err != nil || held {
		t.Fatalf("KeyHeld at epoch 0 = %v, %v", held, err)
	}

	excludeNumber(t, w.pool, w.tenant, device)
	if _, err := w.devices.RelinkRow(ctx, w.tenant, device); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a deleted number's read = %v, want not found", err)
	}
}

func TestHeldElsewhere(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	device, id := w.loggedOutNumber(t, "Loja", "155501000201", "100000000000201")
	held := func() bool {
		t.Helper()
		h, err := w.devices.HeldElsewhere(ctx, w.tenant, device, newLink(id))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if held() {
		t.Fatal("the number itself counts as another")
	}
	// The same account, linked again as a new number: the phone under another
	// device number.
	twin := linkedNumber(t, w.pool, w.tenant, "twin", id.PN.User, "100000000000299")
	if !held() {
		t.Fatal("a live number with the same phone does not count")
	}
	if err := w.devices.SetPaused(ctx, w.tenant.String(), twin.String(), true); err != nil {
		t.Fatal(err)
	}
	if !held() {
		t.Fatal("a paused number with the same phone does not count")
	}
	for _, status := range []wa.Status{wa.StatusLoggedOut, wa.StatusBanned} {
		if err := w.devices.SetStatus(ctx, w.tenant.String(), twin.String(), status, ""); err != nil {
			t.Fatal(err)
		}
		if held() {
			t.Fatalf("a %s number counts", status)
		}
	}
	// The LID alone is enough.
	linkedNumber(t, w.pool, w.tenant, "lid twin", "155501000298", id.LID.User)
	if !held() {
		t.Fatal("a live number with the same LID does not count")
	}
	// Another workspace never counts.
	other := uuid.MustParse(newTenant(t, w.pool, "other"))
	if h, err := w.devices.HeldElsewhere(ctx, other, uuid.New(), newLink(id)); err != nil || h {
		t.Fatalf("another workspace = %v, %v", h, err)
	}
}

// The attach names the new link and changes nothing else of the number:
// its id, workspace, label, receipt mode, epoch, key, grants, permissions
// and archive stay, and no item event is written.
func TestAttachRelinkKeepsTheNumber(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	sessionStore(t, w.pool)
	device, id := w.loggedOutNumber(t, "Loja", "155501000301", "100000000000301")
	if _, err := store.NewMessages(w.pool).Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: w.tenant, DeviceID: device,
		WAID: "wa-1", ChatKey: "155501000399@s.whatsapp.net", ChatPN: "155501000399@s.whatsapp.net",
		Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive, BodySealed: []byte("sealed")}); err != nil {
		t.Fatal(err)
	}
	before := w.snapshot(t, device)
	events := w.count(t, `SELECT count(*) FROM item_events`)
	linked := newLink(id)
	w.putSession(t, linked.PN.String())

	got, err := w.devices.AttachRelink(ctx, w.tenant, device, w.seen(t, device), linked)
	if err != nil {
		t.Fatal(err)
	}
	if got.ResumedPause || got.OldSessionLeft {
		t.Fatalf("attached %+v, want nothing lifted or left", got)
	}
	if after := w.snapshot(t, device); after != before {
		t.Fatalf("the attach changed the number:\nbefore %+v\nafter  %+v", before, after)
	}
	row, err := w.devices.RelinkRow(ctx, w.tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	if row.Identity.PN != linked.PN || row.Identity.LID != linked.LID || row.Status != wa.StatusOffline || row.StatusReason != "linked again" {
		t.Fatalf("row after the attach %+v", row)
	}
	d, err := w.devices.Get(ctx, w.tenant.String(), device.String())
	if err != nil {
		t.Fatal(err)
	}
	if d.Identity.PushName != "Loja" {
		t.Fatalf("push name %q", d.Identity.PushName)
	}
	if n := w.count(t, `SELECT count(*) FROM item_events`); n != events {
		t.Fatalf("the attach wrote %d item events", n-events)
	}
}

// A person's pause is lifted in the attach, and the open notices it raised
// are marked resumed in the same transaction; a seen one stays as it was.
func TestAttachRelinkLiftsThePause(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	sessionStore(t, w.pool)
	device, id := w.loggedOutNumber(t, "Loja", "155501000401", "100000000000401")
	reader := w.person(t, "reader", "member")
	w.reads(t, reader, device)
	if _, err := w.devices.Pause(ctx, w.tenant, device, store.PauseActor{User: w.owner}); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE device_id = $1 AND kind = 'sync_paused' AND resumed_at IS NULL`, device); n != 1 {
		t.Fatalf("%d open pause notices before the attach, want 1", n)
	}
	linked := newLink(id)
	w.putSession(t, linked.PN.String())
	got, err := w.devices.AttachRelink(ctx, w.tenant, device, w.seen(t, device), linked)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ResumedPause {
		t.Fatal("the attach did not say it lifted the pause")
	}
	row, err := w.devices.RelinkRow(ctx, w.tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	if row.Paused || row.PauseCause != "" {
		t.Fatalf("after the attach paused=%v cause=%q", row.Paused, row.PauseCause)
	}
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE device_id = $1 AND kind = 'sync_paused' AND resumed_at IS NOT NULL`, device); n != 1 {
		t.Fatalf("%d resumed pause notices after the attach, want 1", n)
	}
}

// The attach deletes no session. A row under the old link's JID may be
// another workspace's live link, since WhatsApp can give the account's freed
// device number to a new link and number_held asks this workspace only: it
// stays, with its privacy tokens. With no session under the old JID, the old
// link's tokens go. The new link's stay either way.
func TestAttachRelinkLeavesTheOldJIDsSession(t *testing.T) {
	for name, otherLive := range map[string]bool{"another workspace's live link": true, "no session": false} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			w := newDelWorld(t)
			sessionStore(t, w.pool)
			device, id := w.loggedOutNumber(t, "Loja", "155501000501", "100000000000501")
			if otherLive {
				other := uuid.MustParse(newTenant(t, w.pool, "other"))
				linkedNumber(t, w.pool, other, "theirs", id.PN.User, id.LID.User)
				w.putSession(t, id.PN.String())
			}
			linked := newLink(id)
			w.putSession(t, linked.PN.String())
			for _, jid := range []string{id.PN.String(), linked.PN.String()} {
				if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_privacy_tokens VALUES ($1, '155501000599@s.whatsapp.net', 'x', 1)`, jid); err != nil {
					t.Fatal(err)
				}
			}
			got, err := w.devices.AttachRelink(ctx, w.tenant, device, w.seen(t, device), linked)
			if err != nil {
				t.Fatal(err)
			}
			if got.OldSessionLeft != otherLive {
				t.Fatalf("old session left = %v, want %v", got.OldSessionLeft, otherLive)
			}
			want := map[bool]int{true: 1, false: 0}[otherLive]
			if n := w.count(t, `SELECT count(*) FROM whatsmeow_device WHERE jid = $1`, id.PN.String()); n != want {
				t.Fatalf("%d session rows under the old JID, want %d", n, want)
			}
			if n := w.count(t, `SELECT count(*) FROM whatsmeow_privacy_tokens WHERE our_jid = $1`, id.PN.String()); n != want {
				t.Fatalf("%d privacy tokens under the old JID, want %d", n, want)
			}
			if n := w.count(t, `SELECT count(*) FROM whatsmeow_device WHERE jid = $1`, linked.PN.String()); n != 1 {
				t.Fatal("the new session row went")
			}
			if n := w.count(t, `SELECT count(*) FROM whatsmeow_privacy_tokens WHERE our_jid = $1`, linked.PN.String()); n != 1 {
				t.Fatal("the new link's privacy tokens went")
			}
		})
	}
}

// The attach is a compare-and-set on what the relink saw at its start: any
// change since refuses it, and the number stays exactly as it was.
func TestAttachRelinkRefuses(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		change func(t *testing.T, w *delWorld, device uuid.UUID, id wa.Identity)
		noNew  bool
		want   error
	}{
		"deleted meanwhile": {change: func(t *testing.T, w *delWorld, device uuid.UUID, _ wa.Identity) {
			excludeNumber(t, w.pool, w.tenant, device)
		}, want: store.ErrRelinkStateChanged},
		"online again": {change: func(t *testing.T, w *delWorld, device uuid.UUID, _ wa.Identity) {
			if err := w.devices.SetStatus(ctx, w.tenant.String(), device.String(), wa.StatusOnline, ""); err != nil {
				t.Fatal(err)
			}
		}, want: store.ErrRelinkStateChanged},
		"paused since": {change: func(t *testing.T, w *delWorld, device uuid.UUID, _ wa.Identity) {
			if _, err := w.devices.Pause(ctx, w.tenant, device, store.PauseActor{User: w.owner}); err != nil {
				t.Fatal(err)
			}
		}, want: store.ErrRelinkStateChanged},
		"a move's pause": {change: func(t *testing.T, w *delWorld, device uuid.UUID, _ wa.Identity) {
			inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE devices SET paused = true, pause_cause = 'move' WHERE id = $1`, device)
				return err
			})
		}, want: store.ErrRelinkStateChanged},
		"the workspace suspended": {change: func(t *testing.T, w *delWorld, _ uuid.UUID, _ wa.Identity) {
			if _, err := w.pool.Exec(ctx, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, w.tenant); err != nil {
				t.Fatal(err)
			}
		}, want: store.ErrRelinkStateChanged},
		"storage paused": {change: func(t *testing.T, w *delWorld, _ uuid.UUID, _ wa.Identity) {
			if _, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at = now() WHERE id = $1`, w.tenant); err != nil {
				t.Fatal(err)
			}
		}, want: store.ErrStoragePaused},
		"the account linked again as another number": {change: func(t *testing.T, w *delWorld, _ uuid.UUID, id wa.Identity) {
			linkedNumber(t, w.pool, w.tenant, "twin", id.PN.User, "100000000000699")
		}, want: store.ErrRelinkNumberHeld},
		"no new session": {noNew: true, want: store.ErrRelinkNoSession},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			w := newDelWorld(t)
			sessionStore(t, w.pool)
			device, id := w.loggedOutNumber(t, "Loja", "155501000601", "100000000000601")
			seen := w.seen(t, device)
			linked := newLink(id)
			if !tc.noNew {
				w.putSession(t, linked.PN.String())
			}
			if tc.change != nil {
				tc.change(t, w, device, id)
			}
			var before string
			w.scoped(t, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT pn || lid || status || paused::text FROM devices WHERE id = $1`, device).Scan(&before)
			})
			if _, err := w.devices.AttachRelink(ctx, w.tenant, device, seen, linked); !errors.Is(err, tc.want) {
				t.Fatalf("AttachRelink = %v, want %v", err, tc.want)
			}
			var after string
			w.scoped(t, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT pn || lid || status || paused::text FROM devices WHERE id = $1`, device).Scan(&after)
			})
			if after != before {
				t.Fatalf("a refused attach changed the number: %q, then %q", before, after)
			}
		})
	}
}

func TestRelinkRecheck(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	device, id := w.loggedOutNumber(t, "Loja", "155501000701", "100000000000701")
	seen := w.seen(t, device)
	if err := w.devices.RelinkRecheck(ctx, w.tenant, device, seen, id); err != nil {
		t.Fatalf("a logged-out number = %v", err)
	}
	if err := w.devices.RelinkRecheck(ctx, w.tenant, device, store.RelinkSeen{PauseSeq: seen.PauseSeq + 1}, id); !errors.Is(err, store.ErrRelinkStateChanged) {
		t.Fatalf("a pause since = %v", err)
	}
	linkedNumber(t, w.pool, w.tenant, "twin", "155501000798", id.LID.User)
	if err := w.devices.RelinkRecheck(ctx, w.tenant, device, seen, id); !errors.Is(err, store.ErrRelinkNumberHeld) {
		t.Fatalf("the account held by another number = %v", err)
	}
	if err := w.devices.RelinkState(ctx, w.tenant, device, seen); err != nil {
		t.Fatalf("RelinkState asks no number_held: %v", err)
	}
}

// A stop keeps a logged-out or banned status: the number stays one to link
// again, not one that reads as merely offline.
func TestMarkPausedOfflineKeepsTerminal(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	device, _ := w.loggedOutNumber(t, "Loja", "155501000801", "100000000000801")
	status, reason, err := w.devices.MarkPausedOffline(ctx, w.tenant.String(), device.String())
	if err != nil || status != wa.StatusLoggedOut || reason != "unlinked (logged out)" {
		t.Fatalf("logged out: %q %q %v", status, reason, err)
	}
	if err := w.devices.SetStatus(ctx, w.tenant.String(), device.String(), wa.StatusBanned, "banned"); err != nil {
		t.Fatal(err)
	}
	if status, _, err := w.devices.MarkPausedOffline(ctx, w.tenant.String(), device.String()); err != nil || status != wa.StatusBanned {
		t.Fatalf("banned: %q %v", status, err)
	}
	if err := w.devices.SetStatus(ctx, w.tenant.String(), device.String(), wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	if status, reason, err := w.devices.MarkPausedOffline(ctx, w.tenant.String(), device.String()); err != nil ||
		status != wa.StatusOffline || reason != "paused by request" {
		t.Fatalf("online: %q %q %v", status, reason, err)
	}
	if _, _, err := w.devices.MarkPausedOffline(ctx, w.tenant.String(), uuid.NewString()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no such number: %v", err)
	}
}
