package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Recovering a deleted number, the last-reader rule over deleted numbers,
// and what a deletion's logout leaves behind.

func (w *delWorld) capacity(t *testing.T, max int) {
	t.Helper()
	inTenantTx(context.Background(), t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO workspace_capacity(tenant_id,max_devices) VALUES ($1,$2)
			ON CONFLICT (tenant_id) DO UPDATE SET max_devices=excluded.max_devices`, w.tenant, max)
		return err
	})
}

func (w *delWorld) recover(t *testing.T, device uuid.UUID) store.Recovered {
	t.Helper()
	r, err := w.devices.Recover(context.Background(), w.tenant, w.owner, device)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	return r
}

func TestRelinkWhileExcluded(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	old := w.number(t, "Suporte")
	pn := w.pn(ctx, t, old)
	w.quarantine(t, old)
	d, err := w.devices.Get(ctx, w.tenant.String(), w.number(t, "other").String())
	if err != nil {
		t.Fatal(err)
	}
	// The new row takes the phone the old one had: allowed while it is
	// excluded.
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), d.ID, wa.Identity{PN: types.NewJID(strings.TrimSuffix(pn, "@s.whatsapp.net"), types.DefaultUserServer)}); err != nil {
		t.Fatalf("relinking the phone while its old row is excluded: %v", err)
	}
	if _, err := w.devices.Recover(ctx, w.tenant, w.owner, old); !errors.Is(err, store.ErrIdentityInUse) {
		t.Fatalf("recovering the old row: %v", err)
	}
	if !w.excluded(t, old) {
		t.Fatal("a refused recovery changed the row")
	}
}

func TestRecover(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Suporte")
	reader := w.person(t, "reader", "member")
	removed := w.person(t, "removed", "member")
	disabled := w.person(t, "disabled", "member")
	admin := w.person(t, "admin", "admin")
	for _, u := range []uuid.UUID{w.owner, reader, removed, disabled} {
		w.reads(t, u, device)
	}
	adminKey, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "admin's", store.ScopeRead, &admin, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.quarantine(t, device, reader, removed, disabled)
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE device_id=$1 AND kind='number_deleted'`, device); n != 3 {
		t.Fatalf("%d deletion notices, want one per reader", n)
	}
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, removed); err != nil {
		t.Fatal(err)
	}
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, disabled, "member", "disabled"); err != nil {
		t.Fatal(err)
	}
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, admin, "admin", "disabled"); err != nil {
		t.Fatal(err)
	}

	check, err := w.devices.RecoverCheck(ctx, w.tenant, w.owner, device)
	if err != nil {
		t.Fatal(err)
	}
	if len(check.Readers) != 1 || check.Readers[0].UserID != reader || !check.Recoverable || len(check.AllNumberKeys) != 0 {
		t.Fatalf("recover check = %+v", check)
	}
	r := w.recover(t, device)
	if r.Already || r.Status != wa.StatusLoggedOut && r.Status != wa.StatusOffline {
		t.Fatalf("recovered %+v", r)
	}
	got, err := w.devices.Get(ctx, w.tenant.String(), device.String())
	if err != nil || !got.Paused {
		t.Fatalf("the recovered number: %+v %v", got, err)
	}
	if p, err := w.users.DevicePermission(ctx, w.tenant, reader, device); err != nil || !p.Allows(store.ActionRead) {
		t.Fatalf("the reader's access did not come back: %+v %v", p, err)
	}
	for _, gone := range []uuid.UUID{removed, disabled} {
		if n := w.count(t, `SELECT (SELECT count(*) FROM device_key_grants WHERE user_id=$1)+(SELECT count(*) FROM device_permissions WHERE user_id=$1)
			+(SELECT count(*) FROM device_notices WHERE user_id=$1)`, gone); n != 0 {
			t.Fatalf("someone who left kept %d rows", n)
		}
	}
	if ok, err := w.apiKeys.AllowsDevice(ctx, w.keyID2(t, adminKey), w.tenant, device); err == nil && ok {
		t.Fatal("a key created by an admin disabled meanwhile reaches the recovered number")
	}
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE device_id=$1`, device); n != 0 {
		t.Fatalf("%d notices left after the recovery", n)
	}
	if n := w.count(t, `SELECT count(*) FROM item_events WHERE type='recovered' AND item_id=$1`, device); n != 1 {
		t.Fatalf("%d recovered rows", n)
	}

	// A retry of a live row answers Already, even with the plan full.
	w.capacity(t, 1)
	if again := w.recover(t, device); !again.Already {
		t.Fatalf("a retried recovery: %+v", again)
	}

	// A full plan refuses, and nothing changes.
	w.capacity(t, 5)
	second := w.number2(t)
	w.quarantine(t, second)
	w.capacity(t, 1)
	if _, err := w.devices.Recover(ctx, w.tenant, w.owner, second); !errors.Is(err, store.ErrCapacity) {
		t.Fatalf("a full plan: %v", err)
	}
	if !w.excluded(t, second) {
		t.Fatal("a refused recovery changed the row")
	}
	// Past its window, or with a purge started: closed, before capacity.
	w.scoped(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET purge_after=clock_timestamp()-interval '1 minute' WHERE id=$1`, second)
		return err
	})
	if _, err := w.devices.Recover(ctx, w.tenant, w.owner, second); !errors.Is(err, store.ErrRecoveryClosed) {
		t.Fatalf("past the window: %v", err)
	}
	w.scoped(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET purge_after=clock_timestamp()+interval '1 day', purge_started_at=clock_timestamp() WHERE id=$1`, second)
		return err
	})
	if _, err := w.devices.Recover(ctx, w.tenant, w.owner, second); !errors.Is(err, store.ErrRecoveryClosed) {
		t.Fatalf("a purge started: %v", err)
	}
	// A logout in flight holds the device lock.
	w.capacity(t, 10)
	third := w.number2(t)
	w.quarantine(t, third)
	release, ok, err := pg.NewLocker(w.pool).TryLock(ctx, "device:"+third.String())
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	if _, err := w.devices.Recover(ctx, w.tenant, w.owner, third); !errors.Is(err, store.ErrDeviceBusy) {
		t.Fatalf("a logout in flight: %v", err)
	}
	release()
	if !w.excluded(t, third) {
		t.Fatal("a busy recovery changed the row")
	}
	w.recover(t, third)
	// Only an owner recovers.
	if _, err := w.devices.Recover(ctx, w.tenant, w.person(t, "a2", "admin"), second); !errors.Is(err, store.ErrOwnerOnly) {
		t.Fatalf("an admin: %v", err)
	}
}

func (w *delWorld) number2(t *testing.T) uuid.UUID { return w.number(t, "n") }

func (w *delWorld) keyID2(t *testing.T, key string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	prefix, _, _ := strings.Cut(key, ".")
	if err := w.pool.QueryRow(context.Background(), `SELECT id FROM api_keys WHERE prefix=$1`, prefix).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// Recovery and deletion take the workspace row before the device row, so a
// blocker on the workspace leaves every device row free: a NOWAIT probe
// succeeds while they wait.
func TestRecoverAndDeleteLockTheWorkspaceFirst(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	excluded, live := w.number(t, "x"), w.number(t, "l")
	w.quarantine(t, excluded)
	blocker, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE`, w.tenant); err != nil {
		t.Fatal(err)
	}
	blockerPID := int(blocker.Conn().PgConn().PID())
	recovered := make(chan error, 1)
	deleted := make(chan error, 1)
	go func() {
		_, err := w.devices.Recover(ctx, w.tenant, w.owner, excluded)
		recovered <- err
	}()
	go func() {
		_, err := w.devices.Quarantine(ctx, w.tenant, w.owner, live, nil)
		deleted <- err
	}()
	waitBlocked(t, w, blockerPID, 2)
	// Two transactions wait on the workspace; the device rows are free.
	w.scoped(t, func(tx pgx.Tx) error {
		for _, id := range []uuid.UUID{excluded, live} {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM devices WHERE id=$1 FOR UPDATE NOWAIT`, id); err != nil {
				t.Errorf("a device row was locked before the workspace: %v", err)
				return err
			}
		}
		return nil
	})
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-recovered; err != nil {
		t.Fatalf("recover: %v", err)
	}
	if err := <-deleted; err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// waitBlocked waits until n backends wait on pid, directly or behind
// another waiter: a second transaction for the same row queues behind the
// first one, not behind the holder.
func waitBlocked(t *testing.T, w *delWorld, pid, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var blocked int
		if err := w.pool.QueryRow(context.Background(), `WITH RECURSIVE waiting(pid) AS (
			SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
			UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid=ANY(pg_blocking_pids(a.pid))
		) SELECT count(*) FROM waiting`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("fewer than %d transactions waited on the workspace", n)
}

func TestLastReaderOfExcluded(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	admin := w.person(t, "admin", "admin")
	// A live number whose only key holder is the target.
	liveTarget := w.person(t, "live", "member")
	live := w.number(t, "Vivo")
	w.reads(t, liveTarget, live)
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, liveTarget, "member", "disabled"); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("a live number's last reader: %v", err)
	}

	target := w.person(t, "target", "member")
	device := w.number(t, "Suporte")
	w.reads(t, target, device)
	q := w.quarantine(t, device, target)
	for name, act := range map[string]func(actor uuid.UUID) error{
		"disable": func(actor uuid.UUID) error {
			return w.users.UpdateMember(ctx, w.tenant, actor, target, "member", "disabled")
		},
		"remove": func(actor uuid.UUID) error { return w.users.RemoveMember(ctx, w.tenant, actor, target) },
	} {
		err := act(w.owner)
		var refused *store.ErrLastReaderOfDeleted
		if !errors.As(err, &refused) || len(refused.Numbers) != 1 {
			t.Fatalf("%s by an owner: %v", name, err)
		}
		n := refused.Numbers[0]
		if n.DeviceID != device || n.Label != "Suporte" || n.PN == "" || !n.PurgeAfter.Equal(q.PurgeAfter) {
			t.Fatalf("%s: the owner's list %+v", name, n)
		}
		if err := act(admin); !errors.As(err, &refused) || len(refused.Numbers) != 0 {
			t.Fatalf("%s by an admin: %v, %+v", name, err, refused)
		}
	}
	if n := w.count(t, `SELECT count(*) FROM workspace_memberships WHERE user_id=$1 AND status='active'`, target); n != 1 {
		t.Fatal("a refused removal changed the membership")
	}
	if n := w.count(t, `SELECT count(*) FROM device_key_grants WHERE user_id=$1`, target); n != 1 {
		t.Fatal("a refused removal changed the grants")
	}
	// The permission route cannot reach a hidden number at all.
	if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: target}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unsetting Read on an excluded number: %v", err)
	}
	// The way out: recover it, share its key, then remove the person.
	w.recover(t, device)
	w.reads(t, w.owner, device)
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, target); err != nil {
		t.Fatalf("after sharing the key: %v", err)
	}
}

// requireRemainingReader never joins devices: an excluded number keeps
// protecting its last key holder until its row is purged.
func TestRequireRemainingReaderCoversDeleted(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	target := w.person(t, "target", "member")
	live, excluded := w.number(t, "l"), w.number(t, "x")
	w.reads(t, target, live)
	w.reads(t, target, excluded)
	w.quarantine(t, excluded, target)
	for _, device := range []uuid.UUID{live, excluded} {
		if err := w.keys.RevokeGrant(ctx, w.tenant, device, target); !errors.Is(err, store.ErrLastDeviceReader) {
			t.Fatalf("%s: %v", device, err)
		}
	}
	// Purged: the row and its grants go, and nothing is left to protect.
	w.scoped(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM devices WHERE id=$1`, excluded)
		return err
	})
	if err := w.keys.RevokeGrant(ctx, w.tenant, excluded, target); err != nil {
		t.Fatalf("after the purge: %v", err)
	}
}

func TestRecordUnlinkAndRecoverStatus(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	sessionStore(t, w.pool)
	session := func(device uuid.UUID, reg int64) string {
		t.Helper()
		jid := w.pn(ctx, t, device)
		if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_device(jid,registration_id) VALUES ($1,$2)`, jid, reg); err != nil {
			t.Fatal(err)
		}
		if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_privacy_tokens(our_jid,their_jid,token,timestamp) VALUES ($1,'x',''::bytea,1)`, jid); err != nil {
			t.Fatal(err)
		}
		return jid
	}
	tokens := func(jid string) int {
		var n int
		if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM whatsmeow_privacy_tokens WHERE our_jid=$1`, jid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	bystander := session(w.number(t, "bystander"), 9)

	// The logout acknowledged, and the session gone with it.
	acked := w.number(t, "acked")
	jid := session(acked, 1)
	q := w.quarantine(t, acked)
	if q.Session == nil || q.Session.JID != jid || q.Session.RegistrationID != 1 {
		t.Fatalf("the fingerprint = %+v", q.Session)
	}
	if _, err := w.pool.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid=$1`, jid); err != nil {
		t.Fatal(err)
	}
	rec, err := w.devices.RecordUnlink(ctx, w.tenant, acked, q.DeletedAt, true)
	if err != nil || !rec.Unlinked || rec.NoteCode != "" || tokens(jid) != 0 {
		t.Fatalf("acknowledged: %+v %v, %d tokens", rec, err, tokens(jid))
	}

	// The session left: the fingerprint stays, with an attempt.
	left := w.number(t, "left")
	session(left, 2)
	q2 := w.quarantine(t, left)
	rec, err = w.devices.RecordUnlink(ctx, w.tenant, left, q2.DeletedAt, false)
	if err != nil || rec.Unlinked || rec.NoteCode != store.NoteUnlinkUnconfirmed {
		t.Fatalf("unconfirmed: %+v %v", rec, err)
	}
	if n := w.count(t, `SELECT count(*) FROM devices WHERE id=$1 AND (wa_leftover->>'attempts')::int=1 AND status='offline'`, left); n != 1 {
		t.Fatal("the unconfirmed logout did not keep its fingerprint")
	}
	leftovers, err := w.devices.LeftoverSessions(ctx, w.tenant)
	if err != nil || len(leftovers) != 1 || leftovers[0].DeviceID != left || !leftovers[0].Present || leftovers[0].Attempts != 1 {
		t.Fatalf("leftovers %+v %v", leftovers, err)
	}

	// No session at the deletion.
	none := w.number(t, "none")
	q3 := w.quarantine(t, none)
	rec, err = w.devices.RecordUnlink(ctx, w.tenant, none, q3.DeletedAt, false)
	if err != nil || !rec.Unlinked || rec.NoteCode != store.NoteAlreadyDisconnected {
		t.Fatalf("no session: %+v %v", rec, err)
	}
	if tokens(bystander) != 1 {
		t.Fatal("another session's privacy tokens went")
	}
	// Another deleted_at changes nothing.
	if _, err := w.devices.RecordUnlink(ctx, w.tenant, left, q2.DeletedAt.Add(time.Second), true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another deletion: %v", err)
	}
	// A second record of one deletion (the janitor's, racing the handler's)
	// changes nothing, whatever it says: a confirmed logout stays confirmed.
	for _, acknowledged := range []bool{true, false} {
		rec, err = w.devices.RecordUnlink(ctx, w.tenant, acked, q.DeletedAt, acknowledged)
		if err != nil || !rec.Unlinked || rec.NoteCode != "" {
			t.Fatalf("a second record (%v): %+v %v", acknowledged, rec, err)
		}
	}
	if n := w.count(t, `SELECT count(*) FROM devices WHERE id=$1 AND status_reason='unlinked when deleted' AND status='logged_out'`, acked); n != 1 {
		t.Fatal("a second record rewrote a confirmed logout")
	}
	// Acknowledged, yet the fingerprinted session is still in the store: not
	// a logout.
	stays := w.number(t, "stays")
	staysJID := session(stays, 4)
	q6 := w.quarantine(t, stays)
	rec, err = w.devices.RecordUnlink(ctx, w.tenant, stays, q6.DeletedAt, true)
	if err != nil || rec.Unlinked || rec.NoteCode != store.NoteUnlinkUnconfirmed {
		t.Fatalf("acknowledged with the session left: %+v %v", rec, err)
	}
	if n := w.count(t, `SELECT count(*) FROM devices WHERE id=$1 AND (wa_leftover->>'attempts')::int=1 AND status='offline' AND status_reason='deleted'`, stays); n != 1 || tokens(staysJID) != 1 {
		t.Fatalf("a false acknowledgement was taken for a logout (%d rows, %d tokens)", n, tokens(staysJID))
	}
	// The logout went through, and an owner recovered the number before its
	// record landed: the recovery, holding the device lock, records it, so
	// the number never comes back offering a resume WhatsApp already ended.
	lost := w.number(t, "lost")
	lostJID := session(lost, 5)
	w.quarantine(t, lost)
	if _, err := w.pool.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid=$1`, lostJID); err != nil {
		t.Fatal(err)
	}
	if r := w.recover(t, lost); r.Status != wa.StatusLoggedOut || r.StatusReason != "unlinked when deleted" || r.CanResume || tokens(lostJID) != 0 {
		t.Fatalf("recovered before the record: %+v, %d tokens", r.RecoveryState, tokens(lostJID))
	}

	for device, want := range map[uuid.UUID]struct {
		status    wa.Status
		reason    string
		resume    bool
		loggedOut bool
	}{
		acked: {wa.StatusLoggedOut, "unlinked when deleted", false, true},
		left:  {wa.StatusOffline, "deleted", true, false},
		stays: {wa.StatusOffline, "deleted", true, false},
		none:  {wa.StatusLoggedOut, "no session at deletion", false, true},
	} {
		r := w.recover(t, device)
		if r.Status != want.status || r.StatusReason != want.reason || r.CanResume != want.resume || r.LoggedOut != want.loggedOut {
			t.Fatalf("%s after the recovery: %+v, want %+v", device, r.RecoveryState, want)
		}
	}

	// Dead numbers stay dead, banned on every branch.
	for _, status := range []wa.Status{wa.StatusLoggedOut, wa.StatusBanned} {
		dead := w.number(t, string(status))
		if err := w.devices.SetStatus(ctx, w.tenant.String(), dead.String(), status, "by WhatsApp"); err != nil {
			t.Fatal(err)
		}
		q := w.quarantine(t, dead)
		rec, err := w.devices.RecordUnlink(ctx, w.tenant, dead, q.DeletedAt, true)
		if err != nil || !rec.Unlinked || rec.NoteCode != store.NoteAlreadyDisconnected {
			t.Fatalf("%s with no session: %+v %v", status, rec, err)
		}
		if r := w.recover(t, dead); r.Status != status || r.CanResume {
			t.Fatalf("%s after the recovery: %+v", status, r)
		}
	}
	banned := w.number(t, "banned-acked")
	bannedJID := session(banned, 3)
	if err := w.devices.SetStatus(ctx, w.tenant.String(), banned.String(), wa.StatusBanned, "temporary"); err != nil {
		t.Fatal(err)
	}
	q4 := w.quarantine(t, banned)
	if _, err := w.pool.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid=$1`, bannedJID); err != nil {
		t.Fatal(err)
	}
	if rec, err := w.devices.RecordUnlink(ctx, w.tenant, banned, q4.DeletedAt, true); err != nil || !rec.Unlinked || rec.NoteCode != "" {
		t.Fatalf("a banned number's acknowledged logout: %+v %v", rec, err)
	}
	if n := w.count(t, `SELECT count(*) FROM devices WHERE id=$1 AND status='banned'`, banned); n != 1 {
		t.Fatal("a banned number is no longer banned")
	}

	// A number with only a LID has no session a deletion can find, even
	// with a session stored under its LID: a deletion looks a session up by
	// the phone number alone, and never logs out by LID.
	lidOnly, err := w.devices.Create(ctx, w.tenant.String(), "lid", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	lid := types.NewJID("300000000000001", types.HiddenUserServer)
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), lidOnly.ID, wa.Identity{LID: lid}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_device(jid,registration_id) VALUES ($1,6)`, lid.String()); err != nil {
		t.Fatal(err)
	}
	q5 := w.quarantine(t, uuid.MustParse(lidOnly.ID))
	if q5.Session != nil {
		t.Fatalf("a LID-only number has a session to log out: %+v", q5.Session)
	}
	rec, err = w.devices.RecordUnlink(ctx, w.tenant, uuid.MustParse(lidOnly.ID), q5.DeletedAt, false)
	if err != nil || !rec.Unlinked || rec.NoteCode != store.NoteAlreadyDisconnected {
		t.Fatalf("a LID-only number's record: %+v %v", rec, err)
	}
	if n := w.count(t, `SELECT count(*) FROM devices WHERE id=$1 AND status='logged_out' AND status_reason='no session at deletion' AND wa_leftover IS NULL`, lidOnly.ID); n != 1 {
		t.Fatal("a LID-only number was not left logged out with no session")
	}
}

// The recovery's preflight lists everyone who gets something back: the
// readers, the standing service accounts that read it, and, apart, whoever
// only sends through it or, as a member, manages it. An owner's or an
// admin's stored Manage adds nothing to their role and is not listed.
func TestRecoverCheckListsOthers(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Suporte")
	reader := w.person(t, "reader", "member")
	w.reads(t, reader, device)
	sender := w.person(t, "sender", "member")
	manager := w.person(t, "manager", "member")
	admin := w.person(t, "admin", "admin")
	service, err := w.users.CreateService(ctx, w.tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []store.DevicePermission{
		{DeviceID: device, UserID: sender, Send: true},
		{DeviceID: device, UserID: manager, Manage: true},
		{DeviceID: device, UserID: admin, Manage: true},
		{DeviceID: device, UserID: service.ID, Send: true},
		{DeviceID: device, UserID: reader, Read: true, Send: true},
	} {
		if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, p); err != nil {
			t.Fatal(err)
		}
	}
	// SetDevicePermission with Read keeps the reader's grant.
	w.quarantine(t, device, reader)
	check, err := w.devices.RecoverCheck(ctx, w.tenant, w.owner, device)
	if err != nil {
		t.Fatal(err)
	}
	if len(check.Readers) != 1 || check.Readers[0].UserID != reader {
		t.Fatalf("readers = %+v", check.Readers)
	}
	type entry struct {
		kind string
		why  string
	}
	got := map[uuid.UUID]entry{}
	for _, o := range check.Others {
		got[o.ID] = entry{o.Kind, strings.Join(o.Why, ",")}
		if o.Kind == "service" && (o.Name == "" || o.Email != "") || o.Kind == "person" && o.Email == "" {
			t.Fatalf("an entry %+v", o)
		}
	}
	want := map[uuid.UUID]entry{sender: {"person", "send"}, manager: {"person", "manage"}, service.ID: {"service", "send"}}
	if len(got) != len(want) {
		t.Fatalf("others = %+v", check.Others)
	}
	for id, e := range want {
		if got[id] != e {
			t.Fatalf("others = %+v, want %v for %s", check.Others, e, id)
		}
	}
}

// Disabling a person revokes the keys they created, as removing one does:
// a key verifies by itself, and one acting as nobody reads every number.
func TestDisableRevokesCreatedKeys(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	admin := w.person(t, "admin", "admin")
	service, err := w.users.CreateService(ctx, w.tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	created, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "made by the admin", store.ScopeRead, &admin, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	actsAs, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "acting as the service", store.ScopeRead, &w.owner, &service.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "the owner's", store.ScopeRead, &w.owner, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, admin, "admin", "disabled"); err != nil {
		t.Fatal(err)
	}
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, service.ID, store.RoleService, "disabled"); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]bool{created: false, actsAs: false, other: true} {
		if _, err := w.apiKeys.VerifyScoped(ctx, key); (err == nil) != want {
			t.Fatalf("key %s works = %v, want %v", key[:16], err == nil, want)
		}
	}
}

// Notices: a deletion leaves one for each reader and each other owner,
// shown in devices.list until it is seen, per person and per notice.
func TestDeletionNotices(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Suporte")
	reader := w.person(t, "reader", "member")
	coOwner := w.person(t, "co", "owner")
	readingOwner := w.person(t, "reading", "owner")
	for _, u := range []uuid.UUID{w.owner, reader, readingOwner} {
		w.reads(t, u, device)
	}
	q := w.quarantine(t, device, reader, readingOwner)
	for _, u := range []uuid.UUID{reader, coOwner, readingOwner} {
		notices, err := w.devices.Notices(ctx, w.tenant, u)
		if err != nil || len(notices) != 1 {
			t.Fatalf("%s: %+v %v", u, notices, err)
		}
		n := notices[0]
		if n.Kind != store.NoticeNumberDeleted || n.Until == nil || !n.Until.Equal(q.PurgeAfter) || n.RaisedByKind != "person" ||
			n.RaisedByName == nil || n.Hint == nil || *n.Hint != "…5678" || n.Label == nil || *n.Label != "Suporte" {
			t.Fatalf("%s's notice %+v", u, n)
		}
	}
	if mine, err := w.devices.Notices(ctx, w.tenant, w.owner); err != nil || len(mine) != 0 {
		t.Fatalf("the owner who deleted is told: %+v %v", mine, err)
	}
	notices, err := w.devices.Notices(ctx, w.tenant, reader)
	if err != nil {
		t.Fatal(err)
	}
	// Someone else's id changes nothing.
	if left, err := w.devices.SeeNotices(ctx, w.tenant, coOwner, []store.SeenNotice{{ID: notices[0].ID}}); err != nil || len(left) != 1 {
		t.Fatalf("another person's seen mark: %+v %v", left, err)
	}
	if left, err := w.devices.SeeNotices(ctx, w.tenant, reader, []store.SeenNotice{{ID: notices[0].ID}}); err != nil || len(left) != 0 {
		t.Fatalf("seen: %+v %v", left, err)
	}
	w.recover(t, device)
	if left, err := w.devices.Notices(ctx, w.tenant, coOwner); err != nil || len(left) != 0 {
		t.Fatalf("a recovery leaves the owners' notice: %+v %v", left, err)
	}
}

// 0050 comes down after a real deletion and recovery, once the events are
// in the ledger.
func TestDownStepAfterDeletionAndRecovery(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Suporte")
	w.quarantine(t, device)
	if _, err := w.pool.Exec(ctx, downStep(t, 50)); err == nil || !strings.Contains(err.Error(), "excluded numbers exist") {
		t.Fatalf("the down-step with an excluded number: %v", err)
	}
	w.recover(t, device)
	if _, err := w.pool.Exec(ctx, downStep(t, 50)); err == nil || !strings.Contains(err.Error(), "not in the ledger yet") {
		t.Fatalf("the down-step with unledgered events: %v", err)
	}
	w.scoped(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE item_events SET ledgered_at=clock_timestamp()`)
		return err
	})
	if _, err := w.pool.Exec(ctx, downStep(t, 50)); err != nil {
		t.Fatalf("the down-step: %v", err)
	}
	var version int
	if err := w.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 49 {
		t.Fatalf("version %d: %v", version, err)
	}
}
