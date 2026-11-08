package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/ledger"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// devices.logout_cause (0052, DS6): every writer of logged_out, through its
// own store call, leaves the cause a numbers row shows. whatsmeow deletes a
// session when the phone logs the number out, so a later deletion finds
// none: the tests take that real order, the logout, the session row gone,
// then the deletion.

// logoutCause is the number's logout_cause and status, read with the scope
// on: "" for none.
func (w *delWorld) logoutCause(t *testing.T, device uuid.UUID) (cause, status, reason string) {
	t.Helper()
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT coalesce(logout_cause, ''), status, status_reason FROM devices WHERE id = $1`, device).
			Scan(&cause, &status, &reason)
	})
	return cause, status, reason
}

// withSession stores the number's whatsmeow session, as pairing leaves it.
func (w *delWorld) withSession(ctx context.Context, t *testing.T, device uuid.UUID) string {
	t.Helper()
	jid := w.pn(ctx, t, device)
	if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_device (jid, registration_id) VALUES ($1, 7)`, jid); err != nil {
		t.Fatal(err)
	}
	return jid
}

// phoneLogout is the phone's logout as the session sees it: the status,
// then whatsmeow's own delete of the session row.
func (w *delWorld) phoneLogout(ctx context.Context, t *testing.T, device uuid.UUID, jid string) {
	t.Helper()
	if err := w.devices.SetStatus(ctx, w.tenant.String(), device.String(), wa.StatusLoggedOut, "unlinked (logged out from the phone)"); err != nil {
		t.Fatal(err)
	}
	if jid != "" {
		if _, err := w.pool.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid = $1`, jid); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLogoutCauseEveryWriter(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	sessionStore(t, w.pool)
	check := func(name string, device uuid.UUID, want string) {
		t.Helper()
		if got, status, reason := w.logoutCause(t, device); got != want {
			t.Errorf("%s: cause %q (%s, %q), want %q", name, got, status, reason, want)
		}
	}
	status := func(device uuid.UUID, s wa.Status, reason string) {
		t.Helper()
		if err := w.devices.SetStatus(ctx, w.tenant.String(), device.String(), s, reason); err != nil {
			t.Fatal(err)
		}
	}

	// The phone's logout, and a missing session at start or at a
	// supervisor's or a person's start: the relink answers both.
	phone := w.number(t, "phone")
	jid := w.withSession(ctx, t, phone)
	w.phoneLogout(ctx, t, phone, jid)
	check("the phone's logout", phone, "phone")
	for _, reason := range []string{"session missing at startup", "session missing"} {
		n := w.number(t, reason)
		status(n, wa.StatusLoggedOut, reason)
		check(reason, n, "phone")
	}

	// A deletion of a number with no session that was not logged out.
	none := w.number(t, "none")
	q := w.quarantine(t, none)
	check("a deletion with no session", none, "deletion")
	if _, err := w.devices.RecordUnlink(ctx, w.tenant, none, q.DeletedAt, false); err != nil {
		t.Fatal(err)
	}
	check("its record", none, "deletion")

	// A phone's logout, then a deletion: no session left, so the deletion
	// writes "no session at deletion", and the number stays the phone's,
	// through its record and its recovery.
	q = w.quarantine(t, phone)
	if _, s, r := w.logoutCause(t, phone); s != "logged_out" || r != "no session at deletion" {
		t.Fatalf("the deletion of a number the phone logged out: %s %q", s, r)
	}
	check("a deletion after the phone's logout", phone, "phone")
	if _, err := w.devices.RecordUnlink(ctx, w.tenant, phone, q.DeletedAt, true); err != nil {
		t.Fatal(err)
	}
	check("its record", phone, "phone")
	w.recover(t, phone)
	check("its recovery", phone, "phone")

	// The phone's logout with the session row still there: the deletion
	// keeps the reason, and its confirmed logout keeps the cause.
	kept := w.number(t, "kept")
	keptJID := w.withSession(ctx, t, kept)
	w.phoneLogout(ctx, t, kept, "")
	q = w.quarantine(t, kept)
	check("a deletion that found the session of a logged-out number", kept, "phone")
	if _, err := w.pool.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid = $1`, keptJID); err != nil {
		t.Fatal(err)
	}
	if rec, err := w.devices.RecordUnlink(ctx, w.tenant, kept, q.DeletedAt, true); err != nil || !rec.Unlinked {
		t.Fatalf("the record: %+v %v", rec, err)
	}
	if _, s, r := w.logoutCause(t, kept); s != "logged_out" || r != "unlinked when deleted" {
		t.Fatalf("the confirmed logout of a logged-out number: %s %q", s, r)
	}
	check("the confirmed logout of a logged-out number", kept, "phone")

	// The deletion's own confirmed logout.
	unlinked := w.number(t, "unlinked")
	unlinkedJID := w.withSession(ctx, t, unlinked)
	q = w.quarantine(t, unlinked)
	check("a deletion that found a session", unlinked, "")
	if _, err := w.pool.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid = $1`, unlinkedJID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.RecordUnlink(ctx, w.tenant, unlinked, q.DeletedAt, true); err != nil {
		t.Fatal(err)
	}
	check("the deletion's confirmed logout", unlinked, "deletion")

	// A recovery that finds the session gone records the logout; one that
	// finds it live keeps the number out of logged_out.
	gone := w.number(t, "gone")
	goneJID := w.withSession(ctx, t, gone)
	w.quarantine(t, gone)
	if _, err := w.pool.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid = $1`, goneJID); err != nil {
		t.Fatal(err)
	}
	w.recover(t, gone)
	check("a recovery of a session that went", gone, "deletion")
	live := w.number(t, "live")
	w.withSession(ctx, t, live)
	w.quarantine(t, live)
	w.recover(t, live)
	check("a recovery of a live session", live, "")

	// The replay of a deletion keeps a logged-out number's status, and puts
	// any other offline.
	replayedPhone, replayedLive := w.number(t, "replayed phone"), w.number(t, "replayed live")
	w.phoneLogout(ctx, t, replayedPhone, "")
	deletedAt, purgeAfter := w.window(t, "-1 hour")
	if _, err := w.replay(t, []ledger.Line{
		w.line(ledger.TypeDeleted, replayedPhone, &deletedAt, &purgeAfter, deletedAt),
		w.line(ledger.TypeDeleted, replayedLive, &deletedAt, &purgeAfter, deletedAt),
	}, store.ReplayOptions{}); err != nil {
		t.Fatalf("the replay: %v", err)
	}
	check("a replayed deletion of a logged-out number", replayedPhone, "phone")
	check("a replayed deletion of a live number", replayedLive, "")

	// The relink's attach leaves the number offline, linked again.
	relinked, id := w.loggedOutNumber(t, "relinked", "155501000777", "100000000000777")
	check("a phone's logout before a relink", relinked, "phone")
	linked := newLink(id)
	w.putSession(t, linked.PN.String())
	if _, err := w.devices.AttachRelink(ctx, w.tenant, relinked, w.seen(t, relinked), linked); err != nil {
		t.Fatal(err)
	}
	check("the relink's attach", relinked, "")

	// Banned is never logged out, deleted or not.
	banned := w.number(t, "banned")
	status(banned, wa.StatusBanned, "temporary")
	check("banned", banned, "")
	w.quarantine(t, banned)
	check("a banned number deleted", banned, "")

	// Back online after a logout: no cause.
	status(phone, wa.StatusOnline, "")
	check("online again", phone, "")
}
