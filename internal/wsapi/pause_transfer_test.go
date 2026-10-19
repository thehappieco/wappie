package wsapi_test

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// Over the socket: a stop tells the number's readers (decision 0039), the
// workspace's other owners are told of a deletion, and a move to Personal is
// refused while anyone else has access (decision 0040), never leaving the
// number's sync off after a move that did not happen.

// TestDeviceStopTellsReaders is the plan's test 14, socket half: a person's
// stop pushes each other reader their notice and logs who paused; a key's
// stop logs the key; the actor is told nothing.
func TestDeviceStopTellsReaders(t *testing.T) {
	logged := &lockedBuffer{}
	c := newDeletionConsoleWith(t, deletionOptions{log: slog.New(slog.NewTextHandler(logged, nil))})
	device := c.linkedDevice(t, "Vendas")
	reader, readerToken := c.person(t, "ana", "member")
	away, awayToken := c.person(t, "bia", "member")
	c.reads(t, c.owner, device)
	c.reads(t, reader, device)
	c.reads(t, away, device)
	readerConn := connect(t, c.console, wsapi.Hello{Session: readerToken})
	readerFrames := drain(readerConn)
	ownerConn := connect(t, c.console, wsapi.Hello{Session: c.token})
	ownerFrames := drain(ownerConn)

	request(t, ownerConn, "stop", wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: device.String()})
	for f := next(t, ownerFrames, wsapi.TypeDeviceStatus); f.ReqID != "stop"; f = next(t, ownerFrames, wsapi.TypeDeviceStatus) {
		// The broadcast of the new status comes first.
	}
	pushed := payload[wsapi.DeviceNotice](t, next(t, readerFrames, wsapi.TypeDeviceNotice))
	if pushed.Kind != store.NoticeSyncPaused || pushed.DeviceID != device.String() || pushed.Label == nil || *pushed.Label != "Vendas" ||
		pushed.RaisedByKind != "person" || pushed.RaisedByName == nil || pushed.Pauses != 1 {
		t.Fatalf("the reader's push: %+v", pushed)
	}
	list := payload[wsapi.Devices](t, ask(t, c.console, wsapi.Hello{Session: awayToken}, wsapi.TypeDevicesList, nil))
	if len(list.Notices) != 1 || list.Notices[0].ID == pushed.ID || list.Notices[0].Kind != store.NoticeSyncPaused {
		t.Fatalf("the absent reader's notices: %+v", list.Notices)
	}
	if own := payload[wsapi.Devices](t, ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDevicesList, nil)); len(own.Notices) != 0 {
		t.Fatalf("the actor was told: %+v", own.Notices)
	}
	if !strings.Contains(logged.String(), `msg="sync paused"`) || !strings.Contains(logged.String(), "actor_kind=person actor="+c.owner.String()) {
		t.Fatalf("the stop's log: %s", logged.String())
	}

	// An API key's stop: logged with the key, and its readers told.
	if err := c.devices.SetPaused(context.Background(), c.tenant.String(), device.String(), false); err != nil {
		t.Fatal(err)
	}
	key, err := c.keys.VerifyScoped(context.Background(), c.apiKey)
	if err != nil {
		t.Fatal(err)
	}
	if f := ask(t, c.console, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: device.String()}); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("the key's stop: %s %s", f.Type, f.Payload)
	}
	if !strings.Contains(logged.String(), "actor_kind=key actor="+key.ID.String()) {
		t.Fatalf("the key's stop was not logged with the key: %s", logged.String())
	}
	folded := payload[wsapi.DeviceNotice](t, next(t, readerFrames, wsapi.TypeDeviceNotice))
	if folded.ID != pushed.ID || folded.Pauses != 2 || folded.RaisedByKind != "key" || !folded.SeveralActors {
		t.Fatalf("the reader's folded push: %+v", folded)
	}

	// The reader acknowledges what they were shown: the first version, or a
	// bare id, leaves the folded notice unseen and returns it.
	readerHello := wsapi.Hello{Session: readerToken}
	for _, stale := range []wsapi.DeviceNoticeSeen{
		{Notices: []wsapi.SeenNotice{{ID: pushed.ID, Pauses: pushed.Pauses}}},
		{NoticeIDs: []int64{pushed.ID}},
	} {
		left := payload[wsapi.DeviceNotices](t, ask(t, c.console, readerHello, wsapi.TypeDeviceNoticeSeen, stale))
		if len(left.Notices) != 1 || left.Notices[0].Pauses != 2 {
			t.Fatalf("acknowledging %+v: %+v", stale, left)
		}
	}
	seen := wsapi.DeviceNoticeSeen{Notices: []wsapi.SeenNotice{{ID: folded.ID, Pauses: folded.Pauses}}}
	if left := payload[wsapi.DeviceNotices](t, ask(t, c.console, readerHello, wsapi.TypeDeviceNoticeSeen, seen)); len(left.Notices) != 0 {
		t.Fatalf("acknowledging the folded version: %+v", left)
	}
}

// TestResumeOverTheSocket is the plan's test 14, resume half, over the
// socket: a start that runs marks the readers' pause notice resumed,
// keeping its pauses; a start that fails pauses the number again on its
// own (section 5's failed resume), which tells nobody, records nothing and
// leaves the notice as it was.
func TestResumeOverTheSocket(t *testing.T) {
	c := newDeletionConsoleWith(t, deletionOptions{registry: true})
	ctx := context.Background()
	device := c.linkedDevice(t, "Vendas")
	reader, readerToken := c.person(t, "ana", "member")
	c.reads(t, c.owner, device)
	c.reads(t, reader, device)
	owner := wsapi.Hello{Session: c.token}
	ref := wsapi.DeviceRef{DeviceID: device.String()}
	notice := func() wsapi.DeviceNotice {
		t.Helper()
		list := payload[wsapi.Devices](t, ask(t, c.console, wsapi.Hello{Session: readerToken}, wsapi.TypeDevicesList, nil))
		if len(list.Notices) != 1 {
			t.Fatalf("the reader's notices: %+v", list.Notices)
		}
		return list.Notices[0]
	}
	recorded := func() (events, notices int) {
		t.Helper()
		c.scoped(ctx, t, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM item_events WHERE item_id=$1 AND type='sync_paused'),
				(SELECT count(*) FROM device_notices WHERE device_id=$1)`, device).Scan(&events, &notices)
		})
		return events, notices
	}
	step := func(name, frame, want string) {
		t.Helper()
		if f := ask(t, c.console, owner, frame, ref); f.Type != want {
			t.Fatalf("%s: %s %s", name, f.Type, f.Payload)
		}
	}

	step("the stop", wsapi.TypeDeviceStop, wsapi.TypeDeviceStatus)
	step("the start", wsapi.TypeDeviceStart, wsapi.TypeDeviceStatus)
	if n := notice(); n.ResumedAt == nil || n.Pauses != 1 || c.paused(t, c.tenant, device) {
		t.Fatalf("after the start: %+v, paused %v", n, c.paused(t, c.tenant, device))
	}
	step("the second stop", wsapi.TypeDeviceStop, wsapi.TypeDeviceStatus)
	open := notice()
	if open.ResumedAt != nil || open.Pauses != 2 {
		t.Fatalf("after the second stop: %+v", open)
	}
	events, notices := recorded()

	// The session is gone from the store: the start fails, and the handler
	// pauses the number again.
	if _, err := c.pool.Exec(ctx, `DELETE FROM whatsmeow_device`); err != nil {
		t.Fatal(err)
	}
	wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceStart, ref), wsapi.ErrCodeConflict)
	if !c.paused(t, c.tenant, device) {
		t.Fatal("a failed start left the number unpaused")
	}
	if n := notice(); n.ID != open.ID || n.Pauses != 2 || n.ResumedAt != nil || n.SeveralActors {
		t.Fatalf("the failed start changed the notice: %+v", n)
	}
	if e, n := recorded(); e != events || n != notices {
		t.Fatalf("the failed start's pause: %d sync_paused rows (was %d), %d notices (was %d)", e, events, n, notices)
	}
}

// A start that fails puts back the pause it took away with its cause
// (release B's plan, TB12): a person's stays a person's, and a move's stays
// the move's, which a snapshot reports as Wappie's own, never as a person's.
func TestFailedResumeKeepsItsPauseCause(t *testing.T) {
	c := newDeletionConsoleWith(t, deletionOptions{registry: true})
	ctx := context.Background()
	device := c.linkedDevice(t, "Vendas")
	ref := wsapi.DeviceRef{DeviceID: device.String()}
	owner := wsapi.Hello{Session: c.token}
	// The session is gone from the store: every start fails.
	if _, err := c.pool.Exec(ctx, `DELETE FROM whatsmeow_device`); err != nil {
		t.Fatal(err)
	}
	cause := func() string {
		t.Helper()
		d, err := c.devices.Get(ctx, c.tenant.String(), device.String())
		if err != nil || !d.Paused {
			t.Fatalf("after the failed start: paused %v, %v", d.Paused, err)
		}
		return d.PauseCause
	}
	for _, pause := range []struct {
		name string
		do   func() error
		want string
	}{
		{"a person's stop", func() error {
			if f := ask(t, c.console, owner, wsapi.TypeDeviceStop, ref); f.Type != wsapi.TypeDeviceStatus {
				return errors.New(f.Type + " " + string(f.Payload))
			}
			return nil
		}, store.PauseByPerson},
		{"a move's pause", func() error {
			_, err := c.devices.PauseForMove(ctx, c.tenant, device)
			return err
		}, store.PauseForMove},
	} {
		// Live and offline again, as before each start.
		if err := c.devices.SetPaused(ctx, c.tenant.String(), device.String(), false); err != nil {
			t.Fatal(err)
		}
		if err := c.devices.SetStatus(ctx, c.tenant.String(), device.String(), wa.StatusOffline, ""); err != nil {
			t.Fatal(err)
		}
		if err := pause.do(); err != nil {
			t.Fatalf("%s: %v", pause.name, err)
		}
		wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceStart, ref), wsapi.ErrCodeConflict)
		if got := cause(); got != pause.want {
			t.Fatalf("a failed start after %s: pause_cause %q, want %q", pause.name, got, pause.want)
		}
	}
}

// TestOwnersToldOfDeletionOverTheSocket is the plan's test 66, socket
// half: another owner who does not read the number finds the deletion in
// their devices.list; the owner who deleted does not.
func TestOwnersToldOfDeletionOverTheSocket(t *testing.T) {
	c := newDeletionConsole(t)
	device := c.linkedDevice(t, "Caixa")
	c.reads(t, c.owner, device)
	_, otherToken := c.person(t, "bia", "owner")
	gone := payload[wsapi.DeviceDeleted](t, ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceDelete, deleteFrame(device)))
	list := payload[wsapi.Devices](t, ask(t, c.console, wsapi.Hello{Session: otherToken}, wsapi.TypeDevicesList, nil))
	if len(list.Notices) != 1 {
		t.Fatalf("the other owner's notices: %+v", list.Notices)
	}
	n := list.Notices[0]
	if n.Kind != store.NoticeNumberDeleted || n.RaisedByName == nil || !strings.HasPrefix(*n.RaisedByName, "owner") || n.Label == nil ||
		*n.Label != "Caixa" || n.Hint == nil || *n.Hint != "…5678" || n.Until == nil || gone.RecoverableUntil == nil || !n.Until.Equal(*gone.RecoverableUntil) {
		t.Fatalf("the other owner's notice: %+v", n)
	}
	if own := payload[wsapi.Devices](t, ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDevicesList, nil)); len(own.Notices) != 0 {
		t.Fatalf("the deleting owner was told: %+v", own.Notices)
	}
}

// personalOf is the id of the owner's Personal.
func (c *deletionConsole) personalOf(t *testing.T, user uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := c.pool.QueryRow(context.Background(), `SELECT id FROM tenants WHERE personal_owner_id=$1`, user).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (c *deletionConsole) paused(t *testing.T, tenant, device uuid.UUID) bool {
	t.Helper()
	d, err := c.devices.Get(context.Background(), tenant.String(), device.String())
	if err != nil {
		t.Fatalf("reading %s in %s: %v", device, tenant, err)
	}
	return d.Paused
}

func transferFrame(device, target uuid.UUID) wsapi.DeviceTransferRequest {
	return wsapi.DeviceTransferRequest{DeviceID: device.String(), Confirm: device.String(), TargetWorkspaceID: target.String()}
}

// TestTransferRefusedOverTheSocket is the plan's test 63, socket half: the
// preview names who still has access; the move answers others_have_access
// with the list before pausing anything; an admin's preview carries no
// list; a member's frame is refused.
func TestTransferRefusedOverTheSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deletion-ledger.jsonl")
	c := newDeletionConsoleWith(t, deletionOptions{ledger: path})
	device := c.linkedDevice(t, "Vendas")
	c.reads(t, c.owner, device)
	personal := c.personalOf(t, c.owner)
	owner := wsapi.Hello{Session: c.token}
	if p := payload[store.PersonalTransferPreview](t, ask(t, c.console, owner, wsapi.TypeDeviceTransferPreview, wsapi.DeviceRef{DeviceID: device.String()})); !p.Eligible {
		t.Fatalf("the positive control: %+v", p)
	}
	sender, _ := c.person(t, "ana", "member")
	if err := c.users.SetDevicePermission(context.Background(), c.tenant, c.owner, store.DevicePermission{DeviceID: device, UserID: sender, Send: true}); err != nil {
		t.Fatal(err)
	}
	p := payload[store.PersonalTransferPreview](t, ask(t, c.console, owner, wsapi.TypeDeviceTransferPreview, wsapi.DeviceRef{DeviceID: device.String()}))
	if p.Eligible || p.ReasonCode != store.ReasonOthersHaveAccess || len(p.Others) != 1 || p.Others[0].Kind != "person" ||
		p.Others[0].UserID == nil || *p.Others[0].UserID != sender || len(p.Others[0].Why) != 1 || p.Others[0].Why[0] != "send" ||
		p.Others[0].Status != "active" || p.Others[0].Email != "ana@acme.test" {
		t.Fatalf("the preview: %+v", p)
	}
	e := wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceTransfer, transferFrame(device, personal)), wsapi.ErrCodeOthersHaveAccess)
	if len(e.Others) != 1 || e.Others[0].UserID == nil || *e.Others[0].UserID != sender || e.Message == "" {
		t.Fatalf("the refusal: %+v", e)
	}
	if c.paused(t, c.tenant, device) {
		t.Fatal("a refused move paused the number")
	}

	_, adminToken := c.person(t, "adm", "admin")
	f := ask(t, c.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceTransferPreview, wsapi.DeviceRef{DeviceID: device.String()})
	if strings.Contains(string(f.Payload), `"others"`) || payload[store.PersonalTransferPreview](t, f).Eligible {
		t.Fatalf("an admin's preview: %s", f.Payload)
	}
	_, memberToken := c.person(t, "mem", "member")
	wantError(t, ask(t, c.console, wsapi.Hello{Session: memberToken}, wsapi.TypeDeviceTransferPreview, wsapi.DeviceRef{DeviceID: device.String()}), wsapi.ErrCodeNotAuthorized)

	// The way out: every flag off, then the move, which tells the other
	// sessions that saw the number that it is gone.
	if err := c.users.SetDevicePermission(context.Background(), c.tenant, c.owner, store.DevicePermission{DeviceID: device, UserID: sender}); err != nil {
		t.Fatal(err)
	}
	adminConn := connect(t, c.console, wsapi.Hello{Session: adminToken})
	adminFrames := drain(adminConn)
	moved := ask(t, c.console, owner, wsapi.TypeDeviceTransfer, transferFrame(device, personal))
	if moved.Type != wsapi.TypeDeviceTransferred {
		t.Fatalf("the move: %s %s", moved.Type, moved.Payload)
	}
	if r := payload[wsapi.DeviceRemoved](t, next(t, adminFrames, wsapi.TypeDeviceRemoved)); r.DeviceID != device.String() || r.Reason != wsapi.DeviceRemovedMoved {
		t.Fatalf("the admin's push: %+v", r)
	}
	// The move is in the ledger as soon as its reply arrives.
	if got := ledgerTypes(t, path); !slices.Equal(got, []string{"moved_out"}) {
		t.Fatalf("the ledger after the move: %v", got)
	}
}

// TestTransferUndoesItsPause is the plan's test 64, the handler's half:
// after any error from the move, a number the handler paused is unpaused, a
// number already paused stays so, and so does one someone stopped while the
// move ran; a move that committed and lost its answer leaves the number
// paused in Personal, and its viewers are told it moved.
func TestTransferUndoesItsPause(t *testing.T) {
	var c *deletionConsole
	var mode string
	var late uuid.UUID
	started, release := make(chan struct{}, 1), make(chan struct{})
	c = newDeletionConsoleWith(t, deletionOptions{transfer: func(ctx context.Context, source, actor, device, target uuid.UUID) (store.PersonalTransferPreview, error) {
		switch mode {
		case "stopped":
			// Someone stops the number while the move runs; then it fails.
			started <- struct{}{}
			<-release
			return store.PersonalTransferPreview{}, errors.New("ERROR: deadlock detected (SQLSTATE 40P01)")
		case "race":
			// A grant committed after the handler's preview, before the move
			// took its lock.
			if err := store.NewKeys(c.pool).PutGrant(ctx, store.Grant{TenantID: source, DeviceID: device, UserID: late, Epoch: 1, SealedDSK: []byte("late")}, &c.owner); err != nil {
				return store.PersonalTransferPreview{}, err
			}
		case "timeout":
			return store.PersonalTransferPreview{}, errors.New("ERROR: canceling statement due to statement timeout (SQLSTATE 57014)")
		case "lost":
			if _, err := c.devices.TransferPersonal(ctx, source, actor, device, target); err != nil {
				return store.PersonalTransferPreview{}, err
			}
			return store.PersonalTransferPreview{}, errors.New("the commit's answer was lost")
		}
		return c.devices.TransferPersonal(ctx, source, actor, device, target)
	}})
	ctx := context.Background()
	personal := c.personalOf(t, c.owner)
	owner := wsapi.Hello{Session: c.token}
	late, _ = c.person(t, "late", "member")

	for _, tc := range []struct {
		mode, code  string
		alreadyStop bool
	}{
		{"race", wsapi.ErrCodeOthersHaveAccess, false},
		{"race", wsapi.ErrCodeOthersHaveAccess, true},
		{"timeout", wsapi.ErrCodeConflict, false},
		{"timeout", wsapi.ErrCodeConflict, true},
	} {
		mode = tc.mode
		device := c.linkedDevice(t, "Vendas "+tc.mode)
		c.reads(t, c.owner, device)
		if tc.alreadyStop {
			if err := c.devices.SetPaused(ctx, c.tenant.String(), device.String(), true); err != nil {
				t.Fatal(err)
			}
		}
		e := wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceTransfer, transferFrame(device, personal)), tc.code)
		if tc.code == wsapi.ErrCodeOthersHaveAccess && (len(e.Others) != 1 || *e.Others[0].UserID != late) {
			t.Fatalf("%s: the race's refusal %+v", tc.mode, e)
		}
		if got := c.paused(t, c.tenant, device); got != tc.alreadyStop {
			t.Fatalf("%s (already paused %v): paused %v after the failed move", tc.mode, tc.alreadyStop, got)
		}
		var transfers, moves int
		c.scoped(ctx, t, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM device_transfers WHERE device_id=$1),
				(SELECT count(*) FROM item_events WHERE item_id=$1 AND type='moved_out')`, device).Scan(&transfers, &moves)
		})
		if transfers+moves != 0 {
			t.Fatalf("%s: a failed move left %d transfers and %d events", tc.mode, transfers, moves)
		}
	}

	// An admin's stop while the move runs finds the number paused and
	// changes nothing else; the failed move's undo leaves it standing.
	mode = "stopped"
	stopped := c.linkedDevice(t, "Parado")
	c.reads(t, c.owner, stopped)
	_, adminToken := c.person(t, "adm", "admin")
	conn := connect(t, c.console, owner)
	request(t, conn, "move", wsapi.TypeDeviceTransfer, transferFrame(stopped, personal))
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("the move never started")
	}
	f := ask(t, c.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: stopped.String()})
	close(release)
	if f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("the admin's stop: %s %s", f.Type, f.Payload)
	}
	reply, _ := replyTo(t, conn, "move")
	wantError(t, reply, wsapi.ErrCodeConflict)
	if !c.paused(t, c.tenant, stopped) {
		t.Fatal("a stop made while the move ran was undone")
	}

	// The commit went through and only its answer was lost: the number has
	// left the Team, so the undo finds nothing and it stays paused in
	// Personal, as a move leaves it. The owner is told it is no longer in
	// the Team, and the admin's session that saw it, that it moved.
	mode = "lost"
	device := c.linkedDevice(t, "Perdido")
	c.reads(t, c.owner, device)
	adminFrames := drain(connect(t, c.console, wsapi.Hello{Session: adminToken}))
	wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceTransfer, transferFrame(device, personal)), wsapi.ErrCodeNotFound)
	if !c.paused(t, personal, device) {
		t.Fatal("the moved number was unpaused in Personal")
	}
	if r := payload[wsapi.DeviceRemoved](t, next(t, adminFrames, wsapi.TypeDeviceRemoved)); r.DeviceID != device.String() || r.Reason != wsapi.DeviceRemovedMoved {
		t.Fatalf("the admin's push: %+v", r)
	}
}

// A grant.add that waits for a move's lock finds the number gone from the
// workspace (the ownership trigger's WS002) and answers not_found, not
// internal (the plan's test 64).
func TestGrantAddAfterAMove(t *testing.T) {
	c := newDeletionConsole(t)
	ctx := context.Background()
	device := c.linkedDevice(t, "Vendas")
	c.reads(t, c.owner, device)
	personal := c.personalOf(t, c.owner)
	reader, _ := c.person(t, "ana", "member")
	if err := c.devices.SetPaused(ctx, c.tenant.String(), device.String(), true); err != nil {
		t.Fatal(err)
	}
	// The device's row, which the move locks after the workspaces: the move
	// then waits holding them, and the grant waits behind it.
	blocker, err := c.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, c.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM devices WHERE id=$1 FOR UPDATE`, device); err != nil {
		t.Fatal(err)
	}
	pid := blocker.Conn().PgConn().PID()
	moved := make(chan error, 1)
	go func() {
		_, err := c.devices.TransferPersonal(ctx, c.tenant, c.owner, device, personal)
		moved <- err
	}()
	waitWaiting(t, c, pid, 1)
	conn := connect(t, c.console, wsapi.Hello{Session: c.token})
	request(t, conn, "grant", wsapi.TypeGrantAdd, wsapi.GrantRequest{DeviceID: device.String(), UserID: reader.String(), Epoch: 1, SealedDSK: []byte("late")})
	waitWaiting(t, c, pid, 2)
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-moved; err != nil {
		t.Fatal(err)
	}
	f, _ := replyTo(t, conn, "grant")
	if e := wantError(t, f, wsapi.ErrCodeNotFound); !strings.Contains(e.Message, "no longer in this workspace") {
		t.Fatalf("grant.add after the move: %+v", e)
	}
	// Counted in each workspace's own scope: the table's policy shows
	// nothing outside one. The owner's grant, which moved, is the control.
	grants := func(tenant, user uuid.UUID) int {
		t.Helper()
		var n int
		if err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM device_key_grants WHERE device_id=$1 AND user_id=$2`, device, user).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if team, mine, moved := grants(c.tenant, reader), grants(personal, reader), grants(personal, c.owner); team+mine != 0 || moved != 1 {
		t.Fatalf("the reader's grants: %d in the Team, %d in Personal; the owner's in Personal: %d", team, mine, moved)
	}
}

// waitWaiting waits until n backends wait on pid, directly or behind
// another waiter.
func waitWaiting(t *testing.T, c *deletionConsole, pid uint32, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if err := c.pool.QueryRow(context.Background(), `WITH RECURSIVE waiting(pid) AS (
			SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
			UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid=ANY(pg_blocking_pids(a.pid))
		) SELECT count(*) FROM waiting`, int(pid)).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("fewer than %d transactions waited", n)
}
