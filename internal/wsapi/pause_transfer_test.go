package wsapi_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/store"
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
	if n := payload[wsapi.DeviceNotice](t, next(t, readerFrames, wsapi.TypeDeviceNotice)); n.Pauses != 2 || n.RaisedByKind != "key" || !n.SeveralActors {
		t.Fatalf("the reader's folded push: %+v", n)
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
	c := newDeletionConsole(t)
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
}

// TestTransferUndoesItsPause is the plan's test 64, the handler's half:
// after any error from the move, a number the handler paused is unpaused, a
// number already paused stays so, and a move that committed and lost its
// answer leaves the number paused in Personal.
func TestTransferUndoesItsPause(t *testing.T) {
	var c *deletionConsole
	var mode string
	var late uuid.UUID
	c = newDeletionConsoleWith(t, deletionOptions{transfer: func(ctx context.Context, source, actor, device, target uuid.UUID) (store.PersonalTransferPreview, error) {
		switch mode {
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

	// The commit went through and only its answer was lost: the number has
	// left the Team, so the undo finds nothing and it stays paused in
	// Personal, as a move leaves it.
	mode = "lost"
	device := c.linkedDevice(t, "Perdido")
	c.reads(t, c.owner, device)
	wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceTransfer, transferFrame(device, personal)), wsapi.ErrCodeConflict)
	if !c.paused(t, personal, device) {
		t.Fatal("the moved number was unpaused in Personal")
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
	var left int
	if err := c.pool.QueryRow(ctx, `SELECT count(*) FROM device_key_grants WHERE device_id=$1 AND user_id=$2`, device, reader).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d grants for the moved number (%v)", left, err)
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
