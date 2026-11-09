package wsapi_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	waStore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"

	"whatserver2/internal/bus"
	"whatserver2/internal/migrate"
	"whatserver2/internal/numberacts"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
	"whatserver2/internal/wsapi"
)

// The console's runners (internal/numberacts) against the socket's own
// frames (the plan's 6.8): twin numbers in one workspace, the frame acting
// on one, the runner, with this server as its sockets and the same
// registry, on the other, by the same person; each pair must leave the
// same rows, notices, events, pushes and broadcasts, and refuse the same
// people. The known differences are pinned: a resume whose start fails
// (DS9), and the actor of a stop that tells nobody (DS7).

// The socket server is the runners' sockets.
var _ numberacts.Sockets = (*wsapi.Server)(nil)

// parity is a deletion console with a registry whose server the runner
// reaches, and whose workspace is a platform team Wappie has recorded.
type parity struct {
	*deletionConsole
	t      *testing.T
	srv    *wsapi.Server
	runner *numberacts.Runner
	gen    uuid.UUID
	cseq   int64
}

func newParity(t *testing.T) *parity {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE whatsmeow_device (jid text PRIMARY KEY, registration_id bigint NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(pool)
	apiKey, err := keys.Issue(ctx, tenantID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	users, devices, messages := store.NewUsers(pool), store.NewDevices(pool), store.NewMessages(pool)
	b := bus.New()
	unlinker := &fakeUnlinker{pool: pool}
	registry, err := wa.NewRegistry(wa.RegistryConfig{Container: &sqlstore.Container{}, Store: devices, Log: slog.New(slog.DiscardHandler),
		NewClient: func(*waStore.Device, waLog.Logger) wa.Client { return fakewa.New() },
		LoadSession: func(ctx context.Context, jid types.JID) (*waStore.Device, error) {
			var stored bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM whatsmeow_device WHERE jid=$1)`, jid.String()).Scan(&stored); err != nil || !stored {
				return nil, err
			}
			ds := (&sqlstore.Container{}).NewDevice()
			ds.ID = &jid
			return ds, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { registry.StopAll(context.Background()) })
	server := wsapi.NewServer(wsapi.Config{Keys: keys, Sessions: users, Accounts: users, Devices: devices, Messages: messages,
		Keys2: store.NewKeys(pool), Receipts: store.NewReceipts(pool), Bus: b, Unlinker: unlinker, Log: slog.New(slog.DiscardHandler),
		Registry: registry})
	srv := httptest.NewServer(server)
	t.Cleanup(srv.Close)
	c := &deletionConsole{
		console: &console{srv: srv, pool: pool, tenant: uuid.MustParse(tenantID), apiKey: apiKey, devices: devices, users: users, keys: keys},
		bus:     b, unlinker: unlinker, registry: registry,
	}
	c.token = c.account(t, "owner@acme.test", "owner")
	c.owner = c.sessionUser(t, c.token)
	p := &parity{deletionConsole: c, t: t, srv: server, gen: uuid.New(),
		runner: &numberacts.Runner{Store: store.NewContract(pool), Devices: devices, Registry: registry, Sockets: server}}
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp(), generation = $1`, p.gen); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, c.tenant); err != nil {
		t.Fatal(err)
	}
	return p
}

// link gives user a sub, whose stored document names the team with role.
func (p *parity) link(t *testing.T, user uuid.UUID, role string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	sub := uuid.New()
	if _, err := p.pool.Exec(ctx, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'new')`,
		sub, user, sub.String()[:8]+"@id.test"); err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]any{"v": 1, "workspaces": []map[string]any{
		{"id": p.tenant.String(), "kind": "team", "role": role, "status": "open", "wversion": 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, `INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active', $3)`,
		sub, p.gen, doc); err != nil {
		t.Fatal(err)
	}
	return sub
}

// command takes a command of kind by user (with sub) in the team.
func (p *parity) command(t *testing.T, kind string, user, sub uuid.UUID) numberacts.Run {
	t.Helper()
	p.cseq++
	id := uuid.New()
	if _, err := p.pool.Exec(context.Background(), `INSERT INTO contract_commands (id, generation, cseq, workspace_id, wseq, kind, section,
		actor, issued_at, body, body_key, signed_at) VALUES ($1, $2, $3, $4, $3, $5, 'numbers', $6, clock_timestamp(), '{}', $7, clock_timestamp())`,
		id, p.gen, p.cseq, p.tenant, kind, sub, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	return numberacts.Run{Command: id, Workspace: p.tenant, Actor: sub, User: user}
}

// outcome is an act's result in the frame's terms: "ok" for ran, else its
// code.
func (p *parity) outcome(act store.ContractAct, err error) string {
	p.t.Helper()
	if err != nil {
		p.t.Fatal(err)
	}
	if act.Result.Outcome == store.CommandRan {
		return "ok"
	}
	return act.Result.Code
}

// frameOutcome is a frame's reply in the same terms.
func frameOutcome(t *testing.T, f wsapi.Frame, want string) string {
	t.Helper()
	if f.Type != wsapi.TypeError {
		if f.Type != want {
			t.Fatalf("frame %s, want %s: %s", f.Type, want, f.Payload)
		}
		return "ok"
	}
	switch code := payload[wsapi.Error](t, f).Code; code {
	case wsapi.ErrCodeNotFound:
		return kc.CodeNotFound
	case wsapi.ErrCodeNotAuthorized:
		return kc.CodeNotAuthorized
	default:
		return code
	}
}

// numberRow is what a number's row holds that an act changes.
type numberRow struct {
	Label, Status, Reason, Cause string
	Paused                       bool
	PauseSeq                     int
	Notices, Events              int
	Resumed                      int
	Several                      bool
}

func (p *parity) numberRow(t *testing.T, device uuid.UUID) numberRow {
	t.Helper()
	ctx := context.Background()
	var r numberRow
	p.scoped(ctx, t, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT label, status, status_reason, coalesce(pause_cause, ''), paused, pause_seq FROM devices WHERE id = $1`,
			device).Scan(&r.Label, &r.Status, &r.Reason, &r.Cause, &r.Paused, &r.PauseSeq); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE resumed_at IS NOT NULL), coalesce(bool_or(several_actors), false)
			FROM device_notices WHERE device_id = $1`, device).Scan(&r.Notices, &r.Resumed, &r.Several); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM item_events WHERE item_id = $1`, device).Scan(&r.Events)
	})
	return r
}

// watch is a person's open socket, which a broadcast and a pushed notice
// reach.
type watch struct {
	t    *testing.T
	conn *websocket.Conn
}

func (p *parity) watch(t *testing.T, token string) *watch {
	t.Helper()
	conn := dial(t, p.console.srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{Session: token, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("handshake: %s %s", f.Type, f.Payload)
	}
	return &watch{t: t, conn: conn}
}

// saw reads frames for up to two seconds, and reports whether one of type
// typ named device among them.
func (w *watch) saw(typ string, device uuid.UUID) bool {
	w.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		_, data, err := w.conn.Read(ctx)
		cancel()
		if err != nil {
			return false
		}
		var f wsapi.Frame
		if json.Unmarshal(data, &f) != nil || f.Type != typ {
			continue
		}
		var named struct {
			DeviceID string `json:"device_id"`
		}
		if json.Unmarshal(f.Payload, &named) == nil && named.DeviceID == device.String() {
			return true
		}
	}
	return false
}

func TestConsoleParityStop(t *testing.T) {
	p := newParity(t)
	ctx := context.Background()
	admin, adminToken := p.person(t, "bia", "admin")
	adminSub := p.link(t, admin, "admin")
	reader, readerToken := p.person(t, "caio", "member")
	manager, managerToken := p.person(t, "ana", "member")
	managerSub := p.link(t, manager, "member")
	frame, console := p.linkedDevice(t, "Frame"), p.linkedDevice(t, "Console")
	for _, d := range []uuid.UUID{frame, console} {
		p.reads(t, p.owner, d)
		p.reads(t, reader, d)
		p.reads(t, manager, d)
		if err := p.users.SetDevicePermission(ctx, p.tenant, p.owner, store.DevicePermission{DeviceID: d, UserID: manager, Read: true,
			Manage: true}); err != nil {
			t.Fatal(err)
		}
	}
	// A member with Manage: refused by both.
	fo := frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: managerToken}, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: frame.String()}),
		wsapi.TypeDeviceStatus)
	co := p.outcome(p.runnerStop(t, manager, managerSub, console))
	if fo != kc.CodeNotAuthorized || co != kc.CodeNotAuthorized {
		t.Fatalf("a member with Manage: the frame %s, the runner %s", fo, co)
	}
	// An admin: both stop; the reader's open socket hears both.
	w := p.watch(t, readerToken)
	fo = frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: frame.String()}),
		wsapi.TypeDeviceStatus)
	if fo != "ok" || !w.saw(wsapi.TypeDeviceNotice, frame) {
		t.Fatalf("the frame's stop: %s, its notice pushed: false", fo)
	}
	co = p.outcome(p.runnerStop(t, admin, adminSub, console))
	if co != "ok" || !w.saw(wsapi.TypeDeviceNotice, console) {
		t.Fatalf("the runner's stop: %s, or its notice was not pushed", co)
	}
	fr, cr := p.numberRow(t, frame), p.numberRow(t, console)
	fr.Label, cr.Label = "", ""
	if fr != cr || !fr.Paused || fr.Cause != "person" || fr.Notices != 3 || fr.Events != 1 || fr.Status != "offline" || fr.Reason != "paused by request" {
		t.Fatalf("after a stop: the frame's %+v, the runner's %+v", fr, cr)
	}
	// A second stop by another admin: counted, nobody told again.
	_, ownerAdmin := p.person(t, "dora", "admin")
	dora := p.sessionUser(t, ownerAdmin)
	doraSub := p.link(t, dora, "admin")
	ask(t, p.console, wsapi.Hello{Session: ownerAdmin}, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: frame.String()})
	p.outcome(p.runnerStop(t, dora, doraSub, console))
	fr, cr = p.numberRow(t, frame), p.numberRow(t, console)
	fr.Label, cr.Label = "", ""
	if fr != cr || fr.PauseSeq != 2 || fr.Notices != 3 {
		t.Fatalf("after a second stop: the frame's %+v, the runner's %+v", fr, cr)
	}
	// Known difference (DS7): the runner names its actor; the frame's
	// stop names one through its event, the same person here.
	var fby, cby *uuid.UUID
	p.scoped(ctx, t, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT paused_by_user FROM devices WHERE id = $1`, frame).Scan(&fby); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT paused_by_user FROM devices WHERE id = $1`, console).Scan(&cby)
	})
	if fby == nil || cby == nil || *fby != admin || *cby != admin {
		t.Fatalf("who paused: the frame's %v, the runner's %v, want the first stop's %v", fby, cby, admin)
	}
}

func (p *parity) runnerStop(t *testing.T, user, sub, device uuid.UUID) (store.ContractAct, error) {
	t.Helper()
	return p.runner.SyncStop(context.Background(), p.command(t, kc.OpItemSyncStop, user, sub), device)
}

func (p *parity) runnerResume(t *testing.T, user, sub, device uuid.UUID) (store.ContractAct, error) {
	t.Helper()
	return p.runner.SyncResume(context.Background(), p.command(t, kc.OpItemSyncResume, user, sub), device)
}

func TestConsoleParityResume(t *testing.T) {
	p := newParity(t)
	ctx := context.Background()
	admin, adminToken := p.person(t, "bia", "admin")
	adminSub := p.link(t, admin, "admin")
	manager, managerToken := p.person(t, "ana", "member")
	managerSub := p.link(t, manager, "member")
	reader, _ := p.person(t, "caio", "member")
	frame, console := p.linkedDevice(t, "Frame"), p.linkedDevice(t, "Console")
	for _, d := range []uuid.UUID{frame, console} {
		p.reads(t, p.owner, d)
		p.reads(t, reader, d)
		if err := p.users.SetDevicePermission(ctx, p.tenant, p.owner, store.DevicePermission{DeviceID: d, UserID: manager, Manage: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := p.devices.Pause(ctx, p.tenant, d, store.PauseActor{User: p.owner}); err != nil {
			t.Fatal(err)
		}
	}
	ref := func(d uuid.UUID) wsapi.DeviceRef { return wsapi.DeviceRef{DeviceID: d.String()} }
	fo := frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: managerToken}, wsapi.TypeDeviceStart, ref(frame)), wsapi.TypeDeviceStatus)
	co := p.outcome(p.runnerResume(t, manager, managerSub, console))
	if fo != kc.CodeNotAuthorized || co != kc.CodeNotAuthorized {
		t.Fatalf("a member with Manage: the frame %s, the runner %s", fo, co)
	}
	fo = frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceStart, ref(frame)), wsapi.TypeDeviceStatus)
	co = p.outcome(p.runnerResume(t, admin, adminSub, console))
	if fo != "ok" || co != "ok" {
		t.Fatalf("an admin's resume: the frame %s, the runner %s", fo, co)
	}
	fr, cr := p.numberRow(t, frame), p.numberRow(t, console)
	fr.Label, cr.Label = "", ""
	if fr.Paused || cr.Paused || fr.Resumed != 1 || cr.Resumed != 1 || fr.Cause != cr.Cause {
		t.Fatalf("after a resume: the frame's %+v, the runner's %+v", fr, cr)
	}
	for _, d := range []uuid.UUID{frame, console} {
		if _, running := p.registry.Get(d.String()); !running {
			t.Fatalf("%s does not run after its resume", d)
		}
	}
	// A moved number (a move's pause) is resumed by both, by role.
	for _, d := range []uuid.UUID{frame, console} {
		p.registry.Stop(ctx, d.String())
		p.scoped(ctx, t, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE devices SET paused = true, pause_cause = 'move', pause_seq = pause_seq + 1 WHERE id = $1`, d)
			return err
		})
	}
	fo = frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceStart, ref(frame)), wsapi.TypeDeviceStatus)
	co = p.outcome(p.runnerResume(t, admin, adminSub, console))
	if fo != "ok" || co != "ok" || p.paused(t, p.tenant, frame) || p.paused(t, p.tenant, console) {
		t.Fatalf("a moved number's resume: the frame %s, the runner %s", fo, co)
	}
	// Known difference (DS9): a start that fails. Both mark the number
	// logged out; the frame puts the pause back, the runner keeps it
	// lifted (its ran was committed with the lift).
	for _, d := range []uuid.UUID{frame, console} {
		p.registry.Stop(ctx, d.String())
		if _, err := p.devices.Pause(ctx, p.tenant, d, store.PauseActor{User: p.owner}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.pool.Exec(ctx, `DELETE FROM whatsmeow_device`); err != nil {
		t.Fatal(err)
	}
	fo = frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceStart, ref(frame)), wsapi.TypeDeviceStatus)
	co = p.outcome(p.runnerResume(t, admin, adminSub, console))
	fr, cr = p.numberRow(t, frame), p.numberRow(t, console)
	if fo != wsapi.ErrCodeConflict || co != "ok" || !fr.Paused || cr.Paused || fr.Status != "logged_out" || cr.Status != "logged_out" {
		t.Fatalf("a failed start: the frame %s %+v, the runner %s %+v", fo, fr, co, cr)
	}
}

func TestConsoleParityRename(t *testing.T) {
	p := newParity(t)
	ctx := context.Background()
	manager, managerToken := p.person(t, "ana", "member")
	managerSub := p.link(t, manager, "member")
	member, memberToken := p.person(t, "caio", "member")
	memberSub := p.link(t, member, "member")
	frame, console := p.linkedDevice(t, "Frame"), p.linkedDevice(t, "Console")
	for _, d := range []uuid.UUID{frame, console} {
		p.reads(t, p.owner, d)
		if err := p.users.SetDevicePermission(ctx, p.tenant, p.owner, store.DevicePermission{DeviceID: d, UserID: manager, Manage: true}); err != nil {
			t.Fatal(err)
		}
	}
	rename := func(token string, d uuid.UUID, label string) string {
		return frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: token}, wsapi.TypeDeviceRename,
			wsapi.DeviceRename{DeviceID: d.String(), Label: label}), wsapi.TypeDeviceDetail)
	}
	before := "Console"
	co := p.outcome(p.runner.Rename(ctx, p.command(t, kc.OpItemRename, member, memberSub), console, &before, "Vendas SP"))
	if fo := rename(memberToken, frame, "Vendas SP"); fo != kc.CodeNotAuthorized || co != kc.CodeNotAuthorized {
		t.Fatalf("a member without Manage: the frame %s, the runner %s", fo, co)
	}
	co = p.outcome(p.runner.Rename(ctx, p.command(t, kc.OpItemRename, manager, managerSub), console, &before, "Vendas SP"))
	if fo := rename(managerToken, frame, "Vendas SP"); fo != "ok" || co != "ok" {
		t.Fatalf("a member with Manage: the frame %s, the runner %s", fo, co)
	}
	if f, c := p.numberRow(t, frame), p.numberRow(t, console); f.Label != "Vendas SP" || c.Label != f.Label {
		t.Fatalf("the labels: the frame's %q, the runner's %q", f.Label, c.Label)
	}
}

func TestConsoleParitySyncNow(t *testing.T) {
	p := newParity(t)
	ctx := context.Background()
	admin, adminToken := p.person(t, "bia", "admin")
	adminSub := p.link(t, admin, "admin")
	reader, readerToken := p.person(t, "caio", "member")
	readerSub := p.link(t, reader, "member")
	frame, console := p.linkedDevice(t, "Frame"), p.linkedDevice(t, "Console")
	for _, d := range []uuid.UUID{frame, console} {
		p.reads(t, p.owner, d)
		p.reads(t, reader, d)
		p.reads(t, admin, d)
	}
	start := func(token string, d uuid.UUID) string {
		return frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: token}, wsapi.TypeDeviceStart, wsapi.DeviceRef{DeviceID: d.String()}),
			wsapi.TypeDeviceStatus)
	}
	syncNow := func(user, sub uuid.UUID) string {
		return p.outcome(p.runner.SyncNow(ctx, p.command(t, kc.OpItemSyncNow, user, sub), console)) //nolint:contextcheck // the world's helpers run on a context of their own
	}
	if fo, co := start(adminToken, frame), syncNow(admin, adminSub); fo != "ok" || co != "ok" {
		t.Fatalf("an admin who reads: the frame %s, the runner %s", fo, co)
	}
	for _, d := range []uuid.UUID{frame, console} {
		if _, running := p.registry.Get(d.String()); !running {
			t.Fatalf("%s does not run after a sync now", d)
		}
	}
	// A person's sync now is Read's in both (DS13): a reader without
	// Manage may, an admin who does not read may not.
	if fo, co := start(readerToken, frame), syncNow(reader, readerSub); fo != "ok" || co != "ok" {
		t.Fatalf("a reader without Manage: the frame %s, the runner %s", fo, co)
	}
	outsider, outsiderToken := p.person(t, "dora", "admin")
	outsiderSub := p.link(t, outsider, "admin")
	if fo, co := start(outsiderToken, frame), syncNow(outsider, outsiderSub); fo != kc.CodeNotAuthorized || co != kc.CodeNotAuthorized {
		t.Fatalf("an admin who does not read: the frame %s, the runner %s", fo, co)
	}
	// Both refuse a paused number's sync now: the frame by role as a
	// resume, the runner as paused.
	for _, d := range []uuid.UUID{frame, console} {
		if _, err := p.devices.Pause(ctx, p.tenant, d, store.PauseActor{User: p.owner}); err != nil {
			t.Fatal(err)
		}
	}
	if fo, co := start(readerToken, frame), syncNow(reader, readerSub); fo != kc.CodeNotAuthorized || co != kc.CodePaused {
		t.Fatalf("a paused number: the frame %s, the runner %s", fo, co)
	}
}

func TestConsoleParityRegistrationDelete(t *testing.T) {
	p := newParity(t)
	ctx := context.Background()
	admin, adminToken := p.person(t, "bia", "admin")
	adminSub := p.link(t, admin, "admin")
	member, memberToken := p.person(t, "caio", "member")
	memberSub := p.link(t, member, "member")
	frame, console := uuid.MustParse(p.deviceWithKey(t, "device")), uuid.MustParse(p.deviceWithKey(t, "device"))
	del := func(token string) string {
		return frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: token}, wsapi.TypeDeviceDelete,
			wsapi.DeleteRequest{DeviceID: frame.String(), Confirm: frame.String(), Unlink: true}), wsapi.TypeDeviceGone)
	}
	run := func(user, sub uuid.UUID) string {
		return p.outcome(p.runner.RegistrationDelete(ctx, p.command(t, kc.OpItemRegistrationDelete, user, sub), console)) //nolint:contextcheck // the world's helpers run on a context of their own
	}
	if fo, co := del(memberToken), run(member, memberSub); fo != kc.CodeNotAuthorized || co != kc.CodeNotAuthorized {
		t.Fatalf("a member: the frame %s, the runner %s", fo, co)
	}
	if fo, co := del(adminToken), run(admin, adminSub); fo != "ok" || co != "ok" {
		t.Fatalf("an admin: the frame %s, the runner %s", fo, co)
	}
	for _, d := range []uuid.UUID{frame, console} {
		if _, err := p.devices.Get(ctx, p.tenant.String(), d.String()); err == nil {
			t.Fatalf("%s is still there", d)
		}
	}
}

// TestConsoleParityNotFound: a deleted number, and another workspace's,
// are not found by the frames and by the runners alike, before any role.
func TestConsoleParityNotFound(t *testing.T) {
	p := newParity(t)
	ctx := context.Background()
	admin, adminToken := p.person(t, "bia", "admin")
	adminSub := p.link(t, admin, "admin")
	deleted := p.linkedDevice(t, "Gone")
	if _, err := p.devices.Quarantine(ctx, p.tenant, p.owner, deleted, nil); err != nil {
		t.Fatal(err)
	}
	var elsewhere uuid.UUID
	if err := p.pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('other') RETURNING id`).Scan(&elsewhere); err != nil {
		t.Fatal(err)
	}
	theirs := p.linkedDeviceIn(t, elsewhere, "Theirs")
	label := "Gone"
	for _, d := range []uuid.UUID{deleted, theirs} {
		ref := wsapi.DeviceRef{DeviceID: d.String()}
		for _, c := range []struct {
			frame string
			reply string
			run   func() (store.ContractAct, error)
		}{
			{wsapi.TypeDeviceStop, wsapi.TypeDeviceStatus, func() (store.ContractAct, error) { return p.runnerStop(t, admin, adminSub, d) }},
			{wsapi.TypeDeviceStart, wsapi.TypeDeviceStatus, func() (store.ContractAct, error) { return p.runnerResume(t, admin, adminSub, d) }},
			{wsapi.TypeDeviceStart, wsapi.TypeDeviceStatus, func() (store.ContractAct, error) {
				return p.runner.SyncNow(ctx, p.command(t, kc.OpItemSyncNow, admin, adminSub), d) //nolint:contextcheck // the world's helpers run on a context of their own
			}},
			{wsapi.TypeDeviceRename, wsapi.TypeDeviceDetail, func() (store.ContractAct, error) {
				return p.runner.Rename(ctx, p.command(t, kc.OpItemRename, admin, adminSub), d, &label, "X") //nolint:contextcheck // the world's helpers run on a context of their own
			}},
		} {
			var body any = ref
			if c.frame == wsapi.TypeDeviceRename {
				body = wsapi.DeviceRename{DeviceID: d.String(), Label: "X"}
			}
			fo := frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: adminToken}, c.frame, body), c.reply)
			if co := p.outcome(c.run()); fo != kc.CodeNotFound || co != kc.CodeNotFound {
				t.Errorf("%s of %s: the frame %s, the runner %s", c.frame, d, fo, co)
			}
		}
	}
}
