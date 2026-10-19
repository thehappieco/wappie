package wsapi_test

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/membership"
	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// Test 45, the socket's part (the plan's 4.12): the freshness hook at
// every gated act, with the act's mode for each party, never for an API
// key's act; before the act's store transaction (NOWAIT probes from inside
// the hook find the workspace and its numbers unlocked); a send never waits
// for it; and with the enforce flag a refusal is answered
// memberships_unconfirmed and the act changes nothing. What the hook does
// with those calls is membership's TestFreshness*.

// freshCall is one call the hook got.
type freshCall struct {
	kind, act      string
	tenant         uuid.UUID
	parties        []membership.Party
	device, losing uuid.UUID
	probe          error
}

// freshRecorder is a hook that records its calls, probes the workspace's
// locks from inside each, holds Stored calls while hold is set, and
// answers refuse.
type freshRecorder struct {
	pool   *pgxpool.Pool
	mu     sync.Mutex
	calls  []freshCall
	refuse error
	hold   chan struct{}
}

// probe locks the workspace's row and every number's, NOWAIT: an act whose
// transaction were open would hold one of them.
func (r *freshRecorder) probe(ctx context.Context, tenant uuid.UUID) error {
	return pg.InTenantTx(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', 'on', true)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE NOWAIT`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT 1 FROM devices WHERE tenant_id = $1 FOR UPDATE NOWAIT`, tenant)
		return err
	})
}

func (r *freshRecorder) record(ctx context.Context, c freshCall) error {
	c.probe = r.probe(ctx, c.tenant)
	r.mu.Lock()
	r.calls = append(r.calls, c)
	refuse, hold := r.refuse, r.hold
	r.mu.Unlock()
	if hold != nil && len(c.parties) > 0 && c.parties[0].How == membership.Stored && c.act != wsapi.TypeDeviceTransferPreview {
		select {
		case <-hold:
		case <-ctx.Done():
		}
	}
	return refuse
}

func (r *freshRecorder) RequireFresh(ctx context.Context, act string, tenant uuid.UUID, parties ...membership.Party) (membership.Verdict, error) {
	return membership.Verdict{}, r.record(ctx, freshCall{kind: "fresh", act: act, tenant: tenant, parties: parties})
}

func (r *freshRecorder) RequireBackups(ctx context.Context, act string, tenant, device, losing uuid.UUID) (membership.Verdict, error) {
	return membership.Verdict{}, r.record(ctx, freshCall{kind: "backups", act: act, tenant: tenant, device: device, losing: losing})
}

func (r *freshRecorder) RequireMover(ctx context.Context, tenant, actor uuid.UUID) (membership.Verdict, error) {
	return membership.Verdict{}, r.record(ctx, freshCall{kind: "mover", act: membership.ActTransfer, tenant: tenant,
		parties: []membership.Party{{User: actor, How: membership.Always}}})
}

func (r *freshRecorder) set(refuse error, hold chan struct{}) {
	r.mu.Lock()
	r.refuse, r.hold = refuse, hold
	r.mu.Unlock()
}

// since is the calls after the first n.
func (r *freshRecorder) since(n int) []freshCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls[n:])
}

func (r *freshRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// one checks that the calls since n are exactly one, of kind and act,
// with these parties in order, its probes unlocked.
func (r *freshRecorder) one(t *testing.T, n int, kind, act string, parties ...membership.Party) freshCall {
	t.Helper()
	calls := r.since(n)
	if len(calls) != 1 {
		t.Fatalf("%s: %d calls, want 1: %+v", act, len(calls), calls)
	}
	c := calls[0]
	if c.kind != kind || c.act != act || !slices.Equal(c.parties, parties) {
		t.Fatalf("%s: %+v, want %s with %+v", act, c, kind, parties)
	}
	if c.probe != nil {
		t.Fatalf("%s: the hook ran inside the act's transaction: %v", act, c.probe)
	}
	return c
}

// eventuallyOne is one for a call made in the background.
func (r *freshRecorder) eventuallyOne(t *testing.T, n int, kind, act string, parties ...membership.Party) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.count() <= n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	r.one(t, n, kind, act, parties...)
}

func TestFreshnessHook(t *testing.T) {
	rec := &freshRecorder{}
	c := newDeletionConsoleWith(t, deletionOptions{fresh: rec, registry: true})
	rec.pool = c.pool
	ctx := context.Background()
	owner, key := wsapi.Hello{Session: c.token}, wsapi.Hello{APIKey: c.apiKey}
	device := c.linkedDevice(t, "Vendas")
	reader, _ := c.person(t, "reader", "member")
	second, _ := c.person(t, "second", "member")
	c.reads(t, c.owner, device)
	c.reads(t, reader, device)
	ifStale := func(u uuid.UUID) membership.Party { return membership.Party{User: u, How: membership.IfStale} }
	always := func(u uuid.UUID) membership.Party { return membership.Party{User: u, How: membership.Always} }
	stored := func(u uuid.UUID) membership.Party { return membership.Party{User: u, How: membership.Stored} }
	ref := wsapi.DeviceRef{DeviceID: device.String()}

	// A person's stop is gated; an API key's never.
	n := rec.count()
	if f := ask(t, c.console, owner, wsapi.TypeDeviceStop, ref); f.Type == wsapi.TypeError {
		t.Fatalf("a person's stop: %s", f.Payload)
	}
	rec.one(t, n, "fresh", wsapi.TypeDeviceStop, ifStale(c.owner))
	n = rec.count()
	if f := ask(t, c.console, key, wsapi.TypeDeviceStop, ref); f.Type == wsapi.TypeError {
		t.Fatalf("a key's stop: %s", f.Payload)
	}
	if calls := rec.since(n); len(calls) != 0 {
		t.Fatalf("a key's stop was gated: %+v", calls)
	}

	// A person's sends and group administration: in the background, on the
	// stored freshness; the frame is answered while the check waits, and
	// one session checks an act on a number once a minute.
	hold := make(chan struct{})
	rec.set(nil, hold)
	conn := connect(t, c.console, owner)
	n = rec.count()
	send := wsapi.SendRequest{DeviceID: device.String(), Chat: "5511999990000@s.whatsapp.net", Body: "oi"}
	start := time.Now()
	request(t, conn, "s1", wsapi.TypeSend, send)
	if f, _ := replyTo(t, conn, "s1"); f.Type != wsapi.TypeError || payload[wsapi.Error](t, f).Code != wsapi.ErrCodeConflict {
		t.Fatalf("a send: %s %s", f.Type, f.Payload)
	}
	// The check waits for hold, up to its 5 s bound; the send did not.
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the send waited %s for its check", took)
	}
	rec.eventuallyOne(t, n, "fresh", wsapi.TypeSend, stored(c.owner))
	request(t, conn, "s2", wsapi.TypeSend, send)
	if f, _ := replyTo(t, conn, "s2"); f.Type != wsapi.TypeError {
		t.Fatalf("a second send: %s", f.Type)
	}
	time.Sleep(200 * time.Millisecond)
	if calls := rec.since(n); len(calls) != 1 {
		t.Fatalf("a second send within the minute was checked again: %+v", calls)
	}
	n = rec.count()
	request(t, conn, "g1", wsapi.TypeGroupCreate, wsapi.GroupCreateRequest{DeviceID: device.String(), Name: "Equipe", Participants: []string{"5511999990001"}})
	if f, _ := replyTo(t, conn, "g1"); f.Type != wsapi.TypeError {
		t.Fatalf("a group: %s", f.Type)
	}
	rec.eventuallyOne(t, n, "fresh", wsapi.TypeGroupCreate, stored(c.owner))
	close(hold)
	rec.set(nil, nil)
	n = rec.count()
	if f := ask(t, c.console, key, wsapi.TypeSend, send); f.Type != wsapi.TypeError {
		t.Fatalf("a key's send: %s", f.Type)
	}
	time.Sleep(100 * time.Millisecond)
	if calls := rec.since(n); len(calls) != 0 {
		t.Fatalf("a key's send was checked: %+v", calls)
	}

	// Sharing a key: the person IfStale, the recipient Always; a grant to
	// oneself shares nothing. Revoking one: the minute rule.
	grant := func(to uuid.UUID) wsapi.GrantRequest {
		return wsapi.GrantRequest{DeviceID: device.String(), UserID: to.String(), Epoch: 1, SealedDSK: []byte("grant")}
	}
	n = rec.count()
	if f := ask(t, c.console, owner, wsapi.TypeGrantAdd, grant(second)); f.Type == wsapi.TypeError {
		t.Fatalf("a grant: %s", f.Payload)
	}
	rec.one(t, n, "fresh", wsapi.TypeGrantAdd, ifStale(c.owner), always(second))
	n = rec.count()
	if f := ask(t, c.console, owner, wsapi.TypeGrantAdd, grant(c.owner)); f.Type == wsapi.TypeError {
		t.Fatalf("a grant to oneself: %s", f.Payload)
	}
	rec.one(t, n, "fresh", wsapi.TypeGrantAdd, ifStale(c.owner))
	n = rec.count()
	if f := ask(t, c.console, owner, wsapi.TypeGrantRevoke, wsapi.GrantRevoke{DeviceID: device.String(), UserID: second.String()}); f.Type == wsapi.TypeError {
		t.Fatalf("a revocation: %s", f.Payload)
	}
	if call := rec.one(t, n, "backups", wsapi.TypeGrantRevoke); call.device != device || call.losing != second || call.tenant != c.tenant {
		t.Fatalf("a revocation: %+v", call)
	}

	// An API key's creation.
	n = rec.count()
	if f := ask(t, c.console, owner, wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "erp", Scope: "read"}); f.Type == wsapi.TypeError {
		t.Fatalf("a key: %s", f.Payload)
	}
	rec.one(t, n, "fresh", wsapi.TypeKeyCreate, ifStale(c.owner))

	// A move out of the team: the preview on the stored freshness, the
	// move with the mover's document.
	var personal uuid.UUID
	if err := c.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE kind = 'personal' AND personal_owner_id = $1`, c.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	n = rec.count()
	ask(t, c.console, owner, wsapi.TypeDeviceTransferPreview, ref)
	rec.one(t, n, "fresh", wsapi.TypeDeviceTransferPreview, stored(c.owner))
	n = rec.count()
	ask(t, c.console, owner, wsapi.TypeDeviceTransfer, wsapi.DeviceTransferRequest{DeviceID: device.String(), Confirm: device.String(), TargetWorkspaceID: personal.String()})
	rec.one(t, n, "mover", membership.ActTransfer, always(c.owner))

	// A deletion and a recovery.
	n = rec.count()
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, reader)); f.Type == wsapi.TypeError {
		t.Fatalf("a deletion: %s", f.Payload)
	}
	rec.one(t, n, "fresh", wsapi.TypeDeviceDelete, ifStale(c.owner))
	n = rec.count()
	if f := ask(t, c.console, owner, wsapi.TypeDeviceRecover, wsapi.RecoverRequest{DeviceID: device.String(), Confirm: device.String()}); f.Type == wsapi.TypeError {
		t.Fatalf("a recovery: %s", f.Payload)
	}
	rec.one(t, n, "fresh", wsapi.TypeDeviceRecover, ifStale(c.owner))

	// With the enforce flag every gated act is refused and changes nothing;
	// a send still goes on.
	other := c.linkedDevice(t, "Suporte")
	c.reads(t, c.owner, other)
	c.reads(t, reader, other)
	otherRef := wsapi.DeviceRef{DeviceID: other.String()}
	rec.set(membership.ErrMembershipsUnconfirmed, nil)
	refused := func(what, frame string, body any) {
		t.Helper()
		wantError(t, ask(t, c.console, owner, frame, body), wsapi.ErrCodeMembershipsUnconfirmed)
	}
	refused("a stop", wsapi.TypeDeviceStop, otherRef)
	if d, err := c.devices.Get(ctx, c.tenant.String(), other.String()); err != nil || d.Paused {
		t.Fatalf("a refused stop paused the number: %+v %v", d, err)
	}
	refused("a grant", wsapi.TypeGrantAdd, wsapi.GrantRequest{DeviceID: other.String(), UserID: second.String(), Epoch: 1, SealedDSK: []byte("grant")})
	refused("a revocation", wsapi.TypeGrantRevoke, wsapi.GrantRevoke{DeviceID: other.String(), UserID: reader.String()})
	var grants int
	if err := pg.InTenantTx(ctx, c.pool, c.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM device_key_grants WHERE device_id = $1`, other).Scan(&grants)
	}); err != nil || grants != 2 {
		t.Fatalf("%d grants after a refused grant and revocation, want 2: %v", grants, err)
	}
	keys, err := c.keys.List(ctx, c.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	refused("a key", wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "erp2", Scope: "read"})
	if after, err := c.keys.List(ctx, c.tenant.String()); err != nil || len(after) != len(keys) {
		t.Fatalf("a refused key was issued: %d, %d %v", len(keys), len(after), err)
	}
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	devices, err := c.devices.List(ctx, c.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	n = rec.count()
	refused("a pairing", wsapi.TypePair, wsapi.PairRequest{Method: "qr", ArchivePublicKey: pub.Bytes(),
		Grants: []wsapi.KeyGrant{{UserID: c.owner.String(), SealedDSK: []byte("g")}, {UserID: reader.String(), SealedDSK: []byte("g")}}})
	rec.one(t, n, "fresh", wsapi.TypePair, ifStale(c.owner), always(reader))
	if after, err := c.devices.List(ctx, c.tenant.String()); err != nil || len(after) != len(devices) {
		t.Fatalf("a refused pairing made a number: %d, %d %v", len(devices), len(after), err)
	}
	refused("a deletion", wsapi.TypeDeviceDelete, deleteFrame(other, reader))
	if deleted, _, _, _ := c.row(t, other); deleted {
		t.Fatal("a refused deletion deleted the number")
	}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, reader)); f.Type != wsapi.TypeError {
		t.Fatalf("enforce let a deletion through: %s", f.Type)
	}
	rec.set(nil, nil)
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, reader)); f.Type == wsapi.TypeError {
		t.Fatalf("a deletion: %s", f.Payload)
	}
	rec.set(membership.ErrMembershipsUnconfirmed, nil)
	refused("a recovery", wsapi.TypeDeviceRecover, wsapi.RecoverRequest{DeviceID: device.String(), Confirm: device.String()})
	if deleted, _, _, _ := c.row(t, device); !deleted {
		t.Fatal("a refused recovery recovered the number")
	}
	transfer := wsapi.DeviceTransferRequest{DeviceID: other.String(), Confirm: other.String(), TargetWorkspaceID: personal.String()}
	refused("a move", wsapi.TypeDeviceTransfer, transfer)
	rec.set(membership.ErrNotTheOnlyOwner, nil)
	wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceTransfer, transfer), wsapi.ErrCodeConflict)
	if d, err := c.devices.Get(ctx, c.tenant.String(), other.String()); err != nil || d.Paused {
		t.Fatalf("a refused move touched the number: %+v %v", d, err)
	}
	rec.set(membership.ErrMembershipsUnconfirmed, nil)
	if f := ask(t, c.console, owner, wsapi.TypeSend, wsapi.SendRequest{DeviceID: other.String(), Chat: send.Chat, Body: "oi"}); f.Type != wsapi.TypeError ||
		payload[wsapi.Error](t, f).Code != wsapi.ErrCodeConflict {
		t.Fatalf("a send under the enforce flag: %s %s", f.Type, f.Payload)
	}
	for _, call := range rec.since(0) {
		if call.probe != nil {
			t.Fatalf("%s ran inside a transaction: %v", call.act, call.probe)
		}
		if call.tenant != c.tenant {
			t.Fatalf("%s asked for %s", call.act, call.tenant)
		}
	}
}

// Without the hook every act is as before it.
func TestFreshnessHookAbsent(t *testing.T) {
	c := newDeletionConsole(t)
	device := c.linkedDevice(t, "Vendas")
	c.reads(t, c.owner, device)
	if f := ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: device.String()}); f.Type == wsapi.TypeError {
		t.Fatalf("a stop without the hook: %s", f.Payload)
	}
	if d, err := c.devices.Get(context.Background(), c.tenant.String(), device.String()); err != nil || !d.Paused {
		t.Fatalf("not paused: %+v %v", d, err)
	}
}

// lateFresh is a hook whose Members comes once the console's pool exists.
type lateFresh struct {
	m atomic.Pointer[membership.Members]
}

func (l *lateFresh) RequireFresh(ctx context.Context, act string, tenant uuid.UUID, parties ...membership.Party) (membership.Verdict, error) {
	return l.m.Load().RequireFresh(ctx, act, tenant, parties...)
}

func (l *lateFresh) RequireBackups(ctx context.Context, act string, tenant, device, losing uuid.UUID) (membership.Verdict, error) {
	return l.m.Load().RequireBackups(ctx, act, tenant, device, losing)
}

func (l *lateFresh) RequireMover(ctx context.Context, tenant, actor uuid.UUID) (membership.Verdict, error) {
	return l.m.Load().RequireMover(ctx, tenant, actor)
}

// At observe, with the real hook and the fake platform: a send's check
// makes no call and logs "stale at act"; a person's stop asks the
// platform, logs "would refuse" when it gets no answer, and stops the
// number all the same.
func TestFreshnessHookObserves(t *testing.T) {
	late := &lateFresh{}
	c := newDeletionConsoleWith(t, deletionOptions{fresh: late})
	ctx := context.Background()
	secret := membershiptest.Secret(t)
	fake := membershiptest.StartFake(t, secret)
	client := membership.NewClient(&http.Client{}, fake.URL, nil)
	if err := client.Use(secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	late.m.Store(&membership.Members{Client: client, Contract: store.NewContract(c.pool), Log: logs.Logger(), ModeCache: -1})
	sub := uuid.New()
	if _, err := fake.AddAccount(sub.String()); err != nil {
		t.Fatal(err)
	}
	// Observing, the console's team recorded, its owner linked to a sub
	// with no document yet: stale.
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := c.pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp()`)
	exec(`INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, c.tenant)
	exec(`INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, 'owner@id.test', 'legacy')`, sub, c.owner)
	device := c.linkedDevice(t, "Vendas")
	c.reads(t, c.owner, device)
	owner := wsapi.Hello{Session: c.token}

	if f := ask(t, c.console, owner, wsapi.TypeSend, wsapi.SendRequest{DeviceID: device.String(), Chat: "5511999990000@s.whatsapp.net", Body: "oi"}); f.Type != wsapi.TypeError {
		t.Fatalf("a send: %s", f.Type)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(logs.Lines("freshness: stale at act", "act=message.send", sub.String())) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(logs.Lines("freshness: stale at act", "act=message.send", sub.String())) != 1 || fake.Count(contracttest.CallAccount) != 0 {
		t.Fatalf("a send's check: %d calls\n%s", fake.Count(contracttest.CallAccount), logs.String())
	}

	fake.SetDown(true)
	if f := ask(t, c.console, owner, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: device.String()}); f.Type == wsapi.TypeError {
		t.Fatalf("a stop at observe: %s", f.Payload)
	}
	if d, err := c.devices.Get(ctx, c.tenant.String(), device.String()); err != nil || !d.Paused {
		t.Fatalf("the stop did not go on: %+v %v", d, err)
	}
	if len(logs.Lines("freshness: would refuse", "act=device.stop", "reason=unavailable", sub.String())) != 1 {
		t.Fatalf("no would-refuse:\n%s", logs.String())
	}
}
