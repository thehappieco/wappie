package numberacts_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	kc "github.com/thehappieco/kit/contract"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/numberacts"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// sockets is the runners' socket server, counting the access wake-ups.
type sockets struct{ revalidated atomic.Int32 }

func (s *sockets) CancelPairing(string, string)                         {}
func (s *sockets) PushNotices(string, []store.RaisedNotice)             {}
func (s *sockets) BroadcastDeviceStatus(string, string, string, string) {}
func (s *sockets) RevalidateAccess()                                    { s.revalidated.Add(1) }

// flagsWorld is a platform team Wappie has recorded, with an admin linked
// to a sub whose document says admin, and a number its owner reads.
type flagsWorld struct {
	pool   *pgxpool.Pool
	tenant uuid.UUID
	users  *store.Users
	keys   *store.Keys
	owner  uuid.UUID
	gen    uuid.UUID
	cseq   int64
	device uuid.UUID
}

func newFlagsWorld(t *testing.T) *flagsWorld {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	w := &flagsWorld{pool: pool, users: store.NewUsers(pool), keys: store.NewKeys(pool), gen: uuid.New()}
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`).Scan(&w.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp(), generation = $1`, w.gen); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, w.tenant); err != nil {
		t.Fatal(err)
	}
	w.owner = w.person(t, "owner")
	devices := store.NewDevices(pool)
	dev, err := devices.Create(ctx, w.tenant.String(), "Vendas", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err := devices.SetIdentity(ctx, w.tenant.String(), dev.ID, wa.Identity{
		PN:  types.JID{User: "5511900005678", Server: types.DefaultUserServer},
		LID: types.JID{User: "100000000000001", Server: types.HiddenUserServer}}); err != nil {
		t.Fatal(err)
	}
	w.device = uuid.MustParse(dev.ID)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, w.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	w.reads(t, w.owner)
	return w
}

func (w *flagsWorld) person(t *testing.T, role string) uuid.UUID {
	t.Helper()
	u, err := w.users.Create(context.Background(), store.NewUser{TenantID: w.tenant, Email: role + "-" + uuid.NewString()[:8] + "@acme.test",
		Role: role, AuthKey: "test", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32),
		WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// reads gives user the number's key and Read.
func (w *flagsWorld) reads(t *testing.T, user uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if err := w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: w.device, UserID: user, Epoch: 1, SealedDSK: []byte("grant")},
		&w.owner); err != nil {
		t.Fatal(err)
	}
	if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: w.device, UserID: user, Read: true}); err != nil {
		t.Fatal(err)
	}
}

// actor is a person of the team with role, linked to a sub whose document
// gives the team the same role.
func (w *flagsWorld) actor(t *testing.T, role string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	user, sub := w.person(t, role), uuid.New()
	if _, err := w.pool.Exec(ctx, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'new')`,
		sub, user, sub.String()[:8]+"@id.test"); err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]any{"v": 1, "workspaces": []map[string]any{
		{"id": w.tenant.String(), "kind": "team", "role": role, "status": "open", "wversion": 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active', $3)`,
		sub, w.gen, doc); err != nil {
		t.Fatal(err)
	}
	return user, sub
}

// run takes a command of kind by user, with no result yet.
func (w *flagsWorld) run(t *testing.T, kind string, user, sub uuid.UUID) numberacts.Run {
	t.Helper()
	w.cseq++
	id := uuid.New()
	if _, err := w.pool.Exec(context.Background(), `INSERT INTO contract_commands (id, generation, cseq, workspace_id, wseq, kind, section,
		actor, issued_at, body, body_key, signed_at) VALUES ($1, $2, $3, $4, $3, $5, 'numbers', $6, clock_timestamp(), '{}', $7, clock_timestamp())`,
		id, w.gen, w.cseq, w.tenant, kind, sub, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	return numberacts.Run{Command: id, Workspace: w.tenant, Actor: sub, User: user}
}

// TestFlagsRevalidateAccess: the runners wake this process's sockets once
// after a ran that wrote, never after a refusal, a ran that changed
// nothing, or params the kit refuses; and run with no socket server.
func TestFlagsRevalidateAccess(t *testing.T) {
	ctx := context.Background()
	w := newFlagsWorld(t)
	admin, adminSub := w.actor(t, "admin")
	member, memberSub := w.actor(t, "member")
	target := w.person(t, "member")
	s := &sockets{}
	r := &numberacts.Runner{Store: store.NewContract(w.pool), Sockets: s}
	read, readSend := []string{kc.CanRead}, []string{kc.CanRead, kc.CanSend}
	step := func(what string, act store.ContractAct, err error, outcome, code string, wakes int32) {
		t.Helper()
		if err != nil || act.Result.Outcome != outcome || act.Result.Code != code {
			t.Fatalf("%s: %+v %v, want %s %s", what, act, err, outcome, code)
		}
		if got := s.revalidated.Swap(0); got != wakes {
			t.Fatalf("%s: the sockets woken %d times, want %d", what, got, wakes)
		}
	}
	act, err := r.FlagsRaise(ctx, w.run(t, kc.OpItemFlagsRaise, member, memberSub), w.device, target, read, readSend)
	step("a member's raise", act, err, "refused", kc.CodeNotAuthorized, 0)
	// The owner is the number's one reader.
	act, err = r.FlagsDrop(ctx, w.run(t, kc.OpItemFlagsDrop, admin, adminSub), w.device, w.owner, read, []string{})
	step("the last reader's drop", act, err, "refused", kc.CodeLastReader, 0)
	act, err = r.AccessRemove(ctx, w.run(t, kc.OpItemAccessRemove, admin, adminSub), w.device, w.owner)
	step("the last reader's remove", act, err, "refused", kc.CodeLastReader, 0)
	w.reads(t, target)
	act, err = r.FlagsRaise(ctx, w.run(t, kc.OpItemFlagsRaise, admin, adminSub), w.device, target, readSend, append(readSend, kc.CanManage))
	step("a stale raise", act, err, "refused", kc.CodeStateChanged, 0)
	act, err = r.FlagsRaise(ctx, w.run(t, kc.OpItemFlagsRaise, admin, adminSub), w.device, target, read, readSend)
	step("a raise", act, err, "ran", "", 1)
	act, err = r.FlagsDrop(ctx, w.run(t, kc.OpItemFlagsDrop, admin, adminSub), w.device, target, []string{kc.CanManage}, []string{})
	step("a drop of a flag not held", act, err, "ran", "", 0)
	act, err = r.FlagsDrop(ctx, w.run(t, kc.OpItemFlagsDrop, admin, adminSub), w.device, target, readSend, read)
	step("a drop of send", act, err, "ran", "", 1)
	act, err = r.AccessRemove(ctx, w.run(t, kc.OpItemAccessRemove, admin, adminSub), w.device, target)
	step("a remove", act, err, "ran", "", 1)
	act, err = r.AccessRemove(ctx, w.run(t, kc.OpItemAccessRemove, admin, adminSub), w.device, uuid.New())
	step("a remove of nobody", act, err, "ran", "", 0)
	if _, err := r.FlagsRaise(ctx, w.run(t, kc.OpItemFlagsRaise, admin, adminSub), w.device, target, []string{}, read); !errors.Is(err, store.ErrInvalidFlags) ||
		s.revalidated.Load() != 0 {
		t.Fatalf("a raise of read: %v, the sockets woken %d times", err, s.revalidated.Load())
	}
	// No socket server: the act runs all the same.
	r.Sockets = nil
	act, err = r.FlagsRaise(ctx, w.run(t, kc.OpItemFlagsRaise, admin, adminSub), w.device, target, []string{}, []string{kc.CanSend})
	step("a raise with no sockets", act, err, "ran", "", 0)
}
