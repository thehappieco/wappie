package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// dirtyWatch listens on the contract's dirty channel, and a writer
// connection makes the changes, so that "all", which any test's change of
// a person's status sends, is counted only from this test's writer.
type dirtyWatch struct {
	pool     *pgxpool.Pool
	listener *pgxpool.Conn
	writer   *pgxpool.Conn
}

func newDirtyWatch(t *testing.T, pool *pgxpool.Pool) *dirtyWatch {
	t.Helper()
	ctx := context.Background()
	w := &dirtyWatch{pool: pool}
	var err error
	if w.listener, err = pool.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.listener.Release)
	if w.writer, err = pool.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.writer.Release)
	if _, err := w.listener.Exec(ctx, `LISTEN `+store.ContractDirtyChannel); err != nil {
		t.Fatal(err)
	}
	return w
}

// in runs fn in one transaction on the writer, in tenant, with excluded
// numbers visible.
func (w *dirtyWatch) in(ctx context.Context, t *testing.T, tenant uuid.UUID, fn func(tx pgx.Tx) error) {
	t.Helper()
	tx, err := w.writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.device_quarantine', 'on', true)`,
		tenant.String()); err != nil {
		t.Fatal(err)
	}
	if err := fn(tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// heard is every notification that the change before it made, by
// payload: one of the workspaces named, or "all" from the writer. A fence
// the writer sends after the change ends the wait: notifications reach a
// listener in commit order.
func (w *dirtyWatch) heard(t *testing.T, tenants ...uuid.UUID) map[string]int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fence := "fence:" + uuid.NewString()
	if _, err := w.writer.Exec(ctx, `SELECT pg_notify($1, $2)`, store.ContractDirtyChannel, fence); err != nil {
		t.Fatal(err)
	}
	ours := map[string]bool{}
	for _, id := range tenants {
		ours[id.String()] = true
	}
	writer := w.writer.Conn().PgConn().PID()
	got := map[string]int{}
	for {
		n, err := w.listener.Conn().WaitForNotification(ctx)
		if err != nil {
			t.Fatalf("waiting for the fence: %v", err)
		}
		switch {
		case n.Payload == fence:
			return got
		case ours[n.Payload], n.Payload == "all" && n.PID == writer:
			got[n.Payload]++
		}
	}
}

// TestDirtyNotify is the plan's TB13: each change a workspace's snapshot
// shows notifies that workspace once per transaction (a move both of
// them), a person's status and a new platform link notify "all", and what
// a snapshot does not show (a number going online or offline, its
// connection time, a workspace's byte counters) notifies nobody.
func TestDirtyNotify(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	team, device := a.tenant, a.device
	owner, personal := transferOwner(t, a, "owner")
	member, _ := transferOwner(t, a, "member")
	w := newDirtyWatch(t, a.pool)
	expect := func(change string, want map[string]int) {
		t.Helper()
		got := w.heard(t, team, personal)
		if len(got) != len(want) {
			t.Errorf("%s: heard %v, want %v", change, got, want)
			return
		}
		for k, n := range want {
			if got[k] != n {
				t.Errorf("%s: heard %v, want %v", change, got, want)
				return
			}
		}
	}
	once := map[string]int{team.String(): 1}
	none := map[string]int{}
	// sql makes one change in one transaction, from the number, the
	// member, the team and the owner it names.
	sql := func(change string, want map[string]int, statements ...string) {
		t.Helper()
		w.in(ctx, t, team, func(tx pgx.Tx) error {
			for _, s := range statements {
				if _, err := tx.Exec(ctx, `WITH change AS (SELECT $1::uuid AS device, $2::uuid AS member, $3::uuid AS team,
					$4::uuid AS owner) `+s, device, member, team, owner); err != nil {
					return err
				}
			}
			return nil
		})
		expect(change, want)
	}

	// The number, and what its snapshot shows of it.
	sql("its status online", none, `UPDATE devices SET status='online' FROM change WHERE id=change.device`)
	sql("a label", once, `UPDATE devices SET label='Vendas' FROM change WHERE id=change.device`)
	sql("the same label", none, `UPDATE devices SET label='Vendas' FROM change WHERE id=change.device`)
	sql("a push name", once, `UPDATE devices SET push_name='Loja' FROM change WHERE id=change.device`)
	sql("a phone number", once, `UPDATE devices SET pn='5511912345678@s.whatsapp.net' FROM change WHERE id=change.device`)
	sql("a pause", once, `UPDATE devices SET paused=true FROM change WHERE id=change.device`)
	sql("its cause", once, `UPDATE devices SET pause_cause='move' FROM change WHERE id=change.device`)
	sql("a resume", once, `UPDATE devices SET paused=false FROM change WHERE id=change.device`)
	sql("online to offline", none, `UPDATE devices SET status='offline' FROM change WHERE id=change.device`)
	sql("a connection time", none, `UPDATE devices SET last_connected_at=now(), status_reason='x' FROM change WHERE id=change.device`)
	sql("logged out", once, `UPDATE devices SET status='logged_out' FROM change WHERE id=change.device`)
	sql("banned after logged out", once, `UPDATE devices SET status='banned' FROM change WHERE id=change.device`)
	sql("offline after banned", once, `UPDATE devices SET status='offline' FROM change WHERE id=change.device`)
	sql("an exclusion", once, `UPDATE devices SET deleted_at=now(), purge_after=now()+interval '30 days', paused=true
		FROM change WHERE id=change.device`)
	sql("its purge date", once, `UPDATE devices SET purge_after=now()+interval '1 day' FROM change WHERE id=change.device`)
	sql("a recovery", once, `UPDATE devices SET deleted_at=NULL, purge_after=NULL FROM change WHERE id=change.device`)
	sql("a resume after it", once, `UPDATE devices SET paused=false FROM change WHERE id=change.device`)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(a.pool).CreateArchiveKey(ctx, team, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	expect("an archive key, and its epoch", once)

	// Who holds what on it.
	grant := `INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk)
		SELECT change.team, change.device, change.member, 1, 'grant' FROM change`
	sql("a grant, with the permissions it brings", once, grant)
	sql("a permission withheld", once, `UPDATE device_permissions SET can_read=false FROM change
		WHERE device_id=change.device AND user_id=change.member`)
	sql("a grant gone", once, `DELETE FROM device_key_grants USING change WHERE device_id=change.device AND user_id=change.member`)
	sql("a permission gone", once, `DELETE FROM device_permissions USING change WHERE device_id=change.device AND user_id=change.member`)
	sql("a role", once, `UPDATE workspace_memberships SET role='admin' FROM change WHERE tenant_id=change.team AND user_id=change.member`)
	sql("many changes in one transaction", once, grant,
		`UPDATE device_permissions SET can_send=false FROM change WHERE device_id=change.device`,
		`UPDATE devices SET label='Suporte' FROM change WHERE id=change.device`,
		`UPDATE workspace_memberships SET status='disabled' FROM change WHERE tenant_id=change.team AND user_id=change.member`)

	// A person's status reaches every workspace of theirs, as does a link.
	all := map[string]int{"all": 1}
	sql("a person disabled", all, `UPDATE users SET status='disabled' FROM change WHERE id=change.member`)
	sql("a person's name", none, `UPDATE users SET name='Ana' FROM change WHERE id=change.member`)
	sql("a person enabled", all, `UPDATE users SET status='active' FROM change WHERE id=change.member`)
	sql("a platform link", all, `INSERT INTO platform_identities (sub, user_id, email, linked_from)
		SELECT uuidv7(), change.owner, 'owner@id.test', 'new' FROM change`)

	// The workspace's own status and storage stop, not its counters.
	sql("a workspace suspended", once, `UPDATE tenants SET status='suspended' FROM change WHERE id=change.team`)
	sql("a workspace active again", once, `UPDATE tenants SET status='active' FROM change WHERE id=change.team`)
	sql("a storage stop", once, `UPDATE tenants SET storage_paused_at=now() FROM change WHERE id=change.team`)
	sql("a storage limit", once, `UPDATE tenants SET storage_limit_bytes=1000000 FROM change WHERE id=change.team`)
	sql("the byte counters", none, `UPDATE tenants SET storage_archive_bytes=storage_archive_bytes+10, last_seq=last_seq+1
		FROM change WHERE id=change.team`)
	sql("a name", none, `UPDATE tenants SET name='Acme' FROM change WHERE id=change.team`)
	sql("the storage restarted", once, `UPDATE tenants SET storage_paused_at=NULL, storage_limit_bytes=NULL FROM change WHERE id=change.team`)

	// A move notifies the workspace it leaves and the one it reaches. The
	// member leaves first, with their key, and the owner holds the number's.
	sql("the member gone", once, `DELETE FROM device_key_grants USING change WHERE device_id=change.device AND user_id=change.member`,
		`DELETE FROM workspace_memberships USING change WHERE tenant_id=change.team AND user_id=change.member`)
	keys := store.NewKeys(a.pool)
	if err := keys.PutGrant(ctx, store.Grant{TenantID: team, DeviceID: device, UserID: owner, Epoch: 1, SealedDSK: []byte("grant")}, &owner); err != nil {
		t.Fatal(err)
	}
	expect("the owner's grant", once)
	devices := store.NewDevices(a.pool)
	if err := devices.SetPaused(ctx, team.String(), device.String(), true); err != nil {
		t.Fatal(err)
	}
	expect("a person's pause", once)
	if _, err := devices.TransferPersonal(ctx, team, owner, device, personal); err != nil {
		t.Fatal(err)
	}
	expect("a move", map[string]int{team.String(): 1, personal.String(): 1})

	// A new number, and a number gone.
	added, err := devices.Create(ctx, team.String(), "novo", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	expect("a number added", once)
	if err := devices.DeleteUnpaired(ctx, team.String(), added.ID); err != nil {
		t.Fatal(err)
	}
	expect("a number deleted", once)
}
