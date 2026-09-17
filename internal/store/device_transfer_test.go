package store_test

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func transferOwner(t *testing.T, a *archive, role string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	u, err := store.NewUsers(a.pool).Create(context.Background(), store.NewUser{TenantID: a.tenant, Email: uuid.NewString() + "@example.test", Role: role, AuthKey: "test", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	var personal uuid.UUID
	if err = a.pool.QueryRow(context.Background(), `SELECT id FROM tenants WHERE personal_owner_id=$1`, u.ID).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	return u.ID, personal
}

func TestMovePersonalPreservesArchiveAndRevokesSourceAccess(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	d := store.NewDevices(a.pool)
	owner, target := transferOwner(t, a, "owner")
	uid := a.insert(t, row{ts: time.Now(), chat: "friend", object: "original/object"})
	// Destination already has journal entries: moving must remap sequence numbers.
	other, err := d.Create(ctx, target.String(), "existing", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	dst := &archive{pool: a.pool, tenant: target, device: uuid.MustParse(other.ID), messages: a.messages, media: a.media}
	dst.insert(t, row{ts: time.Now(), chat: "existing"})
	before, err := store.NewStorage(a.pool).Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := d.PreviewPersonalTransfer(ctx, a.tenant, owner, a.device)
	if err != nil || !preview.Eligible || preview.TargetWorkspaceID != target.String() {
		t.Fatalf("preview %+v %v", preview, err)
	}
	if err = d.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err = d.TransferPersonal(ctx, a.tenant, owner, a.device, target); err != nil {
		t.Fatal(err)
	}
	moved, err := d.Get(ctx, target.String(), a.device.String())
	if err != nil {
		t.Fatal(err)
	}
	if moved.ArchiveTenantID != a.tenant.String() || !moved.Paused || moved.Label != "phone" {
		t.Fatalf("moved %+v", moved)
	}
	if _, err = d.Get(ctx, a.tenant.String(), a.device.String()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("source still sees device %v", err)
	}
	if err = pg.InTenantTx(ctx, a.pool, target.String(), func(tx pgx.Tx) error {
		var body []byte
		var object string
		var seq int64
		if e := tx.QueryRow(ctx, `SELECT m.body_sealed,d.object_key,m.seq FROM messages m JOIN media d ON d.message_uid=m.uid WHERE m.uid=$1`, uid).Scan(&body, &object, &seq); e != nil {
			return e
		}
		if string(body) != string([]byte{1}) || object != "original/object" || seq <= 1 {
			t.Fatalf("archive changed: %v %s %d", body, object, seq)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sourceAfter, err := store.NewStorage(a.pool).Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if sourceAfter.UsedBytes != 0 {
		t.Fatalf("source charged after move %+v (before %+v)", sourceAfter, before)
	}
	usage, err := store.NewStorage(a.pool).Usage(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := store.NewStorage(a.pool).Reconcile(ctx, target)
	if err != nil || reconciled.UsedBytes != usage.UsedBytes {
		t.Fatalf("ledger drift %+v %+v %v", usage, reconciled, err)
	}
	// An old queued writer must never recreate Team rows under the moved device.
	err = pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO contacts(tenant_id,device_id,contact_key) VALUES($1,$2,'stale')`, a.tenant, a.device)
		return e
	})
	if err == nil {
		t.Fatal("stale source write accepted")
	}
}

func TestMovePersonalRejectsAnotherOwnerAndCapacityWithoutPartialChanges(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	d := store.NewDevices(a.pool)
	owner, target := transferOwner(t, a, "owner")
	a.insert(t, row{ts: time.Now(), chat: "one"})
	second, _ := transferOwner(t, a, "owner")
	preview, err := d.PreviewPersonalTransfer(ctx, a.tenant, owner, a.device)
	if err != nil || preview.Eligible {
		t.Fatalf("second owner %+v %v", preview, err)
	}
	if err = pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM workspace_memberships WHERE user_id=$1`, second)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = d.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if err = pg.InTenantTx(ctx, a.pool, target.String(), func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO workspace_capacity(tenant_id,max_devices) VALUES($1,0)`, target)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.TransferPersonal(ctx, a.tenant, owner, a.device, target); err == nil {
		t.Fatal("capacity bypass")
	}
	if _, err = d.Get(ctx, a.tenant.String(), a.device.String()); err != nil {
		t.Fatal("failed move changed owner", err)
	}
	if a.count(t, "messages") != 1 {
		t.Fatal("failed move changed archive")
	}
	if _, err = d.TransferPersonal(ctx, a.tenant, owner, a.device, uuid.New()); err == nil {
		t.Fatal("arbitrary target accepted")
	}
}

func TestMovePersonalSerializesTheLastSlotAndHonorsSupervisorLock(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	d := store.NewDevices(a.pool)
	owner, target := transferOwner(t, a, "owner")
	second, err := d.Create(ctx, a.tenant.String(), "second", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{a.device.String(), second.ID} {
		if err = d.SetPaused(ctx, a.tenant.String(), id, true); err != nil {
			t.Fatal(err)
		}
	}
	if err = pg.InTenantTx(ctx, a.pool, target.String(), func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO workspace_capacity(tenant_id,max_devices) VALUES($1,1)`, target)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	release, ok, err := pg.NewLocker(a.pool).TryLock(ctx, "device:"+a.device.String())
	if err != nil || !ok {
		t.Fatalf("lock %v %v", ok, err)
	}
	if _, err = d.TransferPersonal(ctx, a.tenant, owner, a.device, target); err == nil {
		release()
		t.Fatal("running supervisor ignored")
	}
	release()
	results := make(chan error, 2)
	for _, id := range []uuid.UUID{a.device, uuid.MustParse(second.ID)} {
		go func(device uuid.UUID) {
			_, err := d.TransferPersonal(ctx, a.tenant, owner, device, target)
			results <- err
		}(id)
	}
	passed := 0
	for range 2 {
		if <-results == nil {
			passed++
		}
	}
	if passed != 1 {
		t.Fatalf("last slot assigned %d times", passed)
	}
	list, err := d.List(ctx, target.String())
	if err != nil || len(list) != 1 {
		t.Fatalf("target devices %+v %v", list, err)
	}
}

func TestMovePersonalStorageLimitLeavesSourceIntact(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	d := store.NewDevices(a.pool)
	owner, target := transferOwner(t, a, "owner")
	a.insert(t, row{ts: time.Now(), chat: "full archive", object: "large-object"})
	limit := int64(1)
	if err := store.NewStorage(a.pool).SetLimit(ctx, target, &limit); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.TransferPersonal(ctx, a.tenant, owner, a.device, target); err == nil {
		t.Fatal("storage capacity ignored")
	}
	if a.count(t, "messages") != 1 || a.count(t, "media") != 1 {
		t.Fatal("archive partially moved")
	}
	list, err := d.List(ctx, target.String())
	if err != nil || len(list) != 0 {
		t.Fatalf("target %+v %v", list, err)
	}
}
