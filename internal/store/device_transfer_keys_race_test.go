package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

func TestPersonalTransferSerializesContentKeyCreation(t *testing.T) {
	a := newArchive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	owner, personal := transferOwner(t, a, "owner")
	keys := store.NewKeys(a.pool)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.CreateArchiveKey(ctx, a.tenant, a.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	if err := keys.PutGrant(ctx, store.Grant{TenantID: a.tenant, DeviceID: a.device, UserID: owner, Epoch: 1, SealedDSK: []byte("owner")}, &owner); err != nil {
		t.Fatal(err)
	}
	devices := store.NewDevices(a.pool)
	if err := devices.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}

	// A transfer takes this same workspace lock before changing ownership.
	// Keep it held while a previous sealing job reaches its content-key INSERT.
	blocker, err := a.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `SELECT id FROM tenants WHERE id=$1 FOR UPDATE`, a.tenant); err != nil {
		t.Fatal(err)
	}
	blockerPID := blocker.Conn().PgConn().PID()
	waitBlocked := func(count int) {
		t.Helper()
		for {
			var waiting int
			if err := a.pool.QueryRow(ctx, `WITH RECURSIVE waiting(pid) AS (
				SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
				UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid=ANY(pg_blocking_pids(a.pid))
			) SELECT count(*) FROM waiting`, blockerPID).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting >= count {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("operations did not reach controlled content-key race")
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	// Queue the move first. An old writer's FK lock alone is too late: the
	// ownership row trigger has already run, and the INSERT may resume after
	// the move scanned the table. The statement trigger must block before it.
	moved := make(chan error, 1)
	go func() { _, err := devices.TransferPersonal(ctx, a.tenant, owner, a.device, personal); moved <- err }()
	waitBlocked(1)
	ready := make(chan struct{})
	type keyResult struct {
		id  uint32
		err error
	}
	created := make(chan keyResult, 1)
	go func() {
		id, err := keys.CreateContentKey(ctx, a.tenant, a.device, 1, func(id uint32) ([]byte, error) {
			close(ready)
			return []byte("sealed key"), nil
		})
		created <- keyResult{id, err}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitBlocked(2)
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var result keyResult
	select {
	case result = <-created:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-moved:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// Either the old writer finishes before the move, or its old workspace is
	// rejected after it. Neither schedule may leave an inaccessible key behind.
	var sourceCount int
	if err := pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM content_keys WHERE device_id=$1`, a.device).Scan(&sourceCount)
	}); err != nil {
		t.Fatal(err)
	}
	if sourceCount != 0 {
		t.Fatalf("%d keys retained obsolete workspace ownership", sourceCount)
	}
	if result.err == nil {
		if _, err := keys.SealedContentKey(ctx, personal, a.device, result.id); err != nil {
			t.Fatalf("completed key was not moved: %v", err)
		}
	}
	archive, err := keys.ArchiveTenant(ctx, personal, a.device)
	if err != nil || archive == uuid.Nil {
		t.Fatalf("moved archive: %s %v", archive, err)
	}
}
