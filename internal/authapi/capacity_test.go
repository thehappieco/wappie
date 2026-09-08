package authapi_test

import (
	"context"
	"github.com/jackc/pgx/v5"
	"sync"
	"testing"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func TestCapacitySerializesConcurrentPairing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, _ := memberAccount(t, h, "capacity@test.com", "owner")
	if err := pg.InTenantTx(ctx, h.pool, h.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO workspace_capacity(tenant_id,max_devices) VALUES($1,2)`, h.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.NewDevices(h.pool).Create(ctx, h.tenant.String(), "phone", wa.ModePassive)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 2 {
		t.Fatalf("created %d want 2", success)
	}
	c, err := h.users.Capacity(ctx, h.tenant, owner.ID)
	if err != nil || c.UsedDevices != 2 || c.MaxDevices == nil || *c.MaxDevices != 2 {
		t.Fatalf("capacity=%+v err=%v", c, err)
	}
}
