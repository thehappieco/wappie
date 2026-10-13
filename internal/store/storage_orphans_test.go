package store_test

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The reference checks of DeleteObject and of the orphan pass are plain
// lookups on media's stored columns (0050), and the plans prove the indexes
// serve them for the application's own role. That role is the point: under
// forced row-level security a non-leakproof qualifier is never an index
// condition for a role that does not bypass it, so an expression index over
// the content path would pass this test as a superuser and scan all of media
// in production, which is what timed the hourly pass out on the owner's
// workspace of about 17,600 objects.
func TestOrphanPassUsesIndexes(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var super, bypass bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass); err != nil {
		t.Fatal(err)
	}
	if super || bypass {
		t.Fatal("this test proves nothing as a role that bypasses row-level security")
	}

	// 18,000 attachments in one workspace, half stored under an object key
	// and half reserved under their content key, 20 objects nothing names,
	// and 2,000 more in a second workspace. Seeded with the accounting
	// triggers off, which only the speed of the seed depends on.
	seed := func(tenant uuid.UUID, n int, prefix string, orphans int) {
		t.Helper()
		dev, err := store.NewDevices(pool).Create(ctx, tenant.String(), prefix, wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`ALTER TABLE messages DISABLE TRIGGER USER`, nil},
				{`ALTER TABLE media DISABLE TRIGGER USER`, nil},
				{`ALTER TABLE storage_objects DISABLE TRIGGER USER`, nil},
				{`INSERT INTO messages(tenant_id,device_id,seq,wa_id,chat_key,kind,type,source,body_sealed)
				  SELECT $1,$2,g,'w'||g,'chat','message','image','live','\x01' FROM generate_series(1,$3::int) g`, []any{tenant, dev.ID, n}},
				{`INSERT INTO media(message_uid,tenant_id,media_type,file_enc_sha256,object_key,object_size)
				  SELECT uid,tenant_id,'image',sha256(convert_to($2||wa_id,'UTF8')),CASE WHEN seq%2=0 THEN $2||'/'||wa_id END,10
				  FROM messages WHERE tenant_id=$1`, []any{tenant, prefix}},
				{`INSERT INTO storage_objects(tenant_id,object_key,bytes)
				  SELECT tenant_id,coalesce(object_key,content_key),10 FROM media WHERE tenant_id=$1`, []any{tenant}},
				{`INSERT INTO storage_objects(tenant_id,object_key,bytes)
				  SELECT $1,$2||'/orphan-'||g,1 FROM generate_series(1,$3::int) g`, []any{tenant, prefix, orphans}},
				{`ALTER TABLE messages ENABLE TRIGGER USER`, nil},
				{`ALTER TABLE media ENABLE TRIGGER USER`, nil},
				{`ALTER TABLE storage_objects ENABLE TRIGGER USER`, nil},
				// The object charge the triggers would have kept, so a delete
				// can release one.
				{`UPDATE tenants SET storage_object_bytes=(SELECT sum(bytes) FROM storage_objects WHERE tenant_id=$1) WHERE id=$1`, []any{tenant}},
			} {
				if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
					return err
				}
			}
			return nil
		})
	}
	owner := uuid.MustParse(newTenant(t, pool, "owner"))
	other := uuid.MustParse(newTenant(t, pool, "other"))
	seed(owner, 18000, "a", 20)
	seed(other, 2000, "b", 0)
	if _, err := pool.Exec(ctx, `ANALYZE messages; ANALYZE media; ANALYZE storage_objects`); err != nil {
		t.Fatal(err)
	}

	var stored, reserved string
	inTenantTx(ctx, t, pool, owner, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT object_key FROM media WHERE object_key IS NOT NULL LIMIT 1),
			(SELECT content_key FROM media WHERE object_key IS NULL LIMIT 1)`).Scan(&stored, &reserved)
	})
	explain := func(query string, args ...any) string {
		t.Helper()
		var lines []string
		inTenantTx(ctx, t, pool, owner, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `EXPLAIN `+query, args...)
			if err != nil {
				return err
			}
			lines, err = pgx.CollectRows(rows, pgx.RowTo[string])
			return err
		})
		return strings.Join(lines, "\n")
	}
	for name, plan := range map[string]string{
		"DeleteObject's reference check": explain(store.DeleteObjectCheckQuery, owner, stored),
		"the orphan listing":             explain(store.UnreferencedObjectsQuery, owner, 1000),
	} {
		for _, want := range []string{
			"using media_object_key on media", "Index Cond: (object_key = ",
			"using media_content_key on media", "Index Cond: (content_key = ",
		} {
			if !strings.Contains(plan, want) {
				t.Errorf("%s has no %q:\n%s", name, want, plan)
			}
		}
		if strings.Contains(plan, "Seq Scan on media") {
			t.Errorf("%s scans media:\n%s", name, plan)
		}
	}

	// And they answer right: the orphans are exactly the twenty, and a key
	// still named by an attachment, either way, is never deleted.
	storage := store.NewStorage(pool)
	orphans, err := storage.UnreferencedObjects(ctx, owner, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 20 || !slices.IsSorted(orphans) || !strings.HasPrefix(orphans[0], "a/orphan-") {
		t.Fatalf("orphans: %d %v", len(orphans), orphans[:min(3, len(orphans))])
	}
	var removed atomic.Int32
	remove := func(context.Context, string) error { removed.Add(1); return nil }
	for _, key := range []string{stored, reserved} {
		if err := storage.DeleteObject(ctx, owner, key, remove); err != nil {
			t.Fatal(err)
		}
	}
	if removed.Load() != 0 {
		t.Fatal("an object an attachment names was deleted")
	}
	if err := storage.DeleteObject(ctx, owner, orphans[0], remove); err != nil || removed.Load() != 1 {
		t.Fatalf("an orphan was not deleted: %d %v", removed.Load(), err)
	}
	var left int
	if err := pg.InTenantTx(ctx, pool, owner.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM storage_objects WHERE object_key = ANY($1)`, []string{stored, reserved, orphans[0]}).Scan(&left)
	}); err != nil || left != 2 {
		t.Fatalf("objects left: %d %v", left, err)
	}
}
