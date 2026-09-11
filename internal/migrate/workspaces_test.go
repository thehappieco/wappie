package migrate

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
)

func TestWorkspaceMigrationPreservesExistingIdentities(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Empty(t)
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var before []Migration
	for _, m := range ms {
		if m.Version < 21 {
			before = append(before, m)
		}
	}
	if err := run(ctx, pool, quietLogger(t), before); err != nil {
		t.Fatal(err)
	}
	type saved struct {
		tenant, user uuid.UUID
		role         string
	}
	var originals []saved
	for _, role := range []string{"owner", "member", "service"} {
		s := saved{role: role}
		if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ($1) RETURNING id`, role).Scan(&s.tenant); err != nil {
			t.Fatal(err)
		}
		if err := pg.InTenantTx(ctx, pool, s.tenant.String(), func(tx pgx.Tx) error {
			if role == "service" {
				return tx.QueryRow(ctx, `INSERT INTO users(tenant_id,email,public_key,role)
				VALUES ($1,$2,decode(repeat('ab',32),'hex'),'service') RETURNING id`, s.tenant, role+"@example.com").Scan(&s.user)
			}
			return tx.QueryRow(ctx, `INSERT INTO users(tenant_id,email,auth_hash,kdf_salt,kdf_params,public_key,wrapped_usk,role)
				VALUES ($1,$2,'existing-hash',decode(repeat('cd',16),'hex'),'{}',decode(repeat('ab',32),'hex'),'existing-wrap',$3) RETURNING id`, s.tenant, role+"@example.com", role).Scan(&s.user)
		}); err != nil {
			t.Fatal(err)
		}
		originals = append(originals, s)
	}
	if err := run(ctx, pool, quietLogger(t), ms); err != nil {
		t.Fatal(err)
	}
	for _, s := range originals {
		if err := pg.InTenantTx(ctx, pool, s.tenant.String(), func(tx pgx.Tx) error {
			var role, pub string
			var hash, wrap *string
			err := tx.QueryRow(ctx, `SELECT m.role,encode(u.public_key,'hex'),u.auth_hash,convert_from(u.wrapped_usk,'UTF8')
				FROM workspace_memberships m JOIN users u ON u.id = m.user_id WHERE m.tenant_id = $1 AND u.id = $2`, s.tenant, s.user).Scan(&role, &pub, &hash, &wrap)
			if err != nil {
				return err
			}
			if role != s.role || len(pub) != 64 {
				t.Fatalf("identity changed: %s %s", role, pub)
			}
			if s.role != "service" && (hash == nil || *hash != "existing-hash" || wrap == nil || *wrap != "existing-wrap") {
				t.Fatal("credentials replaced")
			}
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM workspace_memberships`).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				t.Fatalf("RLS exposed %d memberships", count)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	for _, original := range originals {
		var kind string
		if err := pool.QueryRow(ctx, `SELECT kind FROM tenants WHERE id=$1`, original.tenant).Scan(&kind); err != nil || kind != "team" {
			t.Fatalf("existing workspace changed type: %s %v", kind, err)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE kind='personal' AND personal_owner_id=$1`, original.user).Scan(&count); err != nil {
			t.Fatal(err)
		}
		want := 1
		if original.role == "service" {
			want = 0
		}
		if count != want {
			t.Fatalf("%s personal workspaces=%d want=%d", original.role, count, want)
		}
		if want == 1 {
			var personal uuid.UUID
			if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, original.user).Scan(&personal); err != nil {
				t.Fatal(err)
			}
			if err := pg.InTenantTx(ctx, pool, personal.String(), func(tx pgx.Tx) error {
				var role, status string
				err := tx.QueryRow(ctx, `SELECT role,status FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2`, personal, original.user).Scan(&role, &status)
				if err == nil && (role != "owner" || status != "active") {
					t.Fatalf("invalid personal membership %s %s", role, status)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM workspace_memberships`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("membership visibility leaked out of tenant transaction")
	}
}
