package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// whatserverd tokens retire-keys (step 7's plan, 7.2): its flags, the dry
// run's lines (per key its prefix and the service it acts as, which the
// platform relays to the owner), and the apply's.
func TestRetireKeysCommand(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{
		{"retire-keys"}, {"retire-keys", "-dry-run", "-apply"}, {"retire-keys", "-apply"}, {"retire-keys", "-dry-run", "-confirm", "1"},
		{"retire-keys", "-dry-run", "extra"}, {"retire-keys", "-apply", "-confirm", "-2"},
	} {
		if err := tokensCommand(args, strings.NewReader(""), &out); err == nil || !strings.Contains(err.Error(), "retire-keys") {
			t.Errorf("%q: %v", args, err)
		}
	}

	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('Piloto A') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	users := store.NewUsers(pool)
	owner, err := users.Create(ctx, store.NewUser{TenantID: tenant, Email: "owner@acme.test", Role: "owner", AuthKey: "test",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := users.NewMemberInvitation(ctx, tenant, owner.ID, store.RoleService, "")
	if err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	if _, err := rand.Read(pub); err != nil {
		t.Fatal(err)
	}
	erp, err := users.SignupService(ctx, secret, "erp", pub)
	if err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(pool)
	key, err := keys.IssueActingAsForDevices(ctx, tenant.String(), "orders", store.ScopeRead, &owner.ID, &erp.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(key, ".")
	logged := &everyLine{}
	a := &app{log: slog.New(logged), pools: &pg.Pools{Live: pool, History: pool, API: pool}}

	if err := retireKeys(ctx, a, false, -1, &out); err == nil || !strings.Contains(err.Error(), "tokens on") {
		t.Fatalf("with tokens off: %v", err)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode = 'observe', events_from = coalesce(events_from, clock_timestamp()), events_paused_at = NULL`)
	execSQL(t, pool, `UPDATE contract_token_state SET mode = 'on'`)
	out.Reset()
	if err := retireKeys(ctx, a, false, -1, &out); err != nil {
		t.Fatal(err)
	}
	dry := out.String()
	for _, want := range []string{"dry run, nothing written", `workspace ` + tenant.String() + ` "Piloto A"`,
		"key " + prefix + "  revoke  class rest  scope read  name \"orders\"  acts as erp  creator owner@acme.test  last used never",
		"service erp (" + erp.ID.String() + ")  remove", "keys to revoke: 1;", "apply with: whatserverd tokens retire-keys -apply -confirm 1"} {
		if !strings.Contains(dry, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, dry)
		}
	}
	if err := retireKeys(ctx, a, true, 2, &out); err == nil || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("a wrong count: %v", err)
	}
	out.Reset()
	if err := retireKeys(ctx, a, true, 1, &out); err != nil {
		t.Fatal(err)
	}
	if done := out.String(); !strings.Contains(done, "key "+prefix+"  revoked") || !strings.Contains(done, "revoked 1 keys; removed 1 service") {
		t.Fatalf("the apply:\n%s", done)
	}
	// The log holds the prefix and the service's name, never a key's name
	// or a creator.
	if len(logged.lines) != 1 || logged.lines[0] != "api keys retired revoked=1 prefixes=["+prefix+"] services_removed=[erp] services_kept=[]" {
		t.Fatalf("the apply's log: %q", logged.lines)
	}
}

// everyLine is every log line of a test's, with its attributes.
type everyLine struct{ warnings }

func (l *everyLine) Handle(_ context.Context, r slog.Record) error {
	line := r.Message
	r.Attrs(func(a slog.Attr) bool { line += fmt.Sprintf(" %s=%v", a.Key, a.Value); return true })
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
	return nil
}

func (l *everyLine) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *everyLine) WithGroup(string) slog.Handler      { return l }

// TestMaintainOnceDeletesEndedKeys (step 7's plan, 7.6): the hourly pass
// deletes a key whose end is 13 months past, right after the expiry pass,
// whatever the token mode, and keeps one ended less long ago; a key past
// its 13 months whose connection is still active is kept with a WARN.
func TestMaintainOnceDeletesEndedKeys(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var tenant, owner uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	u, err := store.NewUsers(pool).Create(ctx, store.NewUser{TenantID: tenant, Email: "owner@acme.test", Role: "owner", AuthKey: "test",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	owner = u.ID
	var held uuid.UUID
	for _, k := range []struct{ prefix, revoked string }{
		{"0000000a", `clock_timestamp() - interval '14 months'`},
		{"0000000b", `clock_timestamp() - interval '12 months'`},
		{"0000000c", `clock_timestamp() - interval '14 months'`},
	} {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, name, revoked_at, created_by, origin)
			VALUES ($1, $2, 'x', $2, `+k.revoked+`, $3, 'rest') RETURNING id`, tenant, k.prefix, owner).Scan(&id); err != nil {
			t.Fatal(err)
		}
		held = id
	}
	execSQL(t, pool, `INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host,
		device_count, reader_kid, status, expires_at) VALUES ($1, 'r', $2, $3, 'Claude', 'claude.ai', 1, '0123456789abcdef', 'active',
		clock_timestamp() + interval '1 day')`, tenant, held, owner)

	logged := &warnings{}
	a := &app{log: slog.New(logged), pools: &pg.Pools{Live: pool, History: pool, API: pool}, storage: store.NewStorage(pool)}
	a.maintainOnce(ctx, 30*24*time.Hour, &fakeObjects{})
	rows, err := pool.Query(ctx, `SELECT prefix FROM api_keys ORDER BY prefix`)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		left = append(left, p)
	}
	if rows.Err() != nil || strings.Join(left, ",") != "0000000b,0000000c" {
		t.Fatalf("the keys after the pass: %v %v", left, rows.Err())
	}
	if len(logged.lines) != 1 || !strings.HasPrefix(logged.lines[0], "ended api keys kept: their connection has not ended keys=1") {
		t.Fatalf("the pass's warnings: %q", logged.lines)
	}
}
