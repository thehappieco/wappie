package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"strings"
	"testing"

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
	logged := &warnings{}
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
	if len(logged.lines) != 0 {
		t.Fatalf("the apply warned: %q", logged.lines)
	}
}
