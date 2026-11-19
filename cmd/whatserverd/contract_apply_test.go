package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// whatserverd contract apply (DS54; step E1): the dry run lists what would
// apply, by ids, and writes nothing in any mode; -confirm refuses until the
// mode is enforce; the flags refuse before anything is opened.

// TestContractApplyDryRun: a held person whose document lists a team they
// are not a member of, and a team Wappie lacks: one line per action, ids
// only, the count last, and no row written.
func TestContractApplyDryRun(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	gen, sub, user, personal, team, missing := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp(), generation = $1, generation_confirmed = true`, gen)
	if err := pg.InTenantTx(ctx, pool, personal.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role, auth_source)
			VALUES ($1, $2, 'ana@example.com', decode(repeat('ab', 32), 'hex'), 'owner', 'platform')`, user, personal)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, 'ana@id.test', 'new')`, sub, user)
	exec(`INSERT INTO tenants (id, name) VALUES ($1, 'Vendas')`, team)
	raw, _ := json.Marshal(map[string]any{"v": 1, "sub": sub.String(), "generation": gen.String(), "version": 1, "status": "active",
		"workspaces": []map[string]any{
			{"id": personal.String(), "kind": "personal", "role": "owner", "status": "open", "wversion": 1, "name": nil},
			{"id": team.String(), "kind": "team", "role": "admin", "status": "open", "wversion": 1, "name": "Vendas"},
			{"id": missing.String(), "kind": "team", "role": "owner", "status": "open", "wversion": 1, "name": "Norte"},
		}})
	doc := store.ContractDoc{Sub: sub, Generation: gen, Version: 1, Status: "active", Raw: raw, Workspaces: []store.ContractDocWorkspace{
		{ID: personal, Kind: "personal", Role: "owner", Status: "open", WVersion: 1},
		{ID: team, Kind: "team", Role: "admin", Status: "open", WVersion: 1},
		{ID: missing, Kind: "team", Role: "owner", Status: "open", WVersion: 1},
	}}
	if out, err := c.StoreDocuments(ctx, store.ContractAnswer, doc); err != nil || out[0] != store.ContractDocStored {
		t.Fatalf("the document: %v %v", out, err)
	}
	var before string
	sum := func() string {
		var s string
		if err := pool.QueryRow(ctx, `SELECT md5(coalesce((SELECT string_agg(to_jsonb(x)::text, ',' ORDER BY x.id) FROM tenants x), '')
			|| coalesce((SELECT string_agg(to_jsonb(a)::text, ',' ORDER BY a.sub) FROM contract_accounts a), '')
			|| coalesce((SELECT string_agg(to_jsonb(w)::text, ',' ORDER BY w.workspace_id) FROM contract_workspaces w), ''))`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before = sum()
	var out bytes.Buffer
	if err := contractApplyDryRun(ctx, c, uuid.Nil, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"team_created workspace=" + missing.String(),
		"member_added sub=" + sub.String() + " user=" + user.String() + " workspace=" + team.String() + " platform=admin",
		"personal_named workspace=" + personal.String(),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, text)
		}
	}
	if !strings.HasSuffix(text, " actions, 0 held\n") || strings.Contains(text, "@") || strings.Contains(text, "Vendas") {
		t.Fatalf("the dry run:\n%s", text)
	}
	out.Reset()
	if err := contractApplyDryRun(ctx, c, sub, &out); err != nil || !strings.Contains(out.String(), "member_added") {
		t.Fatalf("the dry run of one sub: %v\n%s", err, out.String())
	}
	if sum() != before {
		t.Fatal("the dry run wrote")
	}
}

// TestContractApplyRefusesBeforeEnforce: -confirm at off and at observe
// refuses with ErrApplyNeedsEnforce and writes nothing; the flags refuse
// before anything is opened.
func TestContractApplyRefusesBeforeEnforce(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	for _, mode := range []string{"off", "observe"} {
		if mode == "observe" {
			if _, err := pool.Exec(ctx, `UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp()`); err != nil {
				t.Fatal(err)
			}
		}
		var out bytes.Buffer
		if err := contractApplyConfirm(ctx, c, 0, &out); !errors.Is(err, store.ErrApplyNeedsEnforce) || out.Len() != 0 {
			t.Fatalf("-confirm 0 at %s: %v, %q", mode, err, out.String())
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "contract apply: give -dry-run [-sub S], or -confirm N"},
		{[]string{"-dry-run", "-confirm", "3"}, "contract apply: -dry-run and -confirm are exclusive"},
		{[]string{"-confirm", "3", "-sub", uuid.NewString()}, "contract apply: -sub goes with -dry-run"},
		{[]string{"-dry-run", "-sub", "nope"}, "contract apply: -sub takes a sub"},
	} {
		if err := contractApplyCommand(c.args, io.Discard); err == nil || err.Error() != c.want {
			t.Errorf("contract apply %v: %v, want %q", c.args, err, c.want)
		}
	}
}
