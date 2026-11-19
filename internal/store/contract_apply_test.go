package store_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Applying the stored documents at enforce (DS54; step E1). 0051's CHECK
// holds no enforce until E2, so these tests run each apply past its mode
// gate (export_test.go's ForTest hooks), every other check and lock the
// same; TestApplyRefusesBeforeEnforce holds the gate itself.

// applyWorld is a contract at observe holding a confirmed generation.
type applyWorld struct {
	pool *pgxpool.Pool
	c    *store.Contract
	gen  uuid.UUID
	ver  map[uuid.UUID]int64
	pns  int
}

func newApplyWorld(t *testing.T) *applyWorld {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	w := &applyWorld{pool: pool, c: store.NewContract(pool), gen: uuid.New(), ver: map[uuid.UUID]int64{}}
	w.exec(t, `UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp(), generation = $1, generation_confirmed = true`, w.gen)
	return w
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func (w *applyWorld) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := w.pool.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// in runs fn in tenant's scope with deleted numbers visible.
func (w *applyWorld) in(t *testing.T, tenant uuid.UUID, fn func(pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()
	inTenantTx(ctx, t, w.pool, tenant, func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error { return fn(tx) })
	})
}

// count is one count(*) in tenant's scope.
func (w *applyWorld) count(t *testing.T, tenant uuid.UUID, q string, args ...any) int {
	t.Helper()
	var n int
	w.in(t, tenant, func(tx pgx.Tx) error { return tx.QueryRow(context.Background(), q, args...).Scan(&n) })
	return n
}

// applyPerson is a person Wappie holds: their account, sub and personal
// workspace (the platform's id).
type applyPerson struct{ user, sub, personal uuid.UUID }

func (w *applyWorld) person(t *testing.T) applyPerson {
	t.Helper()
	ctx := context.Background()
	p := applyPerson{user: uuid.New(), sub: uuid.New(), personal: uuid.New()}
	inTenantTx(ctx, t, w.pool, p.personal, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role, auth_source) VALUES ($1, $2, $3, $4, 'owner', 'platform')`,
			p.user, p.personal, p.user.String()[:8]+"@example.com", randBytes(t, 32))
		return err
	})
	w.exec(t, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'new')`,
		p.sub, p.user, p.sub.String()[:8]+"@id.test")
	return p
}

type applyMember struct {
	user         uuid.UUID
	role, status string
}

// team is Wappie's own team with these members.
func (w *applyWorld) team(t *testing.T, name string, members ...applyMember) uuid.UUID {
	t.Helper()
	id := uuid.New()
	w.exec(t, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, id, name)
	w.join(t, id, members...)
	return id
}

func (w *applyWorld) join(t *testing.T, tenant uuid.UUID, members ...applyMember) {
	t.Helper()
	w.in(t, tenant, func(tx pgx.Tx) error {
		for _, m := range members {
			if m.status == "" {
				m.status = "active"
			}
			if _, err := tx.Exec(context.Background(), `INSERT INTO workspace_memberships (tenant_id, user_id, role, status) VALUES ($1, $2, $3, $4)`,
				tenant, m.user, m.role, m.status); err != nil {
				return err
			}
		}
		return nil
	})
}

// docTeam is a team a document lists.
type docTeam struct {
	id       uuid.UUID
	role     string
	status   string
	wversion int64
	name     *string
}

// docSpec is a document beside its teams.
type docSpec struct {
	status                    string
	disabled, sessions, creds *time.Time
	personal                  *uuid.UUID
	personalName              *string
	teams                     []docTeam
	noPersonal                bool
}

func strp(s string) *string { return &s }

// put stores sub's next document as an answer.
func (w *applyWorld) put(t *testing.T, p applyPerson, spec docSpec) store.ContractDoc {
	t.Helper()
	w.ver[p.sub]++
	if spec.status == "" {
		spec.status = "active"
	}
	personal := p.personal
	if spec.personal != nil {
		personal = *spec.personal
	}
	type ws struct {
		ID       string  `json:"id"`
		Kind     string  `json:"kind"`
		Role     string  `json:"role"`
		Status   string  `json:"status"`
		WVersion int64   `json:"wversion"`
		Name     *string `json:"name"`
	}
	d := store.ContractDoc{Sub: p.sub, Generation: w.gen, Version: w.ver[p.sub], Status: spec.status,
		DisabledAt: spec.disabled, SessionsRevokedAt: spec.sessions, CredentialsRevokedAt: spec.creds}
	var raw []ws
	if spec.status != "closed" {
		if !spec.noPersonal {
			d.Workspaces = append(d.Workspaces, store.ContractDocWorkspace{ID: personal, Kind: "personal", Role: "owner", Status: "open", WVersion: 1})
			raw = append(raw, ws{personal.String(), "personal", "owner", "open", 1, spec.personalName})
		}
		for _, team := range spec.teams {
			if team.status == "" {
				team.status = "open"
			}
			if team.wversion == 0 {
				team.wversion = 1
			}
			d.Workspaces = append(d.Workspaces, store.ContractDocWorkspace{ID: team.id, Kind: "team", Role: team.role, Status: team.status,
				WVersion: team.wversion})
			raw = append(raw, ws{team.id.String(), "team", team.role, team.status, team.wversion, team.name})
		}
	}
	if raw == nil {
		raw = []ws{}
	}
	d.Raw, _ = json.Marshal(map[string]any{"v": 1, "sub": p.sub.String(), "generation": w.gen.String(), "version": d.Version,
		"status": spec.status, "workspaces": raw})
	if out := storeDocs(t, w.c, store.ContractAnswer, d); out[0] != store.ContractDocStored {
		t.Fatalf("the document of %s was %s", p.sub, out[0])
	}
	return d
}

// apply runs sub's whole apply past the gate.
func (w *applyWorld) apply(t *testing.T, p applyPerson) store.ApplyResult {
	t.Helper()
	r, err := w.c.ApplyForTest(context.Background(), p.sub)
	if err != nil {
		t.Fatalf("apply %s: %v", p.sub, err)
	}
	return r
}

// membership is user's role and status in tenant, "" for none.
func (w *applyWorld) membership(t *testing.T, tenant, user uuid.UUID) (role, status string) {
	t.Helper()
	w.in(t, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(context.Background(), `SELECT role, status FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2`,
			tenant, user).Scan(&role, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return role, status
}

// number is a linked number of tenant with its archive key at epoch 1.
func (w *applyWorld) number(t *testing.T, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	w.pns++
	device := linkedNumber(t, w.pool, tenant, "Vendas", fmt.Sprintf("55119%04d1234", w.pns), fmt.Sprintf("2000000%08d", w.pns))
	w.in(t, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key)
			VALUES ($1, $2, 1, decode(repeat('ab', 32), 'hex'))`, tenant, device)
		return err
	})
	return device
}

// reads gives user device's grant and Read.
func (w *applyWorld) reads(t *testing.T, tenant, device, user uuid.UUID) {
	t.Helper()
	w.in(t, tenant, func(tx pgx.Tx) error {
		ctx := context.Background()
		if _, err := tx.Exec(ctx, `INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk, granted_by)
			VALUES ($1, $2, $3, 1, '\x01', $3)`, tenant, device, user); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_permissions (tenant_id, device_id, user_id, can_read) VALUES ($1, $2, $3, true)
			ON CONFLICT (tenant_id, device_id, user_id) DO UPDATE SET can_read = true`, tenant, device, user)
		return err
	})
}

// session is a live session of user in tenant made at at, in family (a
// new one for Nil).
func (w *applyWorld) session(t *testing.T, user, tenant uuid.UUID, at time.Time, family uuid.UUID) uuid.UUID {
	t.Helper()
	if family == uuid.Nil {
		family = uuid.New()
	}
	var id uuid.UUID
	if err := w.pool.QueryRow(context.Background(), `INSERT INTO sessions (user_id, tenant_id, token_hash, expires_at, created_at, family_id)
		VALUES ($1, $2, $3, clock_timestamp() + interval '1 day', $4, $5) RETURNING id`, user, tenant, randBytes(t, 32), at, family).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (w *applyWorld) revoked(t *testing.T, table string, id uuid.UUID) bool {
	t.Helper()
	var r bool
	if err := w.pool.QueryRow(context.Background(), `SELECT revoked_at IS NOT NULL FROM `+table+` WHERE id = $1`, id).Scan(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

// key is a live API key of tenant made by user at at, acting as actsAs
// unless Nil.
func (w *applyWorld) key(t *testing.T, tenant, user, actsAs uuid.UUID, at time.Time) uuid.UUID {
	t.Helper()
	var by, as *uuid.UUID
	if user != uuid.Nil {
		by = &user
	}
	if actsAs != uuid.Nil {
		as = &actsAs
	}
	var id uuid.UUID
	if err := w.pool.QueryRow(context.Background(), `INSERT INTO api_keys (tenant_id, prefix, key_hash, name, created_by, acts_as, created_at)
		VALUES ($1, $2, 'x', 'k', $3, $4, $5) RETURNING id`, tenant, strings.ReplaceAll(uuid.NewString()[:8], "-", "0"), by, as, at).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// connection is a live MCP connection of tenant made by user at at, with
// its own key.
func (w *applyWorld) connection(t *testing.T, tenant, user uuid.UUID, at time.Time) uuid.UUID {
	t.Helper()
	k := w.key(t, tenant, user, uuid.Nil, at)
	var id uuid.UUID
	w.in(t, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host,
			device_count, reader_kid, status, expires_at, created_at)
			VALUES ($1, $2, $3, $4, 'Claude', 'claude.ai', 1, '0123456789abcdef', 'active', clock_timestamp() + interval '1 day', $5) RETURNING id`,
			tenant, uuid.NewString(), k, user, at).Scan(&id)
	})
	return id
}

// keychain is a live AI keychain item of user in tenant made at at.
func (w *applyWorld) keychain(t *testing.T, tenant, user uuid.UUID, at time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	w.in(t, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO ai_keychain (id, tenant_id, user_id, provider, label, suffix, envelope, created_at)
			VALUES ($1, $2, $3, 'anthropic', 'Chave', 'abcd', '\x01', $4)`, id, tenant, user, at)
		return err
	})
	return id
}

// service is a standing service account of tenant that user invited at
// at.
func (w *applyWorld) service(t *testing.T, tenant, user uuid.UUID, at time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	w.in(t, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO users (id, tenant_id, email, public_key, role) VALUES ($1, $2, $3, $4, 'service')`,
			id, tenant, id.String()[:8]+"@service.test", randBytes(t, 32))
		return err
	})
	w.exec(t, `INSERT INTO invites (invite_id, tenant_id, role, created_by, expires_at, claimed_by, claimed_at, completed_at, created_at)
		VALUES ($1, $2, 'service', $3, $4::timestamptz + interval '1 day', $5, $4, $4, $4)`, randBytes(t, 32), tenant, user, at, id)
	return id
}

// markers is an account's applied markers.
func (w *applyWorld) markers(t *testing.T, sub uuid.UUID) (version *int64, held *string) {
	t.Helper()
	if err := w.pool.QueryRow(context.Background(), `SELECT applied_version, apply_held FROM contract_accounts WHERE sub = $1`, sub).
		Scan(&version, &held); err != nil {
		t.Fatal(err)
	}
	return version, held
}

// at is the database's clock moved by offset.
func (w *applyWorld) at(t *testing.T, offset string) time.Time { return dbClock(t, w.pool, offset) }

// checksum is every row an apply may write, each workspace's under its own
// scope, as one hash.
func (w *applyWorld) checksum(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	var b strings.Builder
	err := pgx.BeginTxFunc(ctx, w.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		agg := func(table string) error {
			var s string
			if err := tx.QueryRow(ctx, `SELECT coalesce(md5(string_agg(to_jsonb(x)::text, E'\n' ORDER BY to_jsonb(x)::text)), '') FROM `+table+` x`).
				Scan(&s); err != nil {
				return err
			}
			b.WriteString(table + " " + s + "\n")
			return nil
		}
		for _, table := range []string{"tenants", "sessions", "api_keys", "mcp_connections", "invites", "contract_accounts", "contract_workspaces",
			"contract_closings"} {
			if err := agg(table); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
		if err != nil {
			return err
		}
		tenants, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, id := range tenants {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.device_quarantine', 'on', true)`, id.String()); err != nil {
				return err
			}
			for _, table := range []string{"users", "workspace_memberships", "device_key_grants", "device_permissions", "ai_keychain",
				"workspace_member_history", "devices", "item_events", "device_notices"} {
				if err := agg(table); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// stable is a checksum without the contract's own bookkeeping, which every
// pass writes (apply_last_at, a snapshot made due).
func stable(sum string) string {
	var out []string
	for _, line := range strings.Split(sum, "\n") {
		if !strings.HasPrefix(line, "contract_accounts ") && !strings.HasPrefix(line, "contract_workspaces ") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func kinds(r store.ApplyResult) []string {
	var out []string
	for _, a := range r.Actions {
		out = append(out, a.Kind)
	}
	return out
}

func has(r store.ApplyResult, kind string) bool {
	for _, a := range r.Actions {
		if a.Kind == kind {
			return true
		}
	}
	return false
}

// The gate: off and observe refuse every apply, and nothing is written.
func TestApplyRefusesBeforeEnforce(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	owner, p := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""})
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}}})
	w.put(t, p, docSpec{teams: []docTeam{{id: team, role: "member"}}})
	before := w.checksum(t)
	for _, mode := range []string{"observe", "off"} {
		if mode == "off" {
			w.exec(t, `UPDATE contract_state SET mode = 'off', events_paused_at = clock_timestamp()`)
		}
		for name, call := range map[string]func() error{
			"ApplyAccount":   func() error { _, err := w.c.ApplyAccount(ctx, p.sub); return err },
			"ApplyWorkspace": func() error { _, err := w.c.ApplyWorkspace(ctx, team); return err },
			"EnsureTeams":    func() error { _, err := w.c.EnsureTeams(ctx, p.sub); return err },
			"ConfirmClosing": func() error {
				_, err := w.c.ConfirmClosing(ctx, p.sub, store.ContractDoc{Sub: p.sub, Generation: w.gen, Status: "closed"})
				return err
			},
			"ForgetClosed":        func() error { _, _, err := w.c.ForgetClosed(ctx, p.sub); return err },
			"SweepOrphanServices": func() error { _, err := w.c.SweepOrphanServices(ctx); return err },
		} {
			if err := call(); !errors.Is(err, store.ErrApplyNeedsEnforce) {
				t.Errorf("%s at %s: %v, want ErrApplyNeedsEnforce", name, mode, err)
			}
		}
	}
	w.exec(t, `UPDATE contract_state SET mode = 'observe', events_paused_at = NULL`)
	if after := w.checksum(t); after != before {
		t.Fatalf("a refused apply wrote:\n%s\nwas\n%s", after, before)
	}
	if role, _ := w.membership(t, team, p.user); role != "" {
		t.Fatalf("a refused apply added the membership: %s", role)
	}
}

// The dry run lists the actions and writes nothing, the plan of one sub and
// of everything alike.
func TestApplyDryRunWritesNothing(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	owner, p := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""})
	missing := uuid.New()
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}, {id: missing, role: "owner", name: strp("Nova")}}})
	w.put(t, p, docSpec{teams: []docTeam{{id: team, role: "admin"}}})
	before := w.checksum(t)
	plan, err := w.c.PlanAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actions, held := plan.Actions()
	if actions == 0 || held != 0 {
		t.Fatalf("the plan: %d actions, %d held: %+v", actions, held, plan)
	}
	var created, added bool
	for _, r := range append(plan.Workspaces, plan.Accounts...) {
		created = created || has(r, store.ApplyTeamCreated)
		added = added || has(r, store.ApplyMemberAdded)
	}
	if !created || !added {
		t.Fatalf("the plan has no team_created (%v) or member_added (%v): %+v", created, added, plan)
	}
	one, err := w.c.PlanAccount(ctx, p.sub)
	if err != nil || len(one.Accounts) != 1 || !has(one.Accounts[0], store.ApplyMemberAdded) {
		t.Fatalf("the plan of one sub: %+v %v", one, err)
	}
	if after := w.checksum(t); after != before {
		t.Fatalf("a dry run wrote:\n%s\nwas\n%s", after, before)
	}
}

// A membership the document lists and Wappie lacks is added with its role;
// the workspace's snapshot is due now and the markers say what applied.
func TestApplyAddsMembershipFromDocument(t *testing.T) {
	w := newApplyWorld(t)
	owner, p := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""})
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}}})
	d := w.put(t, p, docSpec{teams: []docTeam{{id: team, role: "admin"}}})
	w.exec(t, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '1 hour'`)
	r := w.apply(t, p)
	if !has(r, store.ApplyMemberAdded) || r.Counts.Added != 1 {
		t.Fatalf("the apply: %v", kinds(r))
	}
	if role, status := w.membership(t, team, p.user); role != "admin" || status != "active" {
		t.Fatalf("the membership: %s %s", role, status)
	}
	var due bool
	if err := w.pool.QueryRow(context.Background(), `SELECT snapshot_due_at <= clock_timestamp() FROM contract_workspaces WHERE workspace_id = $1`,
		team).Scan(&due); err != nil || !due {
		t.Fatalf("the snapshot is not due now: %v %v", due, err)
	}
	if v, held := w.markers(t, p.sub); v == nil || *v != d.Version || held != nil {
		t.Fatalf("the markers: %v %v", v, held)
	}
	if again := w.apply(t, p); again.Changed() {
		t.Fatalf("a second apply did %v", kinds(again))
	}
}

// A team the document names and Wappie lacks is created once, with the
// platform's id and name, kind team, no capacity row and no avatar, though
// two subs race to create it.
func TestApplyCreatesTeamFromDocument(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	a, b := w.person(t), w.person(t)
	team := uuid.New()
	w.put(t, a, docSpec{teams: []docTeam{{id: team, role: "owner", name: strp("Equipe Norte")}}})
	w.put(t, b, docSpec{teams: []docTeam{{id: team, role: "member", name: strp("Equipe Norte")}}})
	var wg sync.WaitGroup
	made := make([][]uuid.UUID, 2)
	errs := make([]error, 2)
	for i, p := range []applyPerson{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			made[i], errs[i] = w.c.EnsureTeamsForTest(ctx, p.sub)
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || len(made[0])+len(made[1]) != 1 {
		t.Fatalf("the race: %v %v, created %v %v", errs[0], errs[1], made[0], made[1])
	}
	var name, kind, avatar, status string
	if err := w.pool.QueryRow(ctx, `SELECT name, kind, avatar, status FROM tenants WHERE id = $1`, team).Scan(&name, &kind, &avatar, &status); err != nil {
		t.Fatal(err)
	}
	if name != "Equipe Norte" || kind != "team" || avatar != "" || status != "active" {
		t.Fatalf("the team: %q %s %q %s", name, kind, avatar, status)
	}
	if n := w.count(t, team, `SELECT count(*) FROM workspace_capacity WHERE tenant_id = $1`, team); n != 0 {
		t.Fatalf("%d capacity rows", n)
	}
	w.apply(t, a)
	w.apply(t, b)
	if role, _ := w.membership(t, team, a.user); role != "owner" {
		t.Fatalf("a's membership: %q", role)
	}
	if role, _ := w.membership(t, team, b.user); role != "member" {
		t.Fatalf("b's membership: %q", role)
	}
}

// Another role: a demotion ends the person's sessions there and expires
// their pending invitations; the access version rises.
func TestApplyChangesRole(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	owner, p := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""}, applyMember{p.user, "admin", ""})
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}}})
	w.put(t, p, docSpec{teams: []docTeam{{id: team, role: "member"}}})
	s := w.session(t, p.user, team, w.at(t, "-1 hour"), uuid.Nil)
	other := w.session(t, p.user, p.personal, w.at(t, "-1 hour"), uuid.Nil)
	w.exec(t, `INSERT INTO invites (invite_id, tenant_id, role, created_by, expires_at) VALUES ($1, $2, 'member', $3, clock_timestamp() + interval '7 days')`,
		randBytes(t, 32), team, p.user)
	var version int64
	w.in(t, team, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT access_version FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2`, team, p.user).Scan(&version)
	})
	r := w.apply(t, p)
	if !has(r, store.ApplyRoleChanged) {
		t.Fatalf("the apply: %v", kinds(r))
	}
	if role, _ := w.membership(t, team, p.user); role != "member" {
		t.Fatalf("the role: %s", role)
	}
	if !w.revoked(t, "sessions", s) || w.revoked(t, "sessions", other) {
		t.Fatalf("the sessions: in the team %v, elsewhere %v", w.revoked(t, "sessions", s), w.revoked(t, "sessions", other))
	}
	var pending int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM invites WHERE tenant_id = $1 AND created_by = $2 AND expires_at > now()`, team, p.user).
		Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("%d pending invitations, %v", pending, err)
	}
	var now int64
	w.in(t, team, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT access_version FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2`, team, p.user).Scan(&now)
	})
	if now <= version {
		t.Fatalf("the access version: %d, was %d", now, version)
	}
}

// A listed membership disabled here is set active, with nothing restored.
func TestApplyReenablesListedDisabledMembership(t *testing.T) {
	w := newApplyWorld(t)
	owner, p := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""}, applyMember{p.user, "member", "disabled"})
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}}})
	w.put(t, p, docSpec{teams: []docTeam{{id: team, role: "member"}}})
	r := w.apply(t, p)
	if !has(r, store.ApplyMemberEnabled) {
		t.Fatalf("the apply: %v", kinds(r))
	}
	if _, status := w.membership(t, team, p.user); status != "active" {
		t.Fatalf("the status: %s", status)
	}
	if n := w.count(t, team, `SELECT count(*) FROM device_key_grants WHERE user_id = $1`, p.user) +
		w.count(t, team, `SELECT count(*) FROM device_permissions WHERE user_id = $1`, p.user); n != 0 {
		t.Fatalf("%d grants or permissions restored", n)
	}
}

// A loss has every effect of removeMember, and the person's keychain items
// and AI connections there; other workspaces, token rows and other people's
// grants are untouched.
func TestApplyLossSharesRemoveMemberEffects(t *testing.T) {
	w := newApplyWorld(t)
	owner, p := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""}, applyMember{p.user, "member", ""})
	kept := w.team(t, "Suporte", applyMember{owner.user, "owner", ""}, applyMember{p.user, "member", ""})
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}}})
	device := w.number(t, team)
	w.reads(t, team, device, owner.user)
	w.reads(t, team, device, p.user)
	past := w.at(t, "-1 hour")
	s := w.session(t, p.user, team, past, uuid.Nil)
	sKept := w.session(t, p.user, kept, past, uuid.Nil)
	k := w.key(t, team, p.user, uuid.Nil, past)
	kKept := w.key(t, kept, p.user, uuid.Nil, past)
	conn := w.connection(t, team, p.user, past)
	item := w.keychain(t, team, p.user, past)
	tokensBefore := w.count(t, team, `SELECT (SELECT count(*) FROM contract_tokens) + (SELECT count(*) FROM contract_token_perms)`)
	w.put(t, p, docSpec{})
	r := w.apply(t, p)
	if !has(r, store.ApplyMemberLost) || r.Counts.Lost != 1 {
		t.Fatalf("the apply: %v", kinds(r))
	}
	if role, _ := w.membership(t, team, p.user); role != "" {
		t.Fatalf("still a member: %s", role)
	}
	if role, _ := w.membership(t, kept, p.user); role != "member" {
		t.Fatalf("the other workspace's membership: %q", role)
	}
	if !w.revoked(t, "sessions", s) || w.revoked(t, "sessions", sKept) || !w.revoked(t, "api_keys", k) || w.revoked(t, "api_keys", kKept) {
		t.Fatal("sessions and keys: only the lost workspace's end")
	}
	var status, reason string
	if err := w.pool.QueryRow(context.Background(), `SELECT status, coalesce(revoke_reason, '') FROM mcp_connections WHERE id = $1`, conn).
		Scan(&status, &reason); err != nil || status != "revoked" || reason != store.ReasonMemberRemoved {
		t.Fatalf("the connection: %s %s %v", status, reason, err)
	}
	if n := w.count(t, team, `SELECT count(*) FROM ai_keychain WHERE id = $1 AND deleted_at IS NOT NULL AND envelope = '\x'`, item); n != 1 {
		t.Fatal("the keychain item is not emptied")
	}
	if n := w.count(t, team, `SELECT count(*) FROM workspace_member_history WHERE user_id = $1`, p.user); n != 1 {
		t.Fatalf("%d history rows", n)
	}
	if n := w.count(t, team, `SELECT count(*) FROM device_key_grants WHERE user_id = $1`, p.user); n != 0 {
		t.Fatalf("%d grants left", n)
	}
	if n := w.count(t, team, `SELECT count(*) FROM device_key_grants WHERE user_id = $1`, owner.user); n != 1 {
		t.Fatalf("the owner's grants: %d", n)
	}
	if after := w.count(t, team, `SELECT (SELECT count(*) FROM contract_tokens) + (SELECT count(*) FROM contract_token_perms)`); after != tokensBefore {
		t.Fatalf("token rows: %d, were %d", after, tokensBefore)
	}
}

// A loss that would strand a number waits while the generation is not
// confirmed; once it is, each number (live or deleted) records
// item.stranded by the app with no cause, and the other owners get their
// notice.
func TestApplyLossThatStrandsWaitsForConfirmation(t *testing.T) {
	w := newApplyWorld(t)
	owner, p := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""}, applyMember{p.user, "member", ""})
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}}})
	live, gone := w.number(t, team), w.number(t, team)
	w.reads(t, team, live, p.user)
	w.reads(t, team, gone, p.user)
	excludeNumber(t, w.pool, team, gone)
	w.exec(t, `UPDATE contract_state SET generation_confirmed = false`)
	w.put(t, p, docSpec{})
	r := w.apply(t, p)
	if r.Held != store.HeldStrandsUnconfirmed || has(r, store.ApplyMemberLost) {
		t.Fatalf("unconfirmed: held %q, %v", r.Held, kinds(r))
	}
	if role, _ := w.membership(t, team, p.user); role != "member" {
		t.Fatalf("a held loss removed the membership: %q", role)
	}
	if _, held := w.markers(t, p.sub); held == nil || *held != store.HeldStrandsUnconfirmed {
		t.Fatalf("apply_held: %v", held)
	}
	w.exec(t, `UPDATE contract_state SET generation_confirmed = true`)
	r = w.apply(t, p)
	if r.Held != "" || !has(r, store.ApplyMemberLost) || r.Counts.Strands != 2 {
		t.Fatalf("confirmed: held %q, %v, strands %d", r.Held, kinds(r), r.Counts.Strands)
	}
	for _, device := range []uuid.UUID{live, gone} {
		var kind string
		var actorSub, person *uuid.UUID
		var cause *string
		w.in(t, team, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT actor_kind, actor_sub, person_sub, cause FROM item_events WHERE item_id = $1 AND type = 'stranded'`,
				device).Scan(&kind, &actorSub, &person, &cause)
		})
		if kind != "app" || actorSub != nil || cause != nil || person == nil || *person != p.sub {
			t.Fatalf("%s's stranded row: %s %v %v %v", device, kind, actorSub, cause, person)
		}
		if n := w.count(t, team, `SELECT count(*) FROM device_notices WHERE device_id = $1 AND user_id = $2 AND kind = 'number_stranded'
			AND raised_by IS NULL AND raised_by_kind = 'app'`, device, owner.user); n != 1 {
			t.Fatalf("%s: %d owner's notices", device, n)
		}
	}
	if n := w.count(t, team, `SELECT count(*) FROM device_notices WHERE device_id = $1 AND kind = 'number_stranded' AND until IS NOT NULL`, gone); n != 1 {
		t.Fatal("the deleted number's notice has no until")
	}
}

// Service accounts, memberships with a deadline and token identities are
// never a person's loss.
func TestApplyLeavesServicesProvisionalAndTokenIdentities(t *testing.T) {
	w := newApplyWorld(t)
	owner, p := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""})
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}}})
	w.in(t, team, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO workspace_memberships (tenant_id, user_id, role, expires_at)
			VALUES ($1, $2, 'member', clock_timestamp() + interval '1 day')`, team, p.user)
		return err
	})
	svc := w.service(t, team, owner.user, w.at(t, "-1 hour"))
	w.put(t, p, docSpec{})
	r := w.apply(t, p)
	if has(r, store.ApplyMemberLost) {
		t.Fatalf("a deadline membership was lost: %v", kinds(r))
	}
	if role, _ := w.membership(t, team, p.user); role != "member" {
		t.Fatalf("the deadline membership: %q", role)
	}
	w.apply(t, owner)
	if role, _ := w.membership(t, team, svc); role != "service" {
		t.Fatalf("the service: %q", role)
	}
}

// Teams no document names, and people with no platform link, are never
// touched.
func TestApplyLeavesUnnamedTeamsAndNoSubPeople(t *testing.T) {
	w := newApplyWorld(t)
	owner, p := w.person(t), w.person(t)
	unnamed := w.team(t, "Piloto A", applyMember{p.user, "owner", ""})
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""})
	local := uuid.New()
	home := uuid.New()
	inTenantTx(context.Background(), t, w.pool, home, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO users (id, tenant_id, email, public_key, role, auth_source)
			VALUES ($1, $2, 'local@example.com', $3, 'owner', 'platform')`, local, home, randBytes(t, 32))
		return err
	})
	w.join(t, team, applyMember{local, "member", ""})
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}}})
	w.put(t, p, docSpec{})
	w.apply(t, p)
	w.apply(t, owner)
	if role, _ := w.membership(t, unnamed, p.user); role != "owner" {
		t.Fatalf("the unnamed team's membership: %q", role)
	}
	if role, _ := w.membership(t, team, local); role != "member" {
		t.Fatalf("the person with no sub: %q", role)
	}
}

// A personal workspace that differs from the document's is held, never
// moved or deleted.
func TestApplyHoldsPersonalMismatch(t *testing.T) {
	w := newApplyWorld(t)
	p := w.person(t)
	other := uuid.New()
	w.put(t, p, docSpec{personal: &other})
	r := w.apply(t, p)
	if r.Held != store.HeldPersonalMismatch {
		t.Fatalf("held %q: %v", r.Held, kinds(r))
	}
	var exists, otherExists bool
	if err := w.pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1 AND personal_owner_id = $2),
		EXISTS (SELECT 1 FROM tenants WHERE id = $3)`, p.personal, p.user, other).Scan(&exists, &otherExists); err != nil || !exists || otherExists {
		t.Fatalf("the personal workspaces: local %v, the document's %v, %v", exists, otherExists, err)
	}
}

// A team's name follows its stored documents at the highest wversion; a
// lower one is ignored, and a restart applies the new generation's again.
func TestApplyRenamesTeamByWVersion(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	a, b := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{a.user, "owner", ""}, applyMember{b.user, "member", ""})
	w.put(t, a, docSpec{teams: []docTeam{{id: team, role: "owner", wversion: 3, name: strp("Vendas SP")}}})
	w.put(t, b, docSpec{teams: []docTeam{{id: team, role: "member", wversion: 2, name: strp("Vendas RJ")}}})
	r, err := w.c.ApplyWorkspaceForTest(ctx, team)
	if err != nil || !has(r, store.ApplyTeamRenamed) {
		t.Fatalf("the rename: %v %v", kinds(r), err)
	}
	name := func() string {
		var n string
		if err := w.pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, team).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := name(); got != "Vendas SP" {
		t.Fatalf("the name: %q", got)
	}
	if r, err := w.c.ApplyWorkspaceForTest(ctx, team); err != nil || len(r.Actions) != 0 {
		t.Fatalf("again: %v %v", kinds(r), err)
	}
	gen := w.gen
	if ok, err := w.c.Restart(ctx, &gen, 0, &gen, true); err != nil || !ok {
		t.Fatalf("the restart: %v %v", ok, err)
	}
	var applied *int64
	if err := w.pool.QueryRow(ctx, `SELECT applied_wversion FROM contract_workspaces WHERE workspace_id = $1`, team).Scan(&applied); err != nil || applied != nil {
		t.Fatalf("after a restart applied_wversion is %v, %v", applied, err)
	}
}

// A closed team is suspended: access is refused and its numbers say
// team_closed; reopened, it is active again. A suspension the contract did
// not make is never lifted.
func TestApplyClosesAndReopensTeam(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	a := w.person(t)
	team := w.team(t, "Vendas", applyMember{a.user, "owner", ""})
	device := w.number(t, team)
	w.reads(t, team, device, a.user)
	w.put(t, a, docSpec{teams: []docTeam{{id: team, role: "owner", status: "closed", wversion: 2}}})
	r, err := w.c.ApplyWorkspaceForTest(ctx, team)
	if err != nil || !has(r, store.ApplyTeamClosed) {
		t.Fatalf("the closure: %v %v", kinds(r), err)
	}
	status := func() (tenant, applied string) {
		if err := w.pool.QueryRow(ctx, `SELECT t.status, coalesce(w.applied_status, '') FROM tenants t JOIN contract_workspaces w ON w.workspace_id = t.id
			WHERE t.id = $1`, team).Scan(&tenant, &applied); err != nil {
			t.Fatal(err)
		}
		return tenant, applied
	}
	if ts, as := status(); ts != "suspended" || as != "closed" {
		t.Fatalf("closed: %s %s", ts, as)
	}
	session := w.session(t, a.user, team, w.at(t, "-1 minute"), uuid.Nil)
	if _, _, err := store.NewUsers(w.pool).ConnectionAccess(ctx, team, a.user, session); err == nil {
		t.Fatal("ConnectionAccess in a closed team")
	}
	snap, err := w.c.Snapshot(ctx, team)
	if err != nil || len(snap.Items) != 1 || snap.Items[0].Reason != store.SnapshotTeamClosed {
		t.Fatalf("the snapshot: %+v %v", snap.Items, err)
	}
	w.put(t, a, docSpec{teams: []docTeam{{id: team, role: "owner", status: "open", wversion: 3}}})
	if r, err := w.c.ApplyWorkspaceForTest(ctx, team); err != nil || !has(r, store.ApplyTeamReopened) {
		t.Fatalf("the reopening: %v %v", kinds(r), err)
	}
	if ts, as := status(); ts != "active" || as != "open" {
		t.Fatalf("reopened: %s %s", ts, as)
	}
	// The operator's suspension stands.
	w.exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, team)
	w.put(t, a, docSpec{teams: []docTeam{{id: team, role: "owner", status: "open", wversion: 4}}})
	if r, err := w.c.ApplyWorkspaceForTest(ctx, team); err != nil || has(r, store.ApplyTeamReopened) {
		t.Fatalf("an operator's suspension: %v %v", kinds(r), err)
	}
	if ts, _ := status(); ts != "suspended" {
		t.Fatalf("an operator's suspension was lifted: %s", ts)
	}
}

// A personal workspace whose document leaves its name null is named in its
// owner's language (Portuguese with none); a locale change renames it once
// the apply named it, and never one it did not.
func TestApplyNamesPersonalWorkspace(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	p, q := w.person(t), w.person(t)
	w.put(t, p, docSpec{})
	r, err := w.c.ApplyWorkspaceForTest(ctx, p.personal)
	if err != nil || !has(r, store.ApplyPersonalNamed) {
		t.Fatalf("the naming: %v %v", kinds(r), err)
	}
	name := func(id uuid.UUID) string {
		var n string
		if err := w.pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := name(p.personal); got != "Espaço pessoal" {
		t.Fatalf("no locale: %q", got)
	}
	users := store.NewUsers(w.pool)
	if _, err := users.SetLocale(ctx, p.user, "en"); err != nil {
		t.Fatal(err)
	}
	if got := name(p.personal); got != "Personal space" {
		t.Fatalf("after en: %q", got)
	}
	was := name(q.personal)
	if _, err := users.SetLocale(ctx, q.user, "de"); err != nil {
		t.Fatal(err)
	}
	if got := name(q.personal); got != was {
		t.Fatalf("an unapplied workspace was renamed: %q, was %q", got, was)
	}
	for locale, want := range map[string]string{"": "Espaço pessoal", "pt": "Espaço pessoal", "es": "Espacio personal",
		"fr": "Espace personnel", "de": "Persönlicher Bereich", "xx": "Espaço pessoal"} {
		if got := store.PersonalWorkspaceName(locale); got != want {
			t.Errorf("PersonalWorkspaceName(%q) = %q", locale, got)
		}
	}
}

// A disabled document suspends the person: sessions, keys and connections
// end; grants, permissions and memberships stay; the snapshot says the
// person does not read while the key still protects; the belt reports
// revoked, not creator_disabled_here.
func TestApplySuspendsDisabledAccount(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	p := w.person(t)
	team := w.team(t, "Vendas", applyMember{p.user, "owner", ""})
	device := w.number(t, team)
	w.reads(t, team, device, p.user)
	past := w.at(t, "-1 hour")
	s := w.session(t, p.user, team, past, uuid.Nil)
	k := w.key(t, team, p.user, uuid.Nil, past)
	conn := w.connection(t, team, p.user, past)
	w.put(t, p, docSpec{status: "disabled", disabled: &past, teams: []docTeam{{id: team, role: "owner"}}})
	r := w.apply(t, p)
	if !has(r, store.ApplyAccountSuspended) {
		t.Fatalf("the apply: %v", kinds(r))
	}
	var status, by string
	w.in(t, p.personal, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, coalesce(disabled_by, '') FROM users WHERE id = $1`, p.user).Scan(&status, &by)
	})
	if status != "disabled" || by != "contract" {
		t.Fatalf("the account: %s by %q", status, by)
	}
	var reason string
	if err := w.pool.QueryRow(ctx, `SELECT coalesce(revoke_reason, '') FROM api_keys WHERE id = $1`, k).Scan(&reason); err != nil || reason != store.RevokeReasonContract {
		t.Fatalf("the key: %q %v", reason, err)
	}
	if !w.revoked(t, "sessions", s) || !w.revoked(t, "mcp_connections", conn) {
		t.Fatal("a session or a connection lives on")
	}
	if role, _ := w.membership(t, team, p.user); role != "owner" {
		t.Fatalf("the membership: %q", role)
	}
	if n := w.count(t, team, `SELECT count(*) FROM device_key_grants WHERE user_id = $1`, p.user) +
		w.count(t, team, `SELECT count(*) FROM device_permissions WHERE user_id = $1`, p.user); n != 2 {
		t.Fatalf("%d grants and permissions, want 2", n)
	}
	snap, err := w.c.Snapshot(ctx, team)
	if err != nil || len(snap.Items) != 1 {
		t.Fatalf("the snapshot: %+v %v", snap, err)
	}
	found := false
	for _, person := range snap.Items[0].People {
		if person.Sub == p.sub {
			found = true
			if person.Reads || !person.HoldsKey {
				t.Fatalf("the suspended person in the snapshot: %+v", person)
			}
		}
	}
	if !found || len(snap.Items[0].Protected) != 1 || snap.Items[0].Protected[0] != p.sub {
		t.Fatalf("the suspended person is not protected: %+v", snap.Items[0])
	}
}

// Only a disable the contract made is lifted, and a disabled_at that rises
// while active ends what began before it, the account staying active. An
// operator's disable stands.
func TestApplyReenablesOnlyItsOwnDisable(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	p, q := w.person(t), w.person(t)
	at := w.at(t, "-1 minute")
	w.put(t, p, docSpec{status: "disabled", disabled: &at})
	w.apply(t, p)
	w.put(t, p, docSpec{status: "active", disabled: &at})
	if r := w.apply(t, p); !has(r, store.ApplyAccountEnabled) {
		t.Fatalf("the enable: %v", kinds(r))
	}
	status := func(u applyPerson) string {
		var s string
		w.in(t, u.personal, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1`, u.user).Scan(&s)
		})
		return s
	}
	if s := status(p); s != "active" {
		t.Fatalf("after the enable: %s", s)
	}
	// A disable and an enable between two passes.
	before := w.session(t, p.user, p.personal, w.at(t, "-30 seconds"), uuid.Nil)
	risen := w.at(t, "-1 second")
	after := w.session(t, p.user, p.personal, w.at(t, "0 seconds"), uuid.Nil)
	w.put(t, p, docSpec{status: "active", disabled: &risen})
	w.apply(t, p)
	if s := status(p); s != "active" || !w.revoked(t, "sessions", before) || w.revoked(t, "sessions", after) {
		t.Fatalf("a risen disabled_at: %s, before %v, after %v", s, w.revoked(t, "sessions", before), w.revoked(t, "sessions", after))
	}
	// The operator's.
	w.in(t, q.personal, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, q.user)
		return err
	})
	w.put(t, q, docSpec{status: "active"})
	r := w.apply(t, q)
	if !r.OperatorDisable || has(r, store.ApplyAccountEnabled) || status(q) != "disabled" {
		t.Fatalf("an operator's disable: %v %v %s", r.OperatorDisable, kinds(r), status(q))
	}
}

// users.disabled_by: the operator's outside the apply, the contract's only
// inside it, never taken over by the contract; cleared by an enable.
func TestUsersDisabledByTrigger(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	p := w.person(t)
	set := func(status string, contract bool) string {
		var by string
		w.in(t, p.personal, func(tx pgx.Tx) error {
			on := ""
			if contract {
				on = "on"
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.contract_apply', $1, true)`, on); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `UPDATE users SET status = $2 WHERE id = $1 RETURNING coalesce(disabled_by, '')`, p.user, status).Scan(&by)
		})
		return by
	}
	if by := set("disabled", false); by != "operator" {
		t.Fatalf("an operator's disable: %q", by)
	}
	if by := set("disabled", true); by != "operator" {
		t.Fatalf("the contract took over an operator's disable: %q", by)
	}
	if by := set("active", false); by != "" {
		t.Fatalf("an enable: %q", by)
	}
	if by := set("disabled", true); by != "contract" {
		t.Fatalf("the contract's disable: %q", by)
	}
	if by := set("disabled", false); by != "operator" {
		t.Fatalf("an operator's disable of the contract's: %q", by)
	}
	err := pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, p.personal.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE users SET disabled_by = NULL WHERE id = $1`, p.user)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "users_disabled_by_shape" {
		t.Fatalf("a disabled account with no disabled_by: %v", err)
	}
}

// sessions_revoked_at ends every session whose family began before it, a
// family's later sessions included.
func TestApplyEndsSessionsByFamilyStart(t *testing.T) {
	w := newApplyWorld(t)
	p := w.person(t)
	family := uuid.New()
	first := w.session(t, p.user, p.personal, w.at(t, "-2 hours"), family)
	refreshed := w.session(t, p.user, p.personal, w.at(t, "-1 second"), family)
	at := w.at(t, "-1 hour")
	later := w.session(t, p.user, p.personal, w.at(t, "-30 minutes"), uuid.Nil)
	w.put(t, p, docSpec{sessions: &at})
	r := w.apply(t, p)
	if r.Counts.Sessions != 2 || !w.revoked(t, "sessions", first) || !w.revoked(t, "sessions", refreshed) || w.revoked(t, "sessions", later) {
		t.Fatalf("%d sessions ended: first %v, refreshed %v, later %v", r.Counts.Sessions, w.revoked(t, "sessions", first),
			w.revoked(t, "sessions", refreshed), w.revoked(t, "sessions", later))
	}
}

// The W45 ask: credentials_revoked_at stops what the person made before
// it, every class; what they made after it and another person's stay; the
// apply stops exactly what observe's diff counted; a second run is a no-op.
func TestApplyStopsCredentialsBeforeRecovery(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	p, other := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{p.user, "owner", ""}, applyMember{other.user, "admin", ""})
	device := w.number(t, team)
	w.reads(t, team, device, p.user)
	w.put(t, other, docSpec{teams: []docTeam{{id: team, role: "admin"}}})
	before, after := w.at(t, "-2 hours"), w.at(t, "-1 minute")
	keyBefore, keyAfter := w.key(t, team, p.user, uuid.Nil, before), w.key(t, team, p.user, uuid.Nil, after)
	connBefore, connAfter := w.connection(t, team, p.user, before), w.connection(t, team, p.user, after)
	itemBefore, itemAfter := w.keychain(t, team, p.user, before), w.keychain(t, team, p.user, after)
	svc := w.service(t, team, p.user, before)
	svcKey := w.key(t, team, p.user, svc, after)
	theirs := w.key(t, team, other.user, uuid.Nil, before)
	at := w.at(t, "-1 hour")
	w.put(t, p, docSpec{creds: &at, teams: []docTeam{{id: team, role: "owner"}}})
	diffs, _, err := w.c.DifferencesOf(ctx, p.sub)
	if err != nil {
		t.Fatal(err)
	}
	var want store.ContractDifference
	for _, d := range diffs {
		if d.Kind == store.DiffCredentialsWouldStop {
			want = d
		}
	}
	if want.Keys != 1 || want.Connections != 2 || want.Services != 1 {
		t.Fatalf("credentials_would_stop: %+v", want)
	}
	r := w.apply(t, p)
	if !has(r, store.ApplyCredentialsStopped) {
		t.Fatalf("the apply: %v", kinds(r))
	}
	if !w.revoked(t, "api_keys", keyBefore) || w.revoked(t, "api_keys", keyAfter) || w.revoked(t, "api_keys", theirs) {
		t.Fatal("keys: only the person's before the recovery stop")
	}
	if !w.revoked(t, "mcp_connections", connBefore) || w.revoked(t, "mcp_connections", connAfter) {
		t.Fatal("connections: only the person's before the recovery stop")
	}
	if n := w.count(t, team, `SELECT count(*) FROM ai_keychain WHERE deleted_at IS NOT NULL AND id = ANY ($1)`, []uuid.UUID{itemBefore, itemAfter}); n != 1 {
		t.Fatalf("%d keychain items emptied, want 1", n)
	}
	if !w.revoked(t, "api_keys", svcKey) {
		t.Fatal("a key acting as the person's service lives on")
	}
	// The service held no number: removed.
	if role, _ := w.membership(t, team, svc); role != "" {
		t.Fatalf("the service: %q", role)
	}
	diffs, _, err = w.c.DifferencesOf(ctx, p.sub)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range diffs {
		if d.Kind == store.DiffCredentialsWouldStop {
			t.Fatalf("after the apply: %+v", d)
		}
	}
	sum := stable(w.checksum(t))
	if again := w.apply(t, p); again.Changed() || stable(w.checksum(t)) != sum {
		t.Fatalf("a second run: %v", kinds(again))
	}
	var reason string
	if err := w.pool.QueryRow(ctx, `SELECT revoke_reason FROM mcp_connections WHERE id = $1`, connBefore).Scan(&reason); err != nil ||
		reason != store.ReasonCredentialsRevoked {
		t.Fatalf("the connection's reason: %q %v", reason, err)
	}
}

// A standing service account that is a number's sole key holder is kept,
// keyless, so the number's last key is not lost.
func TestApplyCredentialsKeepSoleReaderService(t *testing.T) {
	w := newApplyWorld(t)
	p := w.person(t)
	team := w.team(t, "Vendas", applyMember{p.user, "owner", ""})
	device := w.number(t, team)
	before := w.at(t, "-2 hours")
	svc := w.service(t, team, p.user, before)
	w.reads(t, team, device, svc)
	k := w.key(t, team, p.user, svc, before)
	at := w.at(t, "-1 hour")
	w.put(t, p, docSpec{creds: &at, teams: []docTeam{{id: team, role: "owner"}}})
	r := w.apply(t, p)
	if !has(r, store.ApplyServiceKept) || r.Counts.ServicesKept != 1 {
		t.Fatalf("the apply: %v", kinds(r))
	}
	if role, _ := w.membership(t, team, svc); role != "service" {
		t.Fatalf("the sole reader: %q", role)
	}
	if !w.revoked(t, "api_keys", k) || w.count(t, team, `SELECT count(*) FROM device_key_grants WHERE user_id = $1`, svc) != 1 {
		t.Fatal("the kept service: a live key, or its grant gone")
	}
}

// A recovery's stop writes no token row: the belt reads the stored document.
func TestApplyCredentialsLeaveTokenRows(t *testing.T) {
	w := newApplyWorld(t)
	p := w.person(t)
	team := w.team(t, "Vendas", applyMember{p.user, "owner", ""})
	tokens := func() string {
		var s string
		w.in(t, team, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT coalesce(md5(string_agg(x::text, ',' ORDER BY x::text)), '') FROM (
				SELECT to_jsonb(t)::text AS x FROM contract_tokens t UNION ALL SELECT to_jsonb(p)::text FROM contract_token_perms p
				UNION ALL SELECT to_jsonb(s)::text FROM contract_token_sticky s) all_rows`).Scan(&s)
		})
		return s
	}
	was := tokens()
	at := w.at(t, "-1 minute")
	w.put(t, p, docSpec{creds: &at, teams: []docTeam{{id: team, role: "owner"}}})
	w.apply(t, p)
	if tokens() != was {
		t.Fatal("the apply wrote a token row")
	}
}

// A pass run again changes nothing.
func TestApplyIsIdempotent(t *testing.T) {
	w := newApplyWorld(t)
	owner, p := w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""})
	lost := w.team(t, "Suporte", applyMember{owner.user, "owner", ""}, applyMember{p.user, "member", ""})
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}, {id: lost, role: "owner"}}})
	at := w.at(t, "-1 minute")
	w.put(t, p, docSpec{sessions: &at, creds: &at, teams: []docTeam{{id: team, role: "member"}}})
	if r := w.apply(t, p); !r.Changed() {
		t.Fatal("the first apply did nothing")
	}
	sum := w.checksum(t)
	if r := w.apply(t, p); r.Changed() {
		t.Fatalf("the second apply: %v", kinds(r))
	}
	// The markers spare nothing that matters: with them cleared, the
	// tables still say the document.
	w.exec(t, `UPDATE contract_accounts SET applied_version = NULL, applied_sessions_revoked_at = NULL, applied_credentials_revoked_at = NULL`)
	if r := w.apply(t, p); r.Changed() {
		t.Fatalf("with the markers cleared: %v", kinds(r))
	}
	if stable(w.checksum(t)) != stable(sum) {
		t.Fatal("a pass run again changed a table")
	}
}

// A pass that fails mid-way leaves nothing and returns nothing (no
// connection it ended inside the rolled-back transaction, for a reader to
// be told of), and the next pass applies all.
func TestApplyResumesAfterCrash(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	owner, p := w.person(t), w.person(t)
	a := w.team(t, "A", applyMember{owner.user, "owner", ""}, applyMember{p.user, "member", ""})
	b := w.team(t, "B", applyMember{owner.user, "owner", ""}, applyMember{p.user, "member", ""})
	w.put(t, owner, docSpec{teams: []docTeam{{id: a, role: "owner"}, {id: b, role: "owner"}}})
	// One in each team: whichever loss comes first ends one, then fails.
	conns := []uuid.UUID{w.connection(t, a, p.user, w.at(t, "-1 hour")), w.connection(t, b, p.user, w.at(t, "-1 hour"))}
	w.put(t, p, docSpec{})
	store.SetApplyFaultForTest(t, 1)
	failed, err := w.c.ApplyAccountForTest(ctx, p.sub)
	if err == nil {
		t.Fatal("the fault did not fail the apply")
	}
	if len(failed.Ended) != 0 || len(failed.Actions) != 0 || failed.Counts != (store.ApplyCounts{}) {
		t.Fatalf("a rolled-back apply returned %v, ended %v", kinds(failed), failed.Ended)
	}
	for _, conn := range conns {
		if w.revoked(t, "mcp_connections", conn) {
			t.Fatal("a rolled-back apply ended a connection")
		}
	}
	for _, ws := range []uuid.UUID{a, b} {
		if role, _ := w.membership(t, ws, p.user); role != "member" {
			t.Fatalf("a failed pass removed %s's membership", ws)
		}
	}
	if v, _ := w.markers(t, p.sub); v != nil {
		t.Fatalf("a failed pass wrote the markers: %v", *v)
	}
	store.SetApplyFaultForTest(t, 0)
	w.apply(t, p)
	for _, ws := range []uuid.UUID{a, b} {
		if role, _ := w.membership(t, ws, p.user); role != "" {
			t.Fatalf("the next pass left %s's membership", ws)
		}
	}
}

// Going back to observe undoes nothing, and the apply refuses there.
func TestApplyKeepsEverythingBackAtObserve(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	p := w.person(t)
	team := w.team(t, "Vendas", applyMember{p.user, "owner", ""})
	at := w.at(t, "-1 minute")
	w.put(t, p, docSpec{status: "disabled", disabled: &at, teams: []docTeam{{id: team, role: "owner", status: "closed", wversion: 2}}})
	w.apply(t, p)
	w.put(t, p, docSpec{status: "active", disabled: &at, teams: []docTeam{{id: team, role: "owner", status: "open", wversion: 3}}})
	if _, err := w.c.ApplyAccount(ctx, p.sub); !errors.Is(err, store.ErrApplyNeedsEnforce) {
		t.Fatalf("at observe: %v", err)
	}
	var status string
	if err := w.pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1`, team).Scan(&status); err != nil || status != "suspended" {
		t.Fatalf("the closed team at observe: %s %v", status, err)
	}
	var by string
	w.in(t, p.personal, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(disabled_by, '') FROM users WHERE id = $1`, p.user).Scan(&by)
	})
	if by != "contract" {
		t.Fatalf("the suspension at observe: %q", by)
	}
}

// The apply against every writer it meets, each in its own order: no
// deadlock escapes (an apply retries one; the others must never meet one).
func TestApplyLockOrder(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	owner, p, q := w.person(t), w.person(t), w.person(t)
	team := w.team(t, "Vendas", applyMember{owner.user, "owner", ""}, applyMember{p.user, "member", ""}, applyMember{q.user, "member", ""})
	other := w.team(t, "Suporte", applyMember{owner.user, "owner", ""}, applyMember{p.user, "member", ""})
	device := w.number(t, team)
	w.reads(t, team, device, owner.user)
	w.reads(t, team, device, p.user)
	w.put(t, owner, docSpec{teams: []docTeam{{id: team, role: "owner"}, {id: other, role: "owner"}}})
	users := store.NewUsers(w.pool)
	deadlock := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "40P01"
	}
	for round := range 10 {
		at := w.at(t, "-1 second")
		teams := []docTeam{{id: team, role: "admin"}}
		if round%2 == 1 {
			teams = append(teams, docTeam{id: other, role: "member"})
		}
		w.put(t, p, docSpec{sessions: &at, creds: &at, teams: teams})
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		run := func(f func() error) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- f()
			}()
		}
		run(func() error { _, err := w.c.ApplyAccountForTest(ctx, p.sub); return err })
		run(func() error { _, err := w.c.ApplyWorkspaceForTest(ctx, team); return err })
		run(func() error { return w.c.SnapshotsDue(ctx) })
		run(func() error { return w.c.SnapshotsDirty(ctx, []uuid.UUID{team, other}, false, 0) })
		next := w.nextDoc(p, teams)
		run(func() error {
			_, err := w.c.StoreDocuments(ctx, store.ContractAnswer, next)
			return err
		})
		if round == 0 {
			run(func() error { return users.RemoveMember(ctx, team, owner.user, q.user) })
		}
		run(func() error { _, err := w.c.SweepOrphanServicesForTest(ctx); return err })
		wg.Wait()
		close(errs)
		for err := range errs {
			if deadlock(err) {
				t.Fatalf("round %d: a deadlock escaped: %v", round, err)
			}
		}
	}
}

// nextDoc is put's document without storing it, at the next version.
func (w *applyWorld) nextDoc(p applyPerson, teams []docTeam) store.ContractDoc {
	w.ver[p.sub]++
	v := w.ver[p.sub]
	d := store.ContractDoc{Sub: p.sub, Generation: w.gen, Version: v, Status: "active",
		Workspaces: []store.ContractDocWorkspace{{ID: p.personal, Kind: "personal", Role: "owner", Status: "open", WVersion: 1}}}
	raw := []map[string]any{{"id": p.personal.String(), "kind": "personal", "role": "owner", "status": "open", "wversion": 1}}
	for _, team := range teams {
		d.Workspaces = append(d.Workspaces, store.ContractDocWorkspace{ID: team.id, Kind: "team", Role: team.role, Status: "open", WVersion: 1})
		raw = append(raw, map[string]any{"id": team.id.String(), "kind": "team", "role": team.role, "status": "open", "wversion": 1})
	}
	d.Raw, _ = json.Marshal(map[string]any{"v": 1, "sub": p.sub.String(), "generation": w.gen.String(), "version": v, "status": "active",
		"workspaces": raw})
	return d
}

// The sweep revokes a key acting as a service user with no membership and
// deletes its stray grants; a user not known as a service (a token
// identity's shape) is left alone.
func TestSweepOrphanServices(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	p := w.person(t)
	team := w.team(t, "Vendas", applyMember{p.user, "owner", ""})
	device := w.number(t, team)
	svc := w.service(t, team, p.user, w.at(t, "-1 hour"))
	k := w.key(t, team, p.user, svc, w.at(t, "-1 hour"))
	w.reads(t, team, device, svc)
	stranger := w.service(t, team, p.user, w.at(t, "-1 hour"))
	w.exec(t, `DELETE FROM invites WHERE claimed_by = $1`, stranger)
	w.reads(t, team, device, stranger)
	w.in(t, team, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM workspace_memberships WHERE tenant_id = $1 AND user_id = ANY ($2)`, team, []uuid.UUID{svc, stranger})
		return err
	})
	plan, err := w.c.PlanAll(ctx)
	if err != nil || plan.Orphans.Keys != 1 {
		t.Fatalf("the plan's sweep: %+v %v", plan.Orphans, err)
	}
	sweep, err := w.c.SweepOrphanServicesForTest(ctx)
	if err != nil || sweep.Keys != 1 {
		t.Fatalf("the sweep: %+v %v", sweep, err)
	}
	var reason string
	if err := w.pool.QueryRow(ctx, `SELECT coalesce(revoke_reason, '') FROM api_keys WHERE id = $1`, k).Scan(&reason); err != nil ||
		reason != store.RevokeReasonOrphanService {
		t.Fatalf("the key: %q %v", reason, err)
	}
	if n := w.count(t, team, `SELECT count(*) FROM device_key_grants WHERE user_id = $1`, svc); n != 0 {
		t.Fatalf("the orphan's grants: %d", n)
	}
	if n := w.count(t, team, `SELECT count(*) FROM device_key_grants WHERE user_id = $1`, stranger); n != 1 {
		t.Fatalf("a user not known as a service lost its grant: %d", n)
	}
	if again, err := w.c.SweepOrphanServicesForTest(ctx); err != nil || again.Keys+again.Grants+again.Keychain != 0 {
		t.Fatalf("a second sweep: %+v %v", again, err)
	}
}

// closedWorld is a person whose account the platform closed: a team
// membership, a personal workspace with a linked and a pending number.
type closedWorld struct {
	*applyWorld
	owner, p        applyPerson
	team            uuid.UUID
	linked, pending uuid.UUID
}

func newClosedWorld(t *testing.T) closedWorld {
	t.Helper()
	w := newApplyWorld(t)
	cw := closedWorld{applyWorld: w, owner: w.person(t), p: w.person(t)}
	cw.team = w.team(t, "Vendas", applyMember{cw.owner.user, "owner", ""}, applyMember{cw.p.user, "member", ""})
	w.put(t, cw.owner, docSpec{teams: []docTeam{{id: cw.team, role: "owner"}}})
	cw.linked = w.number(t, cw.p.personal)
	w.reads(t, cw.p.personal, cw.linked, cw.p.user)
	dev, err := store.NewDevices(w.pool).Create(context.Background(), cw.p.personal.String(), "nova", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	cw.pending = uuid.MustParse(dev.ID)
	w.put(t, cw.p, docSpec{status: "closed"})
	return cw
}

// A closed account is suspended and leaves every team; its personal
// workspace stays; the closing is recorded and held until confirmed.
func TestApplyClosingSuspendsAndRemoves(t *testing.T) {
	cw := newClosedWorld(t)
	r := cw.apply(t, cw.p)
	if !has(r, store.ApplyAccountSuspended) || !has(r, store.ApplyMemberLost) || !has(r, store.ApplyClosingSeen) ||
		r.Held != store.HeldClosingUnconfirmed {
		t.Fatalf("the closing: %v held %q", kinds(r), r.Held)
	}
	if role, _ := cw.membership(t, cw.team, cw.p.user); role != "" {
		t.Fatalf("still in the team: %q", role)
	}
	if role, _ := cw.membership(t, cw.p.personal, cw.p.user); role != "owner" {
		t.Fatalf("the personal workspace's membership: %q", role)
	}
	if n := cw.count(t, cw.p.personal, `SELECT count(*) FROM devices WHERE deleted_at IS NULL`); n != 2 {
		t.Fatalf("%d personal numbers, want 2 untouched", n)
	}
	var seen bool
	if err := cw.pool.QueryRow(context.Background(), `SELECT seen_at IS NOT NULL AND confirmed_at IS NULL FROM contract_closings WHERE sub = $1`,
		cw.p.sub).Scan(&seen); err != nil || !seen {
		t.Fatalf("the closing record: %v %v", seen, err)
	}
}

// A fresh closed answer of the confirmed generation deletes the personal
// numbers (a linked one excluded, purged within 30 days; a pending one at
// once); anything else deletes nothing.
func TestConfirmClosingQuarantinesPersonalNumbers(t *testing.T) {
	cw := newClosedWorld(t)
	ctx := context.Background()
	cw.apply(t, cw.p)
	for name, fresh := range map[string]store.ContractDoc{
		"active":           {Sub: cw.p.sub, Generation: cw.gen, Status: "active"},
		"disabled":         {Sub: cw.p.sub, Generation: cw.gen, Status: "disabled"},
		"other generation": {Sub: cw.p.sub, Generation: uuid.New(), Status: "closed"},
		"another sub":      {Sub: uuid.New(), Generation: cw.gen, Status: "closed"},
	} {
		want := store.ErrClosingUnconfirmed
		if name == "active" {
			want = store.ErrClosingContradicted
		}
		if _, err := cw.c.ConfirmClosingForTest(ctx, cw.p.sub, fresh); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	if n := cw.count(t, cw.p.personal, `SELECT count(*) FROM devices WHERE deleted_at IS NULL`); n != 2 {
		t.Fatalf("a refused confirmation deleted: %d left", n)
	}
	cw.exec(t, `UPDATE contract_state SET generation_confirmed = false`)
	if _, err := cw.c.ConfirmClosingForTest(ctx, cw.p.sub, store.ContractDoc{Sub: cw.p.sub, Generation: cw.gen, Status: "closed"}); !errors.Is(err, store.ErrClosingUnconfirmed) {
		t.Fatalf("an unconfirmed generation: %v", err)
	}
	cw.exec(t, `UPDATE contract_state SET generation_confirmed = true`)
	res, err := cw.c.ConfirmClosingForTest(ctx, cw.p.sub, store.ContractDoc{Sub: cw.p.sub, Generation: cw.gen, Status: "closed"})
	if err != nil || res.Quarantined != 1 || res.Deleted != 1 {
		t.Fatalf("the confirmation: %+v %v", res, err)
	}
	var within bool
	cw.in(t, cw.p.personal, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT d.purge_after <= c.seen_at + interval '30 days' FROM devices d, contract_closings c
			WHERE d.id = $1 AND c.sub = $2`, cw.linked, cw.p.sub).Scan(&within)
	})
	if !within {
		t.Fatal("the purge is later than 30 days after the closing was seen")
	}
	if n := cw.count(t, cw.p.personal, `SELECT count(*) FROM devices WHERE id = $1`, cw.pending); n != 0 {
		t.Fatal("the pending registration is still there")
	}
	var actor string
	cw.in(t, cw.p.personal, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT actor_kind FROM item_events WHERE item_id = $1 AND type = 'deleted'`, cw.linked).Scan(&actor)
	})
	if actor != "app" {
		t.Fatalf("the deletion's actor: %q", actor)
	}
	if again, err := cw.c.ConfirmClosingForTest(ctx, cw.p.sub, store.ContractDoc{Sub: cw.p.sub, Generation: cw.gen, Status: "closed"}); err != nil || !again.Already {
		t.Fatalf("again: %+v %v", again, err)
	}
}

// Forgetting waits for every personal number's purge.
func TestForgetWaitsForPurge(t *testing.T) {
	cw := newClosedWorld(t)
	ctx := context.Background()
	cw.apply(t, cw.p)
	if _, done, err := cw.c.ForgetClosedForTest(ctx, cw.p.sub); err != nil || done {
		t.Fatalf("before the confirmation: %v %v", done, err)
	}
	if _, err := cw.c.ConfirmClosingForTest(ctx, cw.p.sub, store.ContractDoc{Sub: cw.p.sub, Generation: cw.gen, Status: "closed"}); err != nil {
		t.Fatal(err)
	}
	if _, done, err := cw.c.ForgetClosedForTest(ctx, cw.p.sub); err != nil || done {
		t.Fatalf("before the purge: %v %v", done, err)
	}
}

// Forgetting a closed account deletes its users row and, by their foreign
// keys, its personal workspace and platform identity; a transfer it made
// keeps its record with no actor; the closing's record stays.
func TestForgetClosedAccount(t *testing.T) {
	cw := newClosedWorld(t)
	ctx := context.Background()
	moved := cw.number(t, cw.team)
	cw.in(t, cw.team, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO device_transfers (device_id, source_workspace_id, target_workspace_id, actor_id) VALUES ($1, $2, $3, $4)`,
			moved, cw.team, uuid.New(), cw.p.user)
		return err
	})
	cw.apply(t, cw.p)
	if _, err := cw.c.ConfirmClosingForTest(ctx, cw.p.sub, store.ContractDoc{Sub: cw.p.sub, Generation: cw.gen, Status: "closed"}); err != nil {
		t.Fatal(err)
	}
	// The purge, as its job leaves a number: gone.
	cw.in(t, cw.p.personal, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM devices WHERE tenant_id = $1`, cw.p.personal)
		return err
	})
	cw.exec(t, `UPDATE contract_closings SET purge_due_at = clock_timestamp() WHERE sub = $1`, cw.p.sub)
	res, done, err := cw.c.ForgetClosedForTest(ctx, cw.p.sub)
	if err != nil || !done || res.Already {
		t.Fatalf("the forgetting: %+v %v %v", res, done, err)
	}
	var tenant, link bool
	if err := cw.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1), EXISTS (SELECT 1 FROM platform_identities WHERE sub = $2)`,
		cw.p.personal, cw.p.sub).Scan(&tenant, &link); err != nil || tenant || link {
		t.Fatalf("after the forgetting: personal workspace %v, platform link %v, %v", tenant, link, err)
	}
	var actor *uuid.UUID
	cw.in(t, cw.team, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT actor_id FROM device_transfers WHERE device_id = $1`, moved).Scan(&actor)
	})
	if actor != nil {
		t.Fatalf("the transfer's actor: %v", actor)
	}
	var forgotten bool
	if err := cw.pool.QueryRow(ctx, `SELECT forgotten_at IS NOT NULL FROM contract_closings WHERE sub = $1`, cw.p.sub).Scan(&forgotten); err != nil || !forgotten {
		t.Fatalf("the closing's record: %v %v", forgotten, err)
	}
	if err := cw.c.ClosingUnsubscribed(ctx, cw.p.sub); err != nil {
		t.Fatal(err)
	}
}

// A closed account's team loss that would strand a number (the person is
// its last key holder) waits for the closing's confirmation, as the
// personal numbers' deletion does; the confirmation leaves the hold for
// the next pass, which applies it.
func TestApplyClosingStrandWaitsForConfirmation(t *testing.T) {
	cw := newClosedWorld(t)
	ctx := context.Background()
	device := cw.number(t, cw.team)
	cw.reads(t, cw.team, device, cw.p.user)
	r := cw.apply(t, cw.p)
	if has(r, store.ApplyMemberLost) || r.Held != store.HeldClosingUnconfirmed || r.Counts.Strands != 0 {
		t.Fatalf("before the confirmation: %v held %q strands %d", kinds(r), r.Held, r.Counts.Strands)
	}
	if role, _ := cw.membership(t, cw.team, cw.p.user); role != "member" {
		t.Fatalf("a stranding loss applied before the closing was confirmed: %q", role)
	}
	if n := cw.count(t, cw.team, `SELECT count(*) FROM device_key_grants WHERE user_id = $1`, cw.p.user); n != 1 {
		t.Fatalf("the last key holder's grant: %d", n)
	}
	if _, err := cw.c.ConfirmClosingForTest(ctx, cw.p.sub, store.ContractDoc{Sub: cw.p.sub, Generation: cw.gen, Status: "closed"}); err != nil {
		t.Fatal(err)
	}
	if _, held := cw.markers(t, cw.p.sub); held == nil || *held != store.HeldClosingUnconfirmed {
		t.Fatalf("the confirmation cleared the hold the next pass needs: %v", held)
	}
	subs, _, err := cw.c.PendingApply(ctx, 10)
	if err != nil || len(subs) == 0 || subs[0] != cw.p.sub {
		t.Fatalf("the next pass does not take the account first: %v %v", subs, err)
	}
	r = cw.apply(t, cw.p)
	if !has(r, store.ApplyMemberLost) || r.Held != "" || r.Counts.Strands != 1 {
		t.Fatalf("after the confirmation: %v held %q strands %d", kinds(r), r.Held, r.Counts.Strands)
	}
	if role, _ := cw.membership(t, cw.team, cw.p.user); role != "" {
		t.Fatalf("still in the team: %q", role)
	}
	if _, held := cw.markers(t, cw.p.sub); held != nil {
		t.Fatalf("the hold after the pass: %v", *held)
	}
}

// A closing the document stops saying before its confirmation is dropped:
// nothing is left to confirm, and a later closing starts its own record,
// seen anew. A confirmed closing is forgotten only while the document
// still says closed and the account is still disabled, and the forgotten
// record keeps the sub and the times only.
func TestClosingRecordFollowsTheDocument(t *testing.T) {
	cw := newClosedWorld(t)
	ctx := context.Background()
	cw.apply(t, cw.p)
	var seen time.Time
	if err := cw.pool.QueryRow(ctx, `SELECT seen_at FROM contract_closings WHERE sub = $1`, cw.p.sub).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	cw.put(t, cw.p, docSpec{})
	cw.apply(t, cw.p)
	if confirm, _, _, err := cw.c.PendingClosings(ctx, 10); err != nil || len(confirm) != 0 {
		t.Fatalf("an active document left a closing to confirm: %v %v", confirm, err)
	}
	cw.put(t, cw.p, docSpec{status: "closed"})
	if r := cw.apply(t, cw.p); !has(r, store.ApplyClosingSeen) {
		t.Fatalf("a second closing: %v", kinds(r))
	}
	var again time.Time
	if err := cw.pool.QueryRow(ctx, `SELECT seen_at FROM contract_closings WHERE sub = $1`, cw.p.sub).Scan(&again); err != nil || !again.After(seen) {
		t.Fatalf("the second closing kept the first's seen_at: %v, was %v, %v", again, seen, err)
	}

	if _, err := cw.c.ConfirmClosingForTest(ctx, cw.p.sub, store.ContractDoc{Sub: cw.p.sub, Generation: cw.gen, Status: "closed"}); err != nil {
		t.Fatal(err)
	}
	cw.in(t, cw.p.personal, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM devices WHERE tenant_id = $1`, cw.p.personal)
		return err
	})
	cw.exec(t, `UPDATE contract_closings SET purge_due_at = clock_timestamp() WHERE sub = $1`, cw.p.sub)
	// The document says active again (not applied yet): nothing is forgotten.
	cw.put(t, cw.p, docSpec{})
	if _, done, err := cw.c.ForgetClosedForTest(ctx, cw.p.sub); err != nil || done {
		t.Fatalf("forgotten under an active document: %v %v", done, err)
	}
	var link bool
	if err := cw.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM platform_identities WHERE sub = $1)`, cw.p.sub).Scan(&link); err != nil || !link {
		t.Fatalf("the account went under an active document: %v %v", link, err)
	}
	cw.put(t, cw.p, docSpec{status: "closed"})
	if _, done, err := cw.c.ForgetClosedForTest(ctx, cw.p.sub); err != nil || !done {
		t.Fatalf("the forgetting: %v %v", done, err)
	}
	var kept bool
	if err := cw.pool.QueryRow(ctx, `SELECT user_id IS NULL AND personal_workspace IS NULL AND forgotten_at IS NOT NULL
		FROM contract_closings WHERE sub = $1`, cw.p.sub).Scan(&kept); err != nil || !kept {
		t.Fatalf("the forgotten record keeps more than the sub and the times: %v %v", kept, err)
	}
}

// A team only a replaced document named is neither pending nor created:
// records stay, and a restart keeps them.
func TestApplyCreatesOnlyTeamsADocumentLists(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	a := w.person(t)
	gone := uuid.New()
	w.put(t, a, docSpec{teams: []docTeam{{id: gone, role: "owner", name: strp("Antiga")}}})
	w.put(t, a, docSpec{})
	_, workspaces, err := w.c.PendingApply(ctx, 10)
	if err != nil || slices.Contains(workspaces, gone) {
		t.Fatalf("a team no document lists is pending: %v %v", workspaces, err)
	}
	if r, err := w.c.ApplyWorkspaceForTest(ctx, gone); err != nil || has(r, store.ApplyTeamCreated) {
		t.Fatalf("the apply of a team no document lists: %v %v", kinds(r), err)
	}
	if made, err := w.c.EnsureTeamsForTest(ctx, a.sub); err != nil || len(made) != 0 {
		t.Fatalf("EnsureTeams: %v %v", made, err)
	}
	var exists bool
	if err := w.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)`, gone).Scan(&exists); err != nil || exists {
		t.Fatalf("a team no document lists was created: %v %v", exists, err)
	}
}

// A recovery's stop revokes the person's invitations still pending from
// before it, and stops a service invited before it though redeemed after.
func TestApplyCredentialsRevokePendingInvites(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	p := w.person(t)
	team := w.team(t, "Vendas", applyMember{p.user, "owner", ""})
	invite := func(at time.Time) uuid.UUID {
		var id uuid.UUID
		if err := w.pool.QueryRow(ctx, `INSERT INTO invites (invite_id, tenant_id, role, created_by, expires_at, created_at)
			VALUES ($1, $2, 'member', $3, clock_timestamp() + interval '7 days', $4) RETURNING id`, randBytes(t, 32), team, p.user, at).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	before, after := invite(w.at(t, "-2 hours")), invite(w.at(t, "-1 minute"))
	svc := w.service(t, team, p.user, w.at(t, "-2 hours"))
	w.exec(t, `UPDATE invites SET completed_at = clock_timestamp(), claimed_at = clock_timestamp() WHERE claimed_by = $1`, svc)
	at := w.at(t, "-1 hour")
	w.put(t, p, docSpec{creds: &at, teams: []docTeam{{id: team, role: "owner"}}})
	diffs, _, err := w.c.DifferencesOf(ctx, p.sub)
	if err != nil {
		t.Fatal(err)
	}
	var want store.ContractDifference
	for _, d := range diffs {
		if d.Kind == store.DiffCredentialsWouldStop {
			want = d
		}
	}
	if want.Invites != 1 || want.Services != 1 {
		t.Fatalf("credentials_would_stop: %+v", want)
	}
	r := w.apply(t, p)
	if r.Counts.Invites != 1 || r.Counts.ServicesRemoved != 1 {
		t.Fatalf("the stop: %+v", r.Counts)
	}
	revoked := func(id uuid.UUID) bool {
		var r bool
		if err := w.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM invites WHERE id = $1`, id).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if !revoked(before) || revoked(after) {
		t.Fatalf("invitations: before %v, after %v", revoked(before), revoked(after))
	}
	if role, _ := w.membership(t, team, svc); role != "" {
		t.Fatalf("the service invited before the recovery: %q", role)
	}
}

// team_closed is the apply's own suspension only: at observe, a team the
// platform's record holds closed and an operator suspended says error.
func TestSnapshotTeamClosedIsTheApplysOnly(t *testing.T) {
	w := newApplyWorld(t)
	ctx := context.Background()
	a := w.person(t)
	team := w.team(t, "Vendas", applyMember{a.user, "owner", ""})
	device := w.number(t, team)
	w.reads(t, team, device, a.user)
	w.put(t, a, docSpec{teams: []docTeam{{id: team, role: "owner", status: "closed", wversion: 2}}})
	w.exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, team)
	snap, err := w.c.Snapshot(ctx, team)
	if err != nil || len(snap.Items) != 1 || snap.Items[0].Reason != store.SnapshotError {
		t.Fatalf("an operator's suspension of a closed team: %+v %v", snap.Items, err)
	}
}
