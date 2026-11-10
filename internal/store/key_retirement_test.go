package store_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/store"
)

// whatserverd tokens retire-keys (step 7's plan, 7.1, 7.2 and 10.7).

// retireWorld is a workspace at observe with connections in it, where a
// test makes keys and service accounts, then turns tokens on.
type retireWorld struct {
	*ownWorld
}

func newRetireWorld(t *testing.T) *retireWorld {
	t.Helper()
	return &retireWorld{ownWorld: newOwnWorld(t)}
}

// tokensOn turns the token mode on, as contract tokens on leaves it.
func (w *retireWorld) tokensOn(t *testing.T) {
	t.Helper()
	w.exec(t, `UPDATE contract_token_state SET mode = 'on'`)
}

// key issues a key of the workspace by creator (nil for the command
// line's), unchecked, and returns its text.
func (w *retireWorld) key(t *testing.T, name string, scope store.KeyScope, creator, actsAs *uuid.UUID, devices []uuid.UUID, expires *time.Time) string {
	t.Helper()
	key, err := w.apiKeys.IssueActingAsForDevices(context.Background(), w.tenant.String(), name, scope, creator, actsAs, devices, expires)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return key
}

// standing is a standing service account of the workspace, registered by
// the owner's invitation, that reads devices.
func (w *retireWorld) standing(t *testing.T, devices ...uuid.UUID) uuid.UUID {
	t.Helper()
	svc := w.serviceOf(t, false)
	for _, d := range devices {
		w.reads(t, svc, d)
	}
	return svc
}

// keyState is a key's revocation as the table holds it.
type keyState struct {
	revokedAt *time.Time
	reason    string
}

func (w *retireWorld) keyState(t *testing.T, key string) keyState {
	t.Helper()
	prefix, _, _ := strings.Cut(key, ".")
	var s keyState
	if err := w.pool.QueryRow(context.Background(), `SELECT revoked_at, coalesce(revoke_reason, '') FROM api_keys WHERE prefix = $1`, prefix).
		Scan(&s.revokedAt, &s.reason); err != nil {
		t.Fatal(err)
	}
	return s
}

// member reports whether user is still a member of the workspace.
func (w *retireWorld) member(t *testing.T, user uuid.UUID) bool {
	t.Helper()
	return w.count(t, `SELECT count(*) FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2`, w.tenant, user) == 1
}

// service is the retirement's line for user.
func service(t *testing.T, r store.KeyRetirement, user uuid.UUID) store.RetireService {
	t.Helper()
	for _, ws := range r.Workspaces {
		for _, s := range ws.Services {
			if s.UserID == user {
				return s
			}
		}
	}
	t.Fatalf("no line for service %s", user)
	return store.RetireService{}
}

// apply runs the retirement with the dry run's own count, and checks that
// the dry run said what it then did.
func (w *retireWorld) apply(t *testing.T) store.KeyRetirement {
	t.Helper()
	ctx := context.Background()
	plan, err := w.apiKeys.RetirePlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done, err := w.apiKeys.Retire(ctx, plan.Revoke, "root")
	if err != nil {
		t.Fatal(err)
	}
	if done.Revoke != plan.Revoke || done.Removed != plan.Removed || done.Kept != plan.Kept || len(done.Workspaces) != len(plan.Workspaces) {
		t.Fatalf("the apply %+v is not its dry run %+v", done, plan)
	}
	for i := range plan.Workspaces {
		p, d := plan.Workspaces[i], done.Workspaces[i]
		if !slices.EqualFunc(p.Keys, d.Keys, func(a, b store.RetireKey) bool { return a.ID == b.ID && a.Retire == b.Retire && a.Class == b.Class }) ||
			!slices.Equal(p.Services, d.Services) {
			t.Fatalf("workspace %s: the apply did not do what the dry run said:\n%+v\n%+v", p.ID, p, d)
		}
	}
	return done
}

// TestRetireRevokesOnlyTheRESTKeys: one live key per class. A connection's
// key (metadata, content, AI, a connection token), a setup in flight and
// the old local MCP tokens (with an mcp-… service, with none, and one
// whose creator was deleted) are kept; a panel's key, REST keys acting as
// a standing service and as an old token's service, and the command
// line's key are revoked at the apply's time with platform_tokens. Keys
// already revoked or expired are untouched. The kept keys still
// authenticate on REST and the socket (VerifyClient), but the setup in
// flight, which works only through its connection.
func TestRetireRevokesOnlyTheRESTKeys(t *testing.T) {
	w := newRetireWorld(t)
	ctx := context.Background()
	device := w.shared
	devices := []uuid.UUID{device}
	in20 := time.Now().Add(20 * time.Minute)
	owner := &w.owner

	// The connections' keys, by their service or their prefix.
	conns := map[string]string{}
	for _, kind := range []string{store.KindMetadata, store.KindContent, store.KindAI} {
		id, _ := w.connect(t, w.owner, kind, device)
		conns[kind] = id
	}
	token := clientConsent(w.prepare(t, w.owner, store.KindMetadata, device), store.ClientToken, store.TrustUnknown)
	tok, err := w.conns.Create(ctx, w.tenant, w.owner, token)
	if err != nil {
		t.Fatal(err)
	}
	conns["token"] = tok.ID
	var connKeys []string
	rows, err := w.pool.Query(ctx, `SELECT k.prefix FROM mcp_connections c JOIN api_keys k ON k.id = c.api_key_id WHERE c.id::text = ANY ($1)`,
		[]string{conns[store.KindMetadata], conns[store.KindContent], conns[store.KindAI], conns["token"]})
	if err != nil {
		t.Fatal(err)
	}
	connKeys, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(connKeys) != 4 {
		t.Fatalf("the connections' keys: %v %v", connKeys, err)
	}

	legacyService := w.standing(t, device)
	erp := w.standing(t, device)
	kept := map[string]string{
		"a setup in flight":                      w.key(t, "MCP · Claude", store.ScopeRead, owner, nil, devices, &in20),
		"an old token with its mcp-… service":    w.key(t, "MCP · Claude", store.ScopeRead, owner, &legacyService, devices, nil),
		"an old token with no service":           w.key(t, "MCP · Cursor", store.ScopeRead, owner, nil, devices, nil),
		"an old token whose creator was deleted": w.key(t, "MCP · Desktop", store.ScopeRead, owner, nil, devices, nil),
	}
	w.exec(t, `UPDATE api_keys SET created_by = NULL WHERE prefix = $1`, strings.SplitN(kept["an old token whose creator was deleted"], ".", 2)[0])
	retired := map[string]string{
		"a panel's full key":                  w.key(t, "deploy bot", store.ScopeFull, owner, nil, nil, nil),
		"a REST key acting as a service":      w.key(t, "erp", store.ScopeSend, owner, &erp, devices, nil),
		"a REST key acting as an old token's": w.key(t, "MCP helper", store.ScopeRead, owner, &legacyService, nil, nil),
		"the command line's key":              w.key(t, "cli", store.ScopeFull, nil, nil, nil, nil),
	}
	revoked := w.key(t, "old", store.ScopeFull, owner, nil, nil, nil)
	prefix, _, _ := strings.Cut(revoked, ".")
	if err := w.apiKeys.Revoke(ctx, w.tenant.String(), prefix); err != nil {
		t.Fatal(err)
	}
	soon := time.Now().Add(time.Hour)
	expired := w.key(t, "expired", store.ScopeFull, owner, nil, nil, &soon)
	w.exec(t, `UPDATE api_keys SET expires_at = clock_timestamp() - interval '1 minute' WHERE prefix = $1`, strings.SplitN(expired, ".", 2)[0])
	before := map[string]keyState{"revoked": w.keyState(t, revoked), "expired": w.keyState(t, expired)}

	w.tokensOn(t)
	done := w.apply(t)
	if done.Revoke != len(retired) {
		t.Fatalf("revoked %d keys, want %d", done.Revoke, len(retired))
	}
	for name, key := range retired {
		s := w.keyState(t, key)
		if s.revokedAt == nil || !s.revokedAt.Equal(done.AppliedAt) || s.reason != store.RevokeReasonPlatformTokens {
			t.Errorf("%s: %+v, want revoked at %v for platform_tokens", name, s, done.AppliedAt)
		}
		if _, err := w.apiKeys.VerifyClient(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
			t.Errorf("%s still authenticates: %v", name, err)
		}
	}
	for name, key := range kept {
		if s := w.keyState(t, key); s.revokedAt != nil || s.reason != "" {
			t.Errorf("%s was revoked: %+v", name, s)
		}
		_, err := w.apiKeys.VerifyClient(ctx, key)
		if name == "a setup in flight" {
			if !errors.Is(err, store.ErrInvalidKey) {
				t.Errorf("a setup in flight works with no connection: %v", err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s no longer authenticates: %v", name, err)
		}
	}
	for _, p := range connKeys {
		var revokedAt *time.Time
		if err := w.pool.QueryRow(ctx, `SELECT revoked_at FROM api_keys WHERE prefix = $1`, p).Scan(&revokedAt); err != nil || revokedAt != nil {
			t.Errorf("a connection's key %s: %v %v", p, revokedAt, err)
		}
	}
	for name, s := range before {
		key := map[string]string{"revoked": revoked, "expired": expired}[name]
		if after := w.keyState(t, key); after.reason != "" || (s.revokedAt == nil) != (after.revokedAt == nil) ||
			s.revokedAt != nil && !s.revokedAt.Equal(*after.revokedAt) {
			t.Errorf("the %s key changed: %+v to %+v", name, s, after)
		}
	}
	// The old token's service is kept for its spared key; erp, whose one
	// key was retired, goes, as the owner reads its number.
	if s := service(t, done, legacyService); s.Remove || s.Reason != store.KeptSparedKey || !w.member(t, legacyService) {
		t.Errorf("the old token's service: %+v", s)
	}
	if s := service(t, done, erp); !s.Remove || w.member(t, erp) {
		t.Errorf("erp: %+v", s)
	}
	var row struct {
		revoked, removed, kept int
		by                     string
		keys                   int
	}
	if err := w.pool.QueryRow(ctx, `SELECT revoked, services_removed, services_kept, by, jsonb_array_length(report->'keys')
		FROM key_retirements WHERE applied_at = $1`, done.AppliedAt).Scan(&row.revoked, &row.removed, &row.kept, &row.by, &row.keys); err != nil {
		t.Fatal(err)
	}
	if row.revoked != len(retired) || row.removed != 1 || row.kept != 1 || row.by != "root" || row.keys != len(retired) {
		t.Fatalf("the record: %+v", row)
	}
	var counted int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE revoked_at = $1 AND revoke_reason = 'platform_tokens'`,
		done.AppliedAt).Scan(&counted); err != nil || counted != row.revoked {
		t.Fatalf("%d keys revoked at the apply's time, the record says %d: %v", counted, row.revoked, err)
	}
}

// retireCase is one standing service account with a retired key acting as
// it, on a number of its own.
type retireCase struct {
	service, number uuid.UUID
}

// retiring makes a standing service account that reads a new number and
// that a REST key acts as.
func (w *retireWorld) retiring(t *testing.T, label string) retireCase {
	t.Helper()
	c := retireCase{number: w.number(t, label)}
	c.service = w.standing(t, c.number)
	w.key(t, label, store.ScopeRead, &w.owner, &c.service, nil, nil)
	return c
}

// grantOnly gives user a grant on device at epoch 1, and takes the Read
// the grant's permission row starts with (0023) away.
func (w *retireWorld) grantOnly(t *testing.T, user, device uuid.UUID) {
	t.Helper()
	w.grantAt(t, device, user, 1)
	w.scoped(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, device, user)
		return err
	})
}

// inScope runs sql in the workspace, failing unless it changed a row.
func (w *retireWorld) inScope(t *testing.T, sql string, args ...any) {
	t.Helper()
	w.scoped(t, func(tx pgx.Tx) error {
		tag, err := tx.Exec(context.Background(), sql, args...)
		if err == nil && tag.RowsAffected() == 0 {
			t.Fatalf("%s changed nothing", sql)
		}
		return err
	})
}

// noStranding counts what a removal must never make: item.stranded events
// and notices.
func (w *retireWorld) noStranding(t *testing.T) int {
	t.Helper()
	return w.count(t, `SELECT (SELECT count(*) FROM item_events WHERE type = 'stranded') + (SELECT count(*) FROM device_notices)`)
}

// TestRetireRemovesAStandingServiceOnlyWhenAHumanReaderRemains: a service
// a retired key acted as goes only where every number it holds a key of
// at an epoch not retired keeps another holder who is human (an active
// person with Read and no deadline). A sole holder is kept; one whose
// only grant is at a retired epoch goes; one with a human backup goes,
// with a history row; one whose only backup is another standing service,
// a disabled person, a person without Read or a connection's account is
// kept. A service kept at the first run goes at a later one once a human
// backup exists. Nothing is stranded, and no notice is raised.
func TestRetireRemovesAStandingServiceOnlyWhenAHumanReaderRemains(t *testing.T) {
	w := newRetireWorld(t)
	sole := w.retiring(t, "sole")
	retiredEpoch := w.retiring(t, "retired epoch")
	w.epochKey(t, retiredEpoch.number, 2)
	w.inScope(t, `UPDATE device_archive_keys SET retired_at = clock_timestamp() WHERE device_id = $1 AND epoch = 1`, retiredEpoch.number)
	backed := w.retiring(t, "backed")
	w.reads(t, w.owner, backed.number)

	byService := w.retiring(t, "by a service")
	w.standing(t, byService.number)
	byDisabled := w.retiring(t, "by a disabled person")
	disabled := w.person(t, "disabled", "member")
	w.reads(t, disabled, byDisabled.number)
	w.disableAccount(t, disabled)
	byNoRead := w.retiring(t, "by one without Read")
	noRead := w.person(t, "noread", "member")
	w.grantOnly(t, noRead, byNoRead.number)
	byConnection := w.retiring(t, "by a connection")
	// The owner consents, then loses the number's key: the connection's
	// account is its last other holder.
	w.reads(t, w.owner, byConnection.number)
	w.connect(t, w.owner, store.KindContent, byConnection.number)
	w.inScope(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, byConnection.number, w.owner)
	later := w.retiring(t, "later")

	w.tokensOn(t)
	stranding := w.noStranding(t)
	first := w.apply(t)
	for name, c := range map[string]retireCase{"a sole holder": sole, "a service backup": byService, "a disabled backup": byDisabled,
		"a backup without Read": byNoRead, "a connection's account": byConnection, "later": later} {
		if s := service(t, first, c.service); s.Remove || s.Reason != store.KeptSoleReader || !w.member(t, c.service) {
			t.Errorf("%s: %+v, member %t", name, s, w.member(t, c.service))
		}
	}
	for name, c := range map[string]retireCase{"a retired epoch": retiredEpoch, "a human backup": backed} {
		if s := service(t, first, c.service); !s.Remove || w.member(t, c.service) {
			t.Errorf("%s: %+v", name, s)
		}
		if w.count(t, `SELECT count(*) FROM workspace_member_history WHERE tenant_id = $1 AND user_id = $2`, w.tenant, c.service) != 1 {
			t.Errorf("%s: no history row", name)
		}
		if w.count(t, `SELECT count(*) FROM device_key_grants WHERE user_id = $1`, c.service) != 0 {
			t.Errorf("%s: its grants stayed", name)
		}
	}
	if first.Removed != 2 || first.Kept != 6 {
		t.Fatalf("the first run removed %d and kept %d", first.Removed, first.Kept)
	}

	// A human backup for later; the next run takes it, from the record's
	// revoked keys, and leaves the rest.
	w.reads(t, w.owner, later.number)
	second := w.apply(t)
	if second.Revoke != 0 || second.Removed != 1 || service(t, second, later.service).Remove != true || w.member(t, later.service) {
		t.Fatalf("the second run: %+v", second)
	}
	if got := w.noStranding(t); got != stranding {
		t.Fatalf("the retirement stranded or noticed: %d, was %d", got, stranding)
	}
}

// TestRetireKeepsAServiceASparedKeyActsAs: a service that a retired key
// and a spared one (an old local token) both act as is kept while the
// spared key lives, and a later run removes it once that key is revoked.
func TestRetireKeepsAServiceASparedKeyActsAs(t *testing.T) {
	w := newRetireWorld(t)
	ctx := context.Background()
	c := w.retiring(t, "both")
	w.reads(t, w.owner, c.number)
	legacy := w.key(t, "MCP · Claude", store.ScopeRead, &w.owner, &c.service, []uuid.UUID{c.number}, nil)
	// A service no retired key acted as is never the retirement's.
	other := w.standing(t, w.shared)
	w.tokensOn(t)
	if s := service(t, w.apply(t), c.service); s.Remove || s.Reason != store.KeptSparedKey || !w.member(t, c.service) {
		t.Fatalf("with its spared key: %+v", s)
	}
	prefix, _, _ := strings.Cut(legacy, ".")
	if err := w.apiKeys.Revoke(ctx, w.tenant.String(), prefix); err != nil {
		t.Fatal(err)
	}
	if s := service(t, w.apply(t), c.service); !s.Remove || w.member(t, c.service) {
		t.Fatalf("its spared key revoked: %+v", s)
	}
	if s := service(t, w.apply(t), other); s.Remove || s.Reason != store.KeptNoRetiredKey {
		t.Fatalf("a service no retired key acted as: %+v", s)
	}
}

// TestRetireIsIdempotent: a second apply revokes nothing (its -confirm is
// 0), leaves the first's times, and is recorded.
func TestRetireIsIdempotent(t *testing.T) {
	w := newRetireWorld(t)
	ctx := context.Background()
	key := w.key(t, "deploy bot", store.ScopeFull, &w.owner, nil, nil, nil)
	w.tokensOn(t)
	first := w.apply(t)
	if first.Revoke != 1 {
		t.Fatalf("the first run revoked %d", first.Revoke)
	}
	if _, err := w.apiKeys.Retire(ctx, 1, "root"); !errors.As(err, new(*store.ErrRetireConfirm)) {
		t.Fatalf("a second run with the first's count: %v", err)
	}
	second := w.apply(t)
	if second.Revoke != 0 || second.Removed != 0 {
		t.Fatalf("the second run: %+v", second)
	}
	if s := w.keyState(t, key); s.revokedAt == nil || !s.revokedAt.Equal(first.AppliedAt) {
		t.Fatalf("the key after the second run: %+v", s)
	}
	if n := w.count(t, `SELECT count(*) FROM key_retirements`); n != 2 {
		t.Fatalf("%d records, want 2", n)
	}
}

// retireTables is what a retirement may write, row by row.
func (w *retireWorld) retireTables(t *testing.T) string {
	t.Helper()
	var out string
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT concat_ws('|',
			(SELECT string_agg(concat_ws(',', prefix, revoked_at, revoke_reason), ';' ORDER BY prefix) FROM api_keys),
			(SELECT string_agg(concat_ws(',', user_id, role, status), ';' ORDER BY user_id) FROM workspace_memberships),
			(SELECT string_agg(concat_ws(',', device_id, user_id, epoch), ';' ORDER BY device_id, user_id, epoch) FROM device_key_grants),
			(SELECT string_agg(concat_ws(',', device_id, user_id), ';' ORDER BY device_id, user_id) FROM device_permissions),
			(SELECT count(*) FROM workspace_member_history), (SELECT count(*) FROM key_retirements))`).Scan(&out)
	})
	return out
}

// TestRetireDryRunWritesNothing: the dry run lists what the apply then
// does (apply checks that), and writes nothing, not even the record.
func TestRetireDryRunWritesNothing(t *testing.T) {
	w := newRetireWorld(t)
	ctx := context.Background()
	c := w.retiring(t, "backed")
	w.reads(t, w.owner, c.number)
	w.key(t, "deploy bot", store.ScopeFull, &w.owner, nil, nil, nil)
	w.tokensOn(t)
	before := w.retireTables(t)
	plan, err := w.apiKeys.RetirePlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Revoke != 2 || plan.Removed != 1 || !plan.AppliedAt.IsZero() {
		t.Fatalf("the plan: %+v", plan)
	}
	if after := w.retireTables(t); after != before {
		t.Fatalf("the dry run wrote:\n%s\n%s", before, after)
	}
	w.apply(t)
}

// TestRetireRefusesWhileTokensAreOff: the dry run and the apply refuse
// with tokens off, and with the contract off (which turns tokens off),
// and write nothing; so does an apply whose -confirm is not the count.
func TestRetireRefusesWhileTokensAreOff(t *testing.T) {
	w := newRetireWorld(t)
	ctx := context.Background()
	w.key(t, "deploy bot", store.ScopeFull, &w.owner, nil, nil, nil)
	before := w.retireTables(t)
	refused := func(state string) {
		t.Helper()
		if _, err := w.apiKeys.RetirePlan(ctx); !errors.Is(err, store.ErrRetireNeedsTokens) {
			t.Errorf("%s: the dry run: %v", state, err)
		}
		if _, err := w.apiKeys.Retire(ctx, 1, "root"); !errors.Is(err, store.ErrRetireNeedsTokens) {
			t.Errorf("%s: the apply: %v", state, err)
		}
		if after := w.retireTables(t); after != before {
			t.Errorf("%s: something was written", state)
		}
	}
	refused("tokens off")
	w.tokensOn(t)
	if _, err := w.c.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	refused("the contract off")
	if _, err := w.c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	refused("the contract on again, tokens left off")
	w.tokensOn(t)
	var count *store.ErrRetireConfirm
	if _, err := w.apiKeys.Retire(ctx, 2, "root"); !errors.As(err, &count) || count.Confirm != 2 || count.Revoke != 1 {
		t.Fatalf("a wrong count: %v", err)
	}
	if after := w.retireTables(t); after != before {
		t.Fatal("a wrong count wrote")
	}
}

// TestRetireMakesTheSnapshotsDue: removing a service account deletes its
// grants and membership, whose dirty triggers wake the snapshot of its
// workspace; its other_backups shrink with it.
func TestRetireMakesTheSnapshotsDue(t *testing.T) {
	w := newRetireWorld(t)
	ctx := context.Background()
	c := w.retiring(t, "backed")
	w.reads(t, w.owner, c.number)
	w.tokensOn(t)
	conn, err := w.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN wappie_contract_dirty`); err != nil {
		t.Fatal(err)
	}
	if s := service(t, w.apply(t), c.service); !s.Remove {
		t.Fatalf("not removed: %+v", s)
	}
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		n, err := conn.Conn().WaitForNotification(wait)
		if err != nil {
			t.Fatalf("no dirty notice for the workspace: %v", err)
		}
		if n.Payload == w.tenant.String() {
			return
		}
	}
}
