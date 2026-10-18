package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// statusRun is contract status --check's findings and exit status.
func statusRun(t *testing.T, c *store.Contract, cfg config.Contract) (string, []string, int) {
	t.Helper()
	var out bytes.Buffer
	err := contractStatus(context.Background(), c, cfg, true, &out)
	code := 0
	var exit exitError
	switch {
	case errors.As(err, &exit):
		code = exit.code
	case err != nil:
		t.Fatal(err)
	}
	var findings []string
	for _, line := range strings.Split(out.String(), "\n") {
		if f, ok := strings.CutPrefix(line, "finding: "); ok {
			findings = append(findings, f)
		}
	}
	if (code == 1) != (len(findings) > 0) {
		t.Fatalf("exit %d with %d findings:\n%s", code, len(findings), out.String())
	}
	return out.String(), findings, code
}

func has(findings []string, part string) bool {
	for _, f := range findings {
		if strings.Contains(f, part) {
			return true
		}
	}
	return false
}

// heldSub is a person linked to a sub, with no document: one the round
// would PUT.
func heldSub(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	user, sub := uuid.New(), uuid.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, pool, user.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role, auth_source)
			VALUES ($1, $1, $2, $3, 'owner', 'platform')`, user, user.String()[:8]+"@example.com", key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	execSQL(t, pool, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'legacy')`,
		sub, user, sub.String()[:8]+"@id.test")
	return user, sub
}

func execSQL(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// TB26's and the plan's 18 findings of contract status --check, each pinned
// at both sides of its bound with literals: the feed last read over 5
// minutes ago (the platform alerts at 10), an open platform workspace with
// no snapshot accepted for 60 minutes (it alerts at 90), with the class of
// its failing snapshots, a parked workspace while on, published_through
// over an hour old, a contract ERROR in the last day, a failed secret load,
// the server's fingerprints not the files', and a database that never
// observed beside an installed secret.
func TestContractStatusCheck(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	dir := t.TempDir()
	old := defaultSealedSecret
	defaultSealedSecret = filepath.Join(dir, "absent", membership.SecretFileName)
	t.Cleanup(func() { defaultSealedSecret = old })

	// Before the first observe, with nothing installed: nothing.
	out, findings, _ := statusRun(t, c, config.Contract{})
	if len(findings) != 0 || !strings.Contains(out, "mode: off") || !strings.Contains(out, "transport: none") {
		t.Fatalf("a new installation:\n%s", out)
	}
	// A secret installed, where runtime.env says or where the installer
	// puts it, on a database that never observed: a restore from before B2.
	sealedDir := filepath.Join(dir, "sealed")
	if err := os.MkdirAll(sealedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(sealedDir, membership.SecretFileName)
	if err := os.WriteFile(secretFile, []byte("an envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, findings, code := statusRun(t, c, config.Contract{SecretFile: secretFile}); code != 1 || !has(findings, "contract never observed but a secret is installed") {
		t.Fatalf("never observed, with the configured file: %v", findings)
	}
	defaultSealedSecret = secretFile
	if _, findings, _ := statusRun(t, c, config.Contract{}); !has(findings, "contract never observed but a secret is installed") {
		t.Fatalf("never observed, with the installer's file and no settings: %v", findings)
	}
	defaultSealedSecret = filepath.Join(dir, "absent", membership.SecretFileName)

	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	// Switched a day ago: every bound counts from its own time.
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 day'`)
	read := func(ago string) {
		execSQL(t, pool, `UPDATE contract_state SET feed_read_at = clock_timestamp() - $1::interval,
			published_through = clock_timestamp() - $1::interval`, ago)
	}
	read("4 minutes")
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("observing, read 4 minutes ago: %v", findings)
	}
	read("6 minutes")
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || !has(findings, "the feed was last read") {
		t.Fatalf("read 6 minutes ago: %v", findings)
	}
	// Never read: counted from the switch.
	execSQL(t, pool, `UPDATE contract_state SET feed_read_at = NULL, published_through = clock_timestamp(),
		mode_changed_at = clock_timestamp() - interval '4 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("switched 4 minutes ago, never read: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '6 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); !has(findings, "the feed was last read never") {
		t.Fatalf("switched 6 minutes ago, never read: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 day'`)
	read("1 minute")
	execSQL(t, pool, `UPDATE contract_state SET published_through = clock_timestamp() - interval '59 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("published_through 59 minutes old: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET published_through = clock_timestamp() - interval '61 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || !has(findings, "published_through is") {
		t.Fatalf("published_through 61 minutes old: %v", findings)
	}
	read("1 minute")

	// Back to observe after an off period: the read and published_through
	// left from before it count from the switch, while the leader starts.
	read("3 days")
	for _, mode := range []string{store.ContractOff, store.ContractObserve} {
		if _, err := c.SetMode(ctx, mode); err != nil {
			t.Fatal(err)
		}
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '4 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("observing again 4 minutes, last read 3 days ago: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '6 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || !has(findings, "the feed was last read 72h") {
		t.Fatalf("observing again 6 minutes, last read 3 days ago: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '61 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 2 || !has(findings, "published_through is 72h") {
		t.Fatalf("observing again 61 minutes, last read 3 days ago: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 day'`)
	read("1 minute")

	// Held subs the round's PUTs keep failing for: 14 minutes, then 16.
	_, failing := heldSub(t, pool)
	execSQL(t, pool, `UPDATE contract_state SET round_error = 'refused:not_found', round_error_at = clock_timestamp() - interval '14 minutes'`)
	if out, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 || !strings.Contains(out, "round: PUTs failing since 14m") {
		t.Fatalf("PUTs failing for 14 minutes:\n%s", out)
	}
	execSQL(t, pool, `UPDATE contract_state SET round_error_at = clock_timestamp() - interval '16 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 ||
		!has(findings, "1 held subs not followed: their PUTs have failed since") || !has(findings, "(refused:not_found)") {
		t.Fatalf("PUTs failing for 16 minutes: %v", findings)
	}
	// Followed meanwhile (the run's end not yet recorded): nobody is left.
	gen := uuid.New()
	execSQL(t, pool, `UPDATE contract_state SET generation = $1`, gen)
	execSQL(t, pool, `INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active', '{}')`, failing, gen)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("every held sub followed: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET round_error = NULL, round_error_at = NULL`)

	// The snapshots: named 59 minutes ago with none yet, then 61.
	ws, closed := uuid.New(), uuid.New()
	execSQL(t, pool, `INSERT INTO contract_workspaces (workspace_id, kind, named_at, status) VALUES
		($1, 'personal', clock_timestamp() - interval '59 minutes', 'open'), ($2, 'team', clock_timestamp() - interval '3 hours', 'closed')`, ws, closed)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("named 59 minutes ago (and a closed team): %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_workspaces SET named_at = clock_timestamp() - interval '61 minutes' WHERE workspace_id = $1`, ws)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || !has(findings, ws.String()) {
		t.Fatalf("named 61 minutes ago, no snapshot: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_workspaces SET snapshot_ok_at = clock_timestamp() - interval '59 minutes' WHERE workspace_id = $1`, ws)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("a snapshot 59 minutes old: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_workspaces SET snapshot_ok_at = clock_timestamp() - interval '61 minutes' WHERE workspace_id = $1`, ws)
	if _, findings, _ := statusRun(t, c, config.Contract{}); !has(findings, ws.String()) {
		t.Fatalf("a snapshot 61 minutes old: %v", findings)
	}
	// Stale with its snapshots failing: the failure's class is named.
	execSQL(t, pool, `UPDATE contract_workspaces SET snapshot_error = 'unavailable:timeout', snapshot_tries = 9 WHERE workspace_id = $1`, ws)
	if out, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || !has(findings, "the last one sent: unavailable:timeout") ||
		!strings.Contains(out, "snapshot_failing=unavailable:timeout tries=9") {
		t.Fatalf("a stale snapshot failing:\n%s", out)
	}
	execSQL(t, pool, `UPDATE contract_workspaces SET snapshot_ok_at = clock_timestamp(), snapshot_error = NULL, snapshot_tries = 0
		WHERE workspace_id = $1`, ws)

	// A parked workspace, whatever its status, from the moment it parks:
	// a day of not_found, or a snapshot refused as invalid, and a closed one.
	for _, park := range []struct{ id, class, nfs string }{
		{ws.String(), "refused:not_found", "clock_timestamp() - interval '25 hours'"},
		{closed.String(), "refused:invalid_request", "NULL"},
	} {
		execSQL(t, pool, `UPDATE contract_workspaces SET parked_at = clock_timestamp(), snapshot_error = $2,
			not_found_since = `+park.nfs+` WHERE workspace_id = $1`, park.id, park.class)
		out, findings, code := statusRun(t, c, config.Contract{})
		if code != 1 || len(findings) != 1 || !has(findings, "workspace "+park.id+" is parked since") || !has(findings, park.class) ||
			!strings.Contains(out, "parked=") {
			t.Fatalf("parked (%s):\n%s", park.class, out)
		}
		execSQL(t, pool, `UPDATE contract_workspaces SET parked_at = NULL, snapshot_error = NULL, not_found_since = NULL WHERE workspace_id = $1`, park.id)
	}
	// Off, a park is not the leader's to clear: nothing is sent while off.
	execSQL(t, pool, `UPDATE contract_workspaces SET parked_at = clock_timestamp() - interval '2 days',
		snapshot_error = 'refused:invalid_request' WHERE workspace_id = $1`, ws)
	if _, err := c.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("a park while off: %v", findings)
	}
	// Back to observe: the leader's start releases a park from before the
	// switch, which is told once the switch is 2 minutes old; one since the
	// switch at once.
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if _, findings, code := statusRun(t, c, config.Contract{}); code != 0 || len(findings) != 0 {
		t.Fatalf("right after the switch, a park from before it: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 minute'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("a minute after the switch, a park from before it: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '3 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || !has(findings, "workspace "+ws.String()+" is parked since") {
		t.Fatalf("3 minutes after the switch, a park from before it: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 minute'`)
	execSQL(t, pool, `UPDATE contract_workspaces SET parked_at = clock_timestamp() - interval '30 seconds' WHERE workspace_id = $1`, ws)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || !has(findings, "workspace "+ws.String()+" is parked since") {
		t.Fatalf("a park since the switch: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 day'`)
	execSQL(t, pool, `UPDATE contract_workspaces SET parked_at = NULL, snapshot_error = NULL WHERE workspace_id = $1`, ws)

	// A contract ERROR the leader recorded: a day back.
	execSQL(t, pool, `UPDATE contract_state SET error_class = 'feed_silent', error_at = clock_timestamp() - interval '23 hours'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || !has(findings, "a contract ERROR in the last day: feed_silent") {
		t.Fatalf("an ERROR 23 hours ago: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET error_at = clock_timestamp() - interval '25 hours'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("an ERROR 25 hours ago: %v", findings)
	}

	// The server's published load against the files.
	loaded := filepath.Join(dir, "contract-secrets.loaded")
	cfg := config.Contract{Addr: "127.0.0.1:8291", SecretFile: secretFile, LoadedFile: loaded, KMSKeyARN: "a-test-key"}
	fp := membership.Fingerprint([]byte("an envelope"))
	publish := func(current, step string) {
		l := membership.Loaded{PID: 7, Reloads: 1, Current: current, Other: "none", Error: step}
		if err := os.WriteFile(loaded, []byte(l.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, findings, _ := statusRun(t, c, cfg); len(findings) != 1 || !has(findings, "published no load") {
		t.Fatalf("a secret installed, nothing published: %v", findings)
	}
	publish(fp, "none")
	if out, findings, _ := statusRun(t, c, cfg); len(findings) != 0 || !strings.Contains(out, "current="+fp) {
		t.Fatalf("the files loaded:\n%s", out)
	}
	publish(fp, membership.StepMissing)
	if _, findings, _ := statusRun(t, c, cfg); len(findings) != 0 {
		t.Fatalf("a load that found no file is no failure: %v", findings)
	}
	publish(fp, membership.StepKMS)
	if _, findings, _ := statusRun(t, c, cfg); !has(findings, "failed at step kms") {
		t.Fatalf("a failed reload: %v", findings)
	}
	publish("0123456789ab", "none")
	if _, findings, _ := statusRun(t, c, cfg); !has(findings, "the server holds current=0123456789ab") {
		t.Fatalf("fingerprints that are not the files': %v", findings)
	}
}

// TB26's printing: contract mode says what each switch did, and the return
// to observe both of its counts; the same mode again changes nothing.
func TestContractModeCommand(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	ctx := context.Background()
	for _, step := range []struct{ mode, want string }{
		{"observe", "contract mode: off -> observe"},
		{"observe", "already observe; nothing changed"},
		{"off", "contract mode: observe -> off"},
		{"observe", "events held back for good: 0"},
	} {
		var out bytes.Buffer
		if err := contractMode(ctx, c, step.mode, &out); err != nil || !strings.Contains(out.String(), step.want) {
			t.Fatalf("contract mode %s: %q %v", step.mode, out.String(), err)
		}
	}
	if err := contractModeCommand([]string{"enforce"}, &bytes.Buffer{}); !errors.As(err, &usageError{}) {
		t.Fatalf("an unknown mode: %v", err)
	}
}

// contract diff prints each difference by its kind and ids, and the count.
func TestContractDiffCommand(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	ctx := context.Background()
	var team uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('Piloto A') RETURNING id`).Scan(&team); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := contractDiff(ctx, c, uuid.Nil, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "unnamed_tenant workspace="+team.String()+"\n1 differences\n" {
		t.Fatalf("contract diff: %q", got)
	}
	if strings.Contains(out.String(), "Piloto") {
		t.Fatal("contract diff names a workspace")
	}
	out.Reset()
	if err := contractDiff(ctx, c, uuid.New(), &out); err != nil || out.String() != "0 differences\n" {
		t.Fatalf("--tenant of another: %q %v", out.String(), err)
	}
	if err := contractDiffCommand([]string{"--tenant", "nope"}, &out); err == nil {
		t.Fatal("--tenant takes an id")
	}
}

// The events' findings of contract status --check (the plan's 4.13): a
// workspace's parked events while on, counted as a parked snapshot is (a
// park since the switch to the mode at once, one from before it once the
// switch is 2 minutes old), a queue with no verdict on its batches for
// over 60 minutes, counted from the later of its first failure and the
// switch, and, whatever the cause, events pending for over 60 minutes,
// counted from the later of the oldest one's writing and the switch, told
// once with the queue's own finding; with the status lines that name them.
func TestContractStatusEvents(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	old := defaultSealedSecret
	defaultSealedSecret = filepath.Join(t.TempDir(), "absent", membership.SecretFileName)
	t.Cleanup(func() { defaultSealedSecret = old })
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 day',
		feed_read_at = clock_timestamp(), published_through = clock_timestamp()`)
	ws := uuid.New()
	execSQL(t, pool, `INSERT INTO tenants (id, name) VALUES ($1, 'Equipe')`, ws)
	execSQL(t, pool, `INSERT INTO contract_workspaces (workspace_id, kind, named_at, status, snapshot_ok_at)
		VALUES ($1, 'team', clock_timestamp() - interval '1 hour', 'open', clock_timestamp())`, ws)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("a quiet queue: %v", findings)
	}
	parked := uuid.New()
	if err := pg.InTenantTx(ctx, pool, ws.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind,
			deleted_at, purge_after, parked_at, reject_code)
			VALUES ($1, $2, 'deleted', $3, $4, clock_timestamp(), 'person', clock_timestamp(), clock_timestamp() + interval '30 days',
			clock_timestamp() - interval '1 minute', 'conflict')`, parked, ws, uuid.New(), parked.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	told := func(what string, want bool) {
		t.Helper()
		out, findings, _ := statusRun(t, c, config.Contract{})
		if got := has(findings, "workspace "+ws.String()+" has 1 events parked") && has(findings, "(conflict)"); got != want || len(findings) > 1 {
			t.Fatalf("%s: %v, want the parked events told %v\n%s", what, findings, want, out)
		}
		if !strings.Contains(out, "events pending 0 parked 1") || !strings.Contains(out, "events_parked=conflict") {
			t.Fatalf("%s: the status lines:\n%s", what, out)
		}
	}
	told("a park since the switch", true)
	// The switch after the park: told once it is 2 minutes old.
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '30 seconds'`)
	told("30 seconds after the switch, a park from before it", false)
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '3 minutes'`)
	told("3 minutes after the switch, a park from before it", true)
	// A park since a switch 30 seconds ago: at once.
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '30 seconds'`)
	if err := pg.InTenantTx(ctx, pool, ws.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE item_events SET parked_at = clock_timestamp() - interval '10 seconds' WHERE event_id = $1`, parked)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	told("a park 10 seconds old, since a switch 30 seconds ago", true)
	// Off, nothing is sent: no finding.
	if _, err := c.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	told("off", false)
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 day', feed_read_at = clock_timestamp(),
		published_through = clock_timestamp()`)
	if err := pg.InTenantTx(ctx, pool, ws.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM item_events WHERE event_id = $1`, parked)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// A queue whose batches get no verdict: 59 minutes, then 61.
	execSQL(t, pool, `UPDATE contract_workspaces SET events_error = 'unavailable:timeout', events_error_at = clock_timestamp() - interval '59 minutes',
		events_tries = 9, events_due_at = clock_timestamp() + interval '1 hour', events_not_found_since = clock_timestamp() - interval '2 hours'
		WHERE workspace_id = $1`, ws)
	out, findings, _ := statusRun(t, c, config.Contract{})
	if len(findings) != 0 || !strings.Contains(out, "events_failing=unavailable:timeout since=") || !strings.Contains(out, "tries=9") ||
		!strings.Contains(out, "events_not_found_since=") {
		t.Fatalf("no verdict for 59 minutes: %v\n%s", findings, out)
	}
	execSQL(t, pool, `UPDATE contract_workspaces SET events_error_at = clock_timestamp() - interval '61 minutes' WHERE workspace_id = $1`, ws)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 ||
		!has(findings, "workspace "+ws.String()+"'s events have had no verdict for over 60 minutes") || !has(findings, "(unavailable:timeout)") {
		t.Fatalf("no verdict for 61 minutes: %v", findings)
	}
	// Counted from the switch, when it is later.
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '30 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("no verdict for 61 minutes, switched 30 minutes ago: %v", findings)
	}

	// Events pending with no failure on the queue (a sender whose store
	// calls fail, or none at all): 59 minutes, then 61.
	execSQL(t, pool, `UPDATE contract_workspaces SET events_error = NULL, events_error_at = NULL, events_tries = 0, events_due_at = NULL,
		events_not_found_since = NULL, named_at = clock_timestamp() - interval '1 day' WHERE workspace_id = $1`, ws)
	execSQL(t, pool, `UPDATE contract_state SET events_from = clock_timestamp() - interval '1 day', mode_changed_at = clock_timestamp() - interval '1 day'`)
	pending := uuid.New()
	written := func(ago string) {
		t.Helper()
		pending := pending
		if ago == "0" {
			pending = uuid.New()
		}
		if err := pg.InTenantTx(ctx, pool, ws.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind,
				deleted_at, purge_after, created_at)
				VALUES ($1, $2, 'deleted', $3, $4, clock_timestamp() - $5::interval, 'person', clock_timestamp() - $5::interval,
				clock_timestamp() + interval '30 days', clock_timestamp() - $5::interval)
				ON CONFLICT (event_id) DO UPDATE SET created_at = excluded.created_at, occurred_at = excluded.occurred_at`,
				pending, ws, uuid.New(), pending.String(), ago)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	written("59 minutes")
	out, findings, _ = statusRun(t, c, config.Contract{})
	if len(findings) != 0 || !strings.Contains(out, "events pending 1 parked 0") || !strings.Contains(out, "events_pending_since=") {
		t.Fatalf("an event pending for 59 minutes: %v\n%s", findings, out)
	}
	// The oldest counts: a newer one beside it.
	written("61 minutes")
	written("0")
	backstop := "workspace " + ws.String() + " has 2 events pending for over 60 minutes"
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || !has(findings, backstop) {
		t.Fatalf("an event pending for 61 minutes: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '30 minutes'`)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("an event pending for 61 minutes, switched 30 minutes ago: %v", findings)
	}
	// The queue's own finding tells of them: not twice.
	execSQL(t, pool, `UPDATE contract_state SET mode_changed_at = clock_timestamp() - interval '1 day'`)
	execSQL(t, pool, `UPDATE contract_workspaces SET events_error = 'unavailable:timeout', events_error_at = clock_timestamp() - interval '61 minutes'
		WHERE workspace_id = $1`, ws)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 1 || has(findings, backstop) {
		t.Fatalf("pending, and no verdict for 61 minutes: %v", findings)
	}
	// Off, nothing is sent: no finding.
	if _, err := c.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	execSQL(t, pool, `UPDATE contract_workspaces SET events_error = NULL, events_error_at = NULL WHERE workspace_id = $1`, ws)
	if _, findings, _ := statusRun(t, c, config.Contract{}); len(findings) != 0 {
		t.Fatalf("pending while off: %v", findings)
	}
}
