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
// no snapshot accepted for 60 minutes (it alerts at 90), published_through
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
	execSQL(t, pool, `UPDATE contract_workspaces SET snapshot_ok_at = clock_timestamp() WHERE workspace_id = $1`, ws)

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
