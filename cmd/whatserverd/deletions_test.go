package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/config"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ledger"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The janitor's purge of deleted numbers and the operator's commands
// (decision 0038's plan, sections 7 to 9; tests 26, 44, 54, 56 and 57).

// logLine is one record a recorder kept.
type logLine struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

// recorder keeps every record, at every level, with its attributes.
type recorder struct {
	mu    sync.Mutex
	lines []logLine
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	l := logLine{level: rec.Level, msg: rec.Message, attrs: map[string]string{}}
	rec.Attrs(func(a slog.Attr) bool { l.attrs[a.Key] = a.Value.String(); return true })
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, l)
	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

// find is every record at level whose message contains msg.
func (r *recorder) find(level slog.Level, msg string) []logLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []logLine
	for _, l := range r.lines {
		if l.level == level && strings.Contains(l.msg, msg) {
			out = append(out, l)
		}
	}
	return out
}

func (r *recorder) atLeast(level slog.Level) []logLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []logLine
	for _, l := range r.lines {
		if l.level >= level {
			out = append(out, l)
		}
	}
	return out
}

// bucket is the object store: it records deletes, and hangs on the keys
// told to, until its context ends.
type bucket struct {
	mu      sync.Mutex
	deleted []string
	hang    func(key string) bool
	calls   atomic.Int32
}

func (b *bucket) Configured() bool { return true }

func (b *bucket) Delete(ctx context.Context, key string) error {
	b.calls.Add(1)
	if b.hang != nil && b.hang(key) {
		<-ctx.Done()
		return ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deleted = append(b.deleted, key)
	return nil
}

func (b *bucket) keys() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := slices.Clone(b.deleted)
	slices.Sort(out)
	return out
}

// purgeWorld is a database with workspaces whose numbers can be deleted
// and made due, and an app whose janitor purges them.
type purgeWorld struct {
	pool    *pgxpool.Pool
	devices *store.Devices
	users   *store.Users
	app     *app
	log     *recorder
	ledger  string
	n       int
}

func newPurgeWorld(t *testing.T) *purgeWorld {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	if _, err := pool.Exec(context.Background(), `CREATE TABLE whatsmeow_device (jid text PRIMARY KEY, registration_id bigint NOT NULL);
		CREATE TABLE whatsmeow_privacy_tokens (our_jid text, their_jid text, token bytea NOT NULL, timestamp bigint NOT NULL, PRIMARY KEY (our_jid, their_jid))`); err != nil {
		t.Fatal(err)
	}
	log := &recorder{}
	path := filepath.Join(t.TempDir(), "deletion-ledger.jsonl")
	w := &purgeWorld{pool: pool, devices: store.NewDevices(pool), users: store.NewUsers(pool), log: log, ledger: path}
	w.app = &app{log: slog.New(log), pools: &pg.Pools{Live: pool, History: pool, API: pool}, storage: store.NewStorage(pool),
		ledger: &ledger.File{Path: path}}
	return w
}

// workspace is a team with its owner.
func (w *purgeWorld) workspace(t *testing.T, name string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	var tenant uuid.UUID
	if err := w.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ($1) RETURNING id`, name).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	owner, err := w.users.Create(ctx, store.NewUser{TenantID: tenant, Email: name + "-owner@example.test", Role: "owner", AuthKey: "test",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	return tenant, owner.ID
}

// number is a linked number with one stored attachment, whose object key
// it returns.
func (w *purgeWorld) number(t *testing.T, tenant uuid.UUID) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	w.n++
	dev, err := w.devices.Create(ctx, tenant.String(), fmt.Sprintf("n%d", w.n), wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	pn := types.JID{User: fmt.Sprintf("55119%04d5678", w.n), Server: types.DefaultUserServer}
	if err := w.devices.SetIdentity(ctx, tenant.String(), dev.ID, wa.Identity{PN: pn}); err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(dev.ID)
	key := w.attachment(t, tenant, device, time.Now())
	return device, key
}

func (w *purgeWorld) attachment(t *testing.T, tenant, device uuid.UUID, ts time.Time) string {
	t.Helper()
	ctx := context.Background()
	uid := uuid.New()
	if _, err := store.NewMessages(w.pool).Insert(ctx, store.InsertMessage{UID: uid, TenantID: tenant, DeviceID: device, WAID: uid.String(),
		ChatKey: "chat", Kind: domain.KindMessage, Type: domain.TypeImage, Source: domain.SourceLive, TS: ts, BodySealed: []byte{1},
		Media: &store.InsertMedia{MediaType: "image", FileEncSHA256: []byte(uid.String())}}); err != nil {
		t.Fatal(err)
	}
	key := device.String() + "/" + uid.String()
	if err := store.NewMedia(w.pool).MarkDone(ctx, tenant, uid, key, 10); err != nil {
		t.Fatal(err)
	}
	return key
}

// deleteNumber deletes a number as its owner does, and moves its date by
// offset (an interval) on the database's clock.
func (w *purgeWorld) deleteNumber(t *testing.T, tenant, owner, device uuid.UUID, purgeAt string) {
	t.Helper()
	ctx := context.Background()
	if _, err := w.devices.Quarantine(ctx, tenant, owner, device, nil); err != nil {
		t.Fatal(err)
	}
	w.setPurgeAfter(t, tenant, device, purgeAt)
}

func (w *purgeWorld) setPurgeAfter(t *testing.T, tenant, device uuid.UUID, at string) {
	t.Helper()
	setPurgeAfter(t, w.pool, device, at)
}

// setPurgeAfter moves an excluded number's date on the database's clock, as
// the table's owner with its policies lifted: the quarantine scope is the
// store's own.
func setPurgeAfter(t *testing.T, pool *pgxpool.Pool, device uuid.UUID, at string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `ALTER TABLE devices DISABLE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(ctx, `UPDATE devices SET purge_after = clock_timestamp() + $2::interval WHERE id = $1 AND deleted_at IS NOT NULL`, device, at)
	if _, restore := pool.Exec(ctx, `ALTER TABLE devices ENABLE ROW LEVEL SECURITY; ALTER TABLE devices FORCE ROW LEVEL SECURITY`); restore != nil {
		t.Fatal(restore)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// exists says whether a number's row is still there, excluded or not.
func (w *purgeWorld) exists(t *testing.T, tenant, device uuid.UUID) bool {
	t.Helper()
	ctx := context.Background()
	if _, err := w.devices.Get(ctx, tenant.String(), device.String()); err == nil {
		return true
	}
	deleted, err := w.devices.ListAllDeleted(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(deleted, func(d store.OperatorDeleted) bool { return d.DeviceID == device })
}

func (w *purgeWorld) ledgerLines(t *testing.T) []ledger.Line {
	t.Helper()
	f, err := os.Open(w.ledger)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := ledger.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	return r.Lines
}

// TestMaintainPurgesExcluded is the plan's test 26: the janitor purges a
// number due, in any workspace status, and nothing before its date; the
// purge is in the ledger; a number long overdue is warned about; the valve
// holds every purge.
func TestMaintainPurgesExcluded(t *testing.T) {
	w := newPurgeWorld(t)
	ctx := context.Background()
	team, owner := w.workspace(t, "team")
	suspended, other := w.workspace(t, "suspended")
	due, dueKey := w.number(t, team)
	early, _ := w.number(t, team)
	overdue, overdueKey := w.number(t, suspended)
	w.deleteNumber(t, team, owner, due, "-1 minute")
	w.deleteNumber(t, team, owner, early, "1 minute")
	w.deleteNumber(t, suspended, other, overdue, "-3 hours")
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, suspended); err != nil {
		t.Fatal(err)
	}
	// An orphan in the suspended workspace: the orphan pass visits it too.
	if err := w.app.storage.ReserveObject(ctx, suspended, "orphan", 5); err != nil {
		t.Fatal(err)
	}

	// The valve: nothing is purged, and the pass says how many are due.
	w.app.cfg.Deletion.PurgeHold = true
	b := &bucket{}
	w.app.maintainOnce(ctx, 30*24*time.Hour, b)
	if held := w.log.find(slog.LevelWarn, "purges are held"); len(held) != 1 || held[0].attrs["due"] != "2" {
		t.Fatalf("the valve's warning: %+v", held)
	}
	if !w.exists(t, team, due) || !w.exists(t, suspended, overdue) {
		t.Fatal("a held purge purged")
	}
	w.app.cfg.Deletion.PurgeHold = false

	w.app.maintainOnce(ctx, 30*24*time.Hour, b)
	if w.exists(t, team, due) || w.exists(t, suspended, overdue) || !w.exists(t, team, early) {
		t.Fatalf("after the pass: due %v, overdue %v, early %v", w.exists(t, team, due), w.exists(t, suspended, overdue), w.exists(t, team, early))
	}
	if got, want := b.keys(), []string{dueKey, "orphan", overdueKey}; !slices.Equal(got, sorted(want)) {
		t.Fatalf("the bucket deleted %q, want %q", got, sorted(want))
	}
	purged := w.log.find(slog.LevelInfo, "number purged")
	if len(purged) != 2 {
		t.Fatalf("%d number purged lines", len(purged))
	}
	if late := w.log.find(slog.LevelWarn, "overdue"); len(late) == 0 || late[0].attrs["device"] != overdue.String() {
		t.Fatalf("no warning for the overdue number: %+v", late)
	}
	// The purges are in the ledger, as are the deletions.
	types := map[string]int{}
	for _, l := range w.ledgerLines(t) {
		types[l.Type]++
	}
	if types["deleted"] != 3 || types["purged"] != 2 {
		t.Fatalf("the ledger: %v", types)
	}
	if errs := w.log.atLeast(slog.LevelError); len(errs) != 0 {
		t.Fatalf("errors: %+v", errs)
	}
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// A purge that runs out of its budget says which workspaces it did not
// reach, retention still runs in the same pass, and each pass starts at the
// next workspace.
func TestMaintainPurgeBudget(t *testing.T) {
	w := newPurgeWorld(t)
	ctx := context.Background()
	a, aOwner := w.workspace(t, "a")
	bTenant, bOwner := w.workspace(t, "b")
	for _, ws := range []struct{ tenant, owner uuid.UUID }{{a, aOwner}, {bTenant, bOwner}} {
		device, _ := w.number(t, ws.tenant)
		w.deleteNumber(t, ws.tenant, ws.owner, device, "-1 minute")
	}
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET retention_days = 30 WHERE id = $1`, a); err != nil {
		t.Fatal(err)
	}
	live, _ := w.number(t, a)
	expired := w.attachment(t, a, live, time.Now().Add(-40*24*time.Hour))
	w.app.janitor.purge = time.Nanosecond
	b := &bucket{}
	turn := w.app.purgeTurn.Load()
	w.app.maintainOnce(ctx, 30*24*time.Hour, b)
	out := w.log.find(slog.LevelWarn, "ran out of its budget")
	if len(out) != 1 || !strings.Contains(out[0].attrs["not_reached"], a.String()+":1") ||
		!strings.Contains(out[0].attrs["not_reached"], bTenant.String()+":1") {
		t.Fatalf("the budget's warning: %+v", out)
	}
	if !slices.Contains(b.keys(), expired) {
		t.Fatalf("retention did not run after the purge's budget ran out: %q", b.keys())
	}
	if w.app.purgeTurn.Load() != turn+1 {
		t.Fatal("the next pass starts where this one did")
	}
	// Two passes start at two workspaces.
	tenants := []uuid.UUID{a, bTenant}
	if purgeStart(tenants, 0) == purgeStart(tenants, 1) {
		t.Fatal("two passes start at the same workspace")
	}
}

// Object deletes that hang end at their bound; after three in a row, the
// rest of the pass skips them, once warned; the purge and retention still
// run, and the skipped objects wait for the next orphan pass.
func TestMaintainObjectBreaker(t *testing.T) {
	w := newPurgeWorld(t)
	ctx := context.Background()
	team, owner := w.workspace(t, "team")
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET retention_days = 30 WHERE id = $1`, team); err != nil {
		t.Fatal(err)
	}
	device, _ := w.number(t, team)
	for range 3 {
		w.attachment(t, team, device, time.Now())
	}
	w.deleteNumber(t, team, owner, device, "-1 minute")
	live, _ := w.number(t, team)
	for range 3 {
		w.attachment(t, team, live, time.Now().Add(-40*24*time.Hour))
	}
	for i := range 3 {
		if err := w.app.storage.ReserveObject(ctx, team, fmt.Sprintf("orphan-%d", i), 5); err != nil {
			t.Fatal(err)
		}
	}
	w.app.janitor.object = 250 * time.Millisecond
	b := &bucket{hang: func(string) bool { return true }}
	start := time.Now()
	w.app.maintainOnce(ctx, 30*24*time.Hour, b)
	// Three deletes ran out of their bound (in the bucket, or before it on
	// a loaded database), and none after them reached it.
	if n := b.calls.Load(); n < 1 || n > 3 {
		t.Fatalf("%d deletes reached the bucket, want at most the breaker's 3", n)
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("the pass took %s: the deletes did not end at their bound", took)
	}
	if trip := w.log.find(slog.LevelWarn, "keep timing out"); len(trip) != 1 {
		t.Fatalf("the breaker's warning: %+v", trip)
	}
	if w.exists(t, team, device) {
		t.Fatal("the purge did not finish")
	}
	if l := w.log.find(slog.LevelInfo, "retention applied"); len(l) != 1 || l[0].attrs["messages"] != "3" {
		t.Fatalf("retention: %+v", l)
	}
	// Every object is still charged, an orphan for the next pass.
	orphans, err := w.app.storage.UnreferencedObjects(ctx, team, 1000)
	if err != nil || len(orphans) != 10 {
		t.Fatalf("orphans left: %d %v", len(orphans), err)
	}
	b.hang = nil
	w.app.maintainOnce(ctx, 30*24*time.Hour, b)
	if orphans, err := w.app.storage.UnreferencedObjects(ctx, team, 1000); err != nil || len(orphans) != 0 {
		t.Fatalf("the next pass left %d orphans: %v", len(orphans), err)
	}
}

// The janitor's retry of an unconfirmed logout gives up after its third
// attempt, and the purge then removes the session by its fingerprint (the
// plan's test 54, its purge step).
func TestPurgeRemovesAnUnconfirmedSession(t *testing.T) {
	unlinker := &fakeSessionUnlinker{err: errors.New("WhatsApp did not answer")}
	jw := newJanitorWorld(t, unlinker)
	unlinker.pool = jw.pool
	ctx := context.Background()
	device, jid := jw.deleted(t, 7)
	for range store.MaxUnlinkAttempts + 1 {
		jw.app.retryLeftoverSessions(ctx)
	}
	if n := unlinker.failed[device.String()]; n != store.MaxUnlinkAttempts {
		t.Fatalf("%d logouts tried, want %d", n, store.MaxUnlinkAttempts)
	}
	setPurgeAfter(t, jw.pool, device, "-1 minute")
	jw.app.storage = store.NewStorage(jw.pool)
	jw.app.maintainOnce(ctx, 30*24*time.Hour, &bucket{})
	var sessions int
	if err := jw.pool.QueryRow(ctx, `SELECT count(*) FROM whatsmeow_device WHERE jid = $1`, jid).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("the unconfirmed session after the purge: %d %v", sessions, err)
	}
}

// devices purge-deleted purges a workspace's due numbers as the janitor
// does, and one number now only when asked by its id.
func TestPurgeDeletedCommand(t *testing.T) {
	w := newPurgeWorld(t)
	team, owner := w.workspace(t, "team")
	due, _ := w.number(t, team)
	early, _ := w.number(t, team)
	w.deleteNumber(t, team, owner, due, "-1 minute")
	w.deleteNumber(t, team, owner, early, "20 days")
	ctx := context.Background()
	var out bytes.Buffer
	if err := purgeDeleted(ctx, w.app, &bucket{}, team.String(), "", false, &out); err != nil {
		t.Fatal(err)
	}
	if w.exists(t, team, due) || !w.exists(t, team, early) {
		t.Fatalf("the due path: due %v, early %v\n%s", w.exists(t, team, due), w.exists(t, team, early), out.String())
	}
	if len(w.log.find(slog.LevelInfo, "number purged")) != 1 {
		t.Fatal("no number purged line")
	}
	if err := purgeDeleted(ctx, w.app, &bucket{}, "", "", true, &out); err == nil {
		t.Fatal("--now with no number was accepted")
	}
	if err := purgeDeleted(ctx, w.app, &bucket{}, "", early.String(), false, &out); err == nil || !strings.Contains(err.Error(), "not due") {
		t.Fatalf("one number not due: %v", err)
	}
	if err := purgeDeleted(ctx, w.app, &bucket{}, "", early.String(), true, &out); err != nil {
		t.Fatal(err)
	}
	if w.exists(t, team, early) {
		t.Fatal("--now left the number")
	}
	var listed bytes.Buffer
	if err := listDeleted(ctx, w.app, "", &listed); err != nil || !strings.Contains(listed.String(), "0 deleted number(s)") {
		t.Fatalf("the list after both purges: %v\n%s", err, listed.String())
	}
}

// TestServeChecksLedgerBeforeStarting is the plan's test 56: in prod, the
// serve path says once, before its "starting" line, whether it can write
// the ledger, and starts either way; the operator's list works with a
// ledger it cannot write.
func TestServeChecksLedgerBeforeStarting(t *testing.T) {
	dir := t.TempDir()
	prod := config.Config{Env: config.EnvProd}
	log := &recorder{}
	lg := slog.New(log)
	checkDeletionLedger(prod, &ledger.File{Path: filepath.Join(dir, "missing", "ledger.jsonl")}, lg)
	if bad := log.find(slog.LevelError, "deletion ledger not writable"); len(bad) != 1 || !strings.Contains(bad[0].attrs["path"], "missing") {
		t.Fatalf("an unwritable ledger: %+v", log.lines)
	}
	path := filepath.Join(dir, "ledger.jsonl")
	checkDeletionLedger(prod, &ledger.File{Path: path}, lg)
	if ok := log.find(slog.LevelInfo, "deletion ledger writable"); len(ok) != 1 || ok[0].attrs["path"] != path {
		t.Fatalf("a writable ledger: %+v", log.lines)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the created ledger: %v %v", info, err)
	}
	quiet := &recorder{}
	checkDeletionLedger(config.Config{Env: config.EnvDev}, &ledger.File{Path: filepath.Join(dir, "missing", "x")}, slog.New(quiet))
	if len(quiet.lines) != 0 {
		t.Fatalf("a dev server checked its ledger: %+v", quiet.lines)
	}

	// In serve, the check comes after setup and before "starting".
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "serve" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := call.Fun.(type) {
			case *ast.Ident:
				if f.Name == "setup" || f.Name == "checkDeletionLedger" {
					order = append(order, f.Name)
				}
			case *ast.SelectorExpr:
				if f.Sel.Name != "Info" || len(call.Args) == 0 {
					return true
				}
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Value == strconv.Quote("starting") {
					order = append(order, "starting")
				}
			}
			return true
		})
	}
	if !slices.Equal(order, []string{"setup", "checkDeletionLedger", "starting"}) {
		t.Fatalf("serve's order: %v", order)
	}

	// The operator's list, with the same configuration.
	w := newPurgeWorld(t)
	w.app.cfg = prod
	w.app.ledger = &ledger.File{Path: filepath.Join(dir, "missing", "ledger.jsonl")}
	var out bytes.Buffer
	if err := listDeleted(context.Background(), w.app, "", &out); err != nil || !strings.Contains(out.String(), "not writable") {
		t.Fatalf("devices list-deleted with an unwritable ledger: %v\n%s", err, out.String())
	}
}

// testDSN is the test database's DSN for one schema: what the commands read
// from WS_POSTGRES_DSN.
func testDSN(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	schema := pool.Config().ConnConfig.RuntimeParams["search_path"]
	dsn := pgtest.DSN()
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + schema
}

// commandEnv points the commands at pool's schema, in dev.
func commandEnv(t *testing.T, pool *pgxpool.Pool, ledgerPath string) {
	t.Helper()
	t.Setenv("WS_ENV", "dev")
	t.Setenv("WS_POSTGRES_DSN", testDSN(t, pool))
	t.Setenv("WS_DELETION_LEDGER", ledgerPath)
	t.Setenv("WS_LOG_LEVEL", "error")
}

func migrationRows(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(context.Background(), `SELECT string_agg(version::text || ':' || checksum, ',' ORDER BY version) FROM schema_migrations`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestReplayRunsNoMigration is the plan's test 57: the commands that must
// never migrate refuse a database one version behind, and leave it as it
// was; at the binary's version, a dry run changes no row.
func TestReplayRunsNoMigration(t *testing.T) {
	ctx := context.Background()
	behind := pgtest.Empty(t)
	ms, err := migrate.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms[:len(ms)-1] {
		if _, err := behind.Exec(ctx, m.SQL); err != nil {
			t.Fatalf("%04d: %v", m.Version, err)
		}
	}
	if _, err := behind.Exec(ctx, `CREATE TABLE schema_migrations (version integer PRIMARY KEY, name text NOT NULL, checksum text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now(), duration_ms integer NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, m := range ms[:len(ms)-1] {
		if _, err := behind.Exec(ctx, `INSERT INTO schema_migrations (version, name, checksum, duration_ms) VALUES ($1, $2, $3, 0)`,
			m.Version, m.Name, m.Checksum); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	commandEnv(t, behind, path)
	before := migrationRows(t, behind)
	for _, args := range [][]string{
		{"deletions", "replay", "-ledger", path, "-snapshot-time", "20261014T000000Z", "-dry-run"},
		{"deletions", "export-ledger"},
		{"devices", "list-deleted"},
	} {
		var out bytes.Buffer
		var err error
		if args[0] == "devices" {
			err = devicesCommand(args[1:], &out)
		} else {
			err = deletionsCommand(args[1:], &out)
		}
		if !errors.Is(err, migrate.ErrNotCurrent) {
			t.Fatalf("%v one version behind: %v", args, err)
		}
		if after := migrationRows(t, behind); after != before {
			t.Fatalf("%v changed schema_migrations", args)
		}
	}

	// At the binary's version: a dry run changes nothing.
	w := newPurgeWorld(t)
	team, _ := w.workspace(t, "team")
	device, _ := w.number(t, team)
	var deletedAt, purgeAfter time.Time
	if err := w.pool.QueryRow(ctx, `SELECT t, t + interval '30 days' FROM (SELECT clock_timestamp() - interval '1 hour' AS t) n`).Scan(&deletedAt, &purgeAfter); err != nil {
		t.Fatal(err)
	}
	file := &ledger.File{Path: filepath.Join(t.TempDir(), "ledger.jsonl")}
	if err := file.Export(func(write func([]ledger.Line) error) error {
		return write([]ledger.Line{{V: ledger.Version, EventID: uuid.New(), Type: ledger.TypeDeleted, WorkspaceID: team, DeviceID: device,
			DeletedAt: &deletedAt, PurgeAfter: &purgeAfter, OccurredAt: deletedAt}})
	}); err != nil {
		t.Fatal(err)
	}
	commandEnv(t, w.pool, file.Path)
	before = migrationRows(t, w.pool)
	var out bytes.Buffer
	if err := deletionsCommand([]string{"replay", "-ledger", file.Path, "-snapshot-time", "20200101T000000Z", "-dry-run"}, &out); err != nil {
		t.Fatalf("a dry run: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "excluded") || !strings.Contains(out.String(), "nothing was changed") {
		t.Fatalf("the dry run's report:\n%s", out.String())
	}
	if !w.exists(t, team, device) || migrationRows(t, w.pool) != before {
		t.Fatal("a dry run changed the database")
	}
	if d, err := w.devices.Get(ctx, team.String(), device.String()); err != nil || d.Paused {
		t.Fatalf("a dry run changed the number: %+v %v", d, err)
	}
}

// TestNoMailForDeletion is the plan's test 44, release A's part: nothing on
// the paths of a deletion, a pause, a recovery, a purge, a refused removal
// or a transfer reaches a mailer, statically and in a running app with a
// mail server configured.
func TestNoMailForDeletion(t *testing.T) {
	// No package on those paths names the mailer.
	for _, dir := range []string{"../../internal/wsapi", "../../internal/store", "../../internal/ledger"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				noMailer(t, filepath.Join(dir, e.Name()))
			}
		}
	}
	for _, name := range []string{"maintain.go", "deletions.go", "excluded.go"} {
		noMailer(t, name)
	}

	// An app set up as serve sets it up, with a mail server that counts
	// every connection.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var connections atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			conn.Close()
		}
	}()
	w := newPurgeWorld(t)
	team, owner := w.workspace(t, "team")
	reader, err := w.users.Create(context.Background(), store.NewUser{TenantID: team, Email: "reader@example.test", Role: "member", AuthKey: "test",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	commandEnv(t, w.pool, w.ledger)
	t.Setenv("WS_SMTP_ADDR", listener.Addr().String())
	t.Setenv("WS_MAIL_FROM", "wappie@example.test")
	t.Setenv("WS_APP_URL", "https://wappie.example.test")
	t.Setenv("WS_SMTP_TLS", "implicit")
	ctx := context.Background()
	a, closeAll, err := setup(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	if !a.cfg.Signup.SMTP.Configured() {
		t.Fatal("the app has no mail server")
	}
	a.log = slog.New(w.log)

	// The reader alone holds the number's key and reads it.
	device, _ := w.number(t, team)
	keys := store.NewKeys(w.pool)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.CreateArchiveKey(ctx, team, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	if err := keys.PutGrant(ctx, store.Grant{TenantID: team, DeviceID: device, UserID: reader.ID, Epoch: 1, SealedDSK: []byte("grant")}, &owner); err != nil {
		t.Fatal(err)
	}
	if err := a.users.SetDevicePermission(ctx, team, owner, store.DevicePermission{DeviceID: device, UserID: reader.ID, Read: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.devices.Pause(ctx, team, device, store.PauseActor{User: owner}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.devices.Quarantine(ctx, team, owner, device, []uuid.UUID{reader.ID}); err != nil {
		t.Fatal(err)
	}
	// Removing the last key holder of a deleted number is refused.
	var stranded *store.ErrLastReaderOfDeleted
	if err := a.users.RemoveMember(ctx, team, owner, reader.ID); !errors.As(err, &stranded) {
		t.Fatalf("the removal of a deleted number's last key holder: %v", err)
	}
	if _, err := a.devices.Recover(ctx, team, owner, device); err != nil {
		t.Fatal(err)
	}
	if _, err := a.devices.Quarantine(ctx, team, owner, device, []uuid.UUID{reader.ID}); err != nil {
		t.Fatal(err)
	}
	w.setPurgeAfter(t, team, device, "-1 minute")
	a.maintainOnce(ctx, 30*24*time.Hour, &bucket{})
	if w.exists(t, team, device) {
		t.Fatal("the purge did not run")
	}
	// A move to Personal.
	moving, _ := w.number(t, team)
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	if err := a.devices.SetPaused(ctx, team.String(), moving.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.devices.TransferPersonal(ctx, team, owner, moving, personal); err != nil {
		t.Fatal(err)
	}
	a.maintainOnce(ctx, 30*24*time.Hour, &bucket{})
	time.Sleep(100 * time.Millisecond)
	if n := connections.Load(); n != 0 {
		t.Fatalf("%d connections to the mail server", n)
	}
	if types := ledgerTypes(w.ledgerLines(t)); types["deleted"] != 2 || types["recovered"] != 1 || types["purged"] != 1 || types["moved_out"] != 1 {
		t.Fatalf("the ledger: %v", types)
	}
}

func ledgerTypes(lines []ledger.Line) map[string]int {
	out := map[string]int{}
	for _, l := range lines {
		out[l.Type]++
	}
	return out
}

// noMailer fails if the Go file at path imports the mailer.
func noMailer(t *testing.T, path string) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range file.Imports {
		if imp.Path.Value == strconv.Quote("whatserver2/internal/mailer") {
			t.Errorf("%s imports the mailer", path)
		}
	}
}
