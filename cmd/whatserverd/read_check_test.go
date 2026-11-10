package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// toldReaders records whom the read check told.
type toldReaders struct{ told []string }

func (r *toldReaders) TellRevoked(_ context.Context, reader, id string) {
	r.told = append(r.told, reader+"/"+id)
}

// TestCheckReadAtStart: serve's read check (DS48) ends a connection whose
// person does not read a number it holds, tells its reader, and logs one
// Warn line per end, with ids only and the remedy for a keyless or an
// orphan number. A connection whose person reads its number is kept and
// logged nowhere.
func TestCheckReadAtStart(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	var logs bytes.Buffer
	a := &app{log: slog.New(slog.NewTextHandler(&logs, nil)), pools: &pg.Pools{API: pool}}
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('team') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	users, keys, apiKeys := store.NewUsers(pool), store.NewKeys(pool), store.NewAPIKeys(pool)
	devices, conns := store.NewDevices(pool), store.NewMCPConnections(pool)
	account := func(email, role string) uuid.UUID {
		t.Helper()
		u, err := users.Create(ctx, store.NewUser{TenantID: tenant, Email: email, Role: role, AuthKey: "test",
			KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	owner, person := account("owner@check.test", "owner"), account("person@check.test", "admin")
	number := func(label string) uuid.UUID {
		t.Helper()
		d, err := devices.Create(ctx, tenant.String(), label, wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(d.ID)
		pub, _, err := seal.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if err := keys.CreateArchiveKey(ctx, tenant, id, 1, pub); err != nil {
			t.Fatal(err)
		}
		for _, u := range []uuid.UUID{owner, person} {
			if err := keys.PutGrant(ctx, store.Grant{TenantID: tenant, DeviceID: id, UserID: u, Epoch: 1, SealedDSK: []byte("grant"), Fingerprint: grantFingerprint(t, keys, tenant, id, 1)}, &owner); err != nil {
				t.Fatal(err)
			}
			if err := users.SetDevicePermission(ctx, tenant, owner, store.DevicePermission{DeviceID: id, UserID: u, Read: true}); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	connect := func(device uuid.UUID) string {
		t.Helper()
		in20 := time.Now().Add(20 * time.Minute)
		key, err := apiKeys.IssueActingAsForDevices(ctx, tenant.String(), "assistant", store.ScopeRead, &person, nil, []uuid.UUID{device}, &in20)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		c, err := conns.Create(ctx, tenant, person, store.CreateMCPConnection{RequestID: uuid.NewString(), KeyPrefix: prefix,
			ClientName: "Claude", RedirectHost: "claude.ai", DeviceCount: 1, ReaderKID: "0123456789abcdef",
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if err := conns.Activate(ctx, store.HostedReader, c.ID); err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	keyless, orphan, fine := number("Keyless"), number("Orphan"), number("Fine")
	onKeyless, onOrphan, onFine := connect(keyless), connect(orphan), connect(fine)
	// Left by what came before: a number with no key (epoch 0), and one
	// whose key nobody holds.
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		for _, q := range []string{`DELETE FROM device_archive_keys WHERE device_id = $1`, `UPDATE devices SET current_epoch = 0 WHERE id = $1`} {
			if _, err := tx.Exec(ctx, q, keyless); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `DELETE FROM device_key_grants WHERE device_id = $1`, orphan)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	told := &toldReaders{}
	a.checkReadAtStart(ctx, told)
	slices.Sort(told.told)
	want := []string{store.HostedReader + "/" + onKeyless, store.HostedReader + "/" + onOrphan}
	slices.Sort(want)
	if !slices.Equal(told.told, want) {
		t.Fatalf("told %v, want %v", told.told, want)
	}
	lines := map[string]string{}
	for line := range strings.Lines(logs.String()) {
		for _, id := range []string{onKeyless, onOrphan, onFine} {
			if strings.Contains(line, "connection="+id) {
				lines[id] = line
			}
		}
	}
	for id, parts := range map[string][]string{
		onKeyless: {"level=WARN", "workspace=" + tenant.String(), "reason=access_lost", "keyless=[" + keyless.String() + "]",
			`keyless_remedy="whatserverd device-key -device <id> -grant <email>, then a new consent"`},
		onOrphan: {"level=WARN", "workspace=" + tenant.String(), "orphan=[" + orphan.String() + "]",
			`orphan_remedy="a grant sealed with the printed key, or delete the number and pair it again with -grant"`},
	} {
		for _, part := range parts {
			if !strings.Contains(lines[id], part) {
				t.Errorf("the line for %s does not say %s:\n%s", id, part, lines[id])
			}
		}
	}
	if _, ok := lines[onFine]; ok || strings.Contains(logs.String(), "@check.test") {
		t.Fatalf("the log names more than the ends' ids:\n%s", logs.String())
	}
	if strings.Contains(lines[onKeyless], "orphan") || strings.Contains(lines[onOrphan], "keyless") {
		t.Fatalf("a remedy for the wrong kind:\n%s", logs.String())
	}
}

// TestServeRunsReadCheck: the read check runs in serve only, in a goroutine
// started once the listener is bound, and nowhere else: not in setupWith,
// which the command line's commands run too.
func TestServeRunsReadCheck(t *testing.T) {
	src := rawCode(t, ".")
	serve := funcBody(t, src, "serve")
	call := "go a.checkReadAtStart(ctx, &a.readers)"
	bound := strings.Index(serve, "listenPatiently(ctx, a.cfg.HTTPAddr")
	if at := strings.Index(serve, call); at < 0 || bound < 0 || at < bound {
		t.Fatalf("serve does not start the read check after the listener is bound")
	}
	if strings.Contains(funcBody(t, src, "setupWith"), "checkReadAtStart") {
		t.Fatal("setupWith runs the read check")
	}
	if n := strings.Count(src, "checkReadAtStart("); n != 2 {
		t.Fatalf("checkReadAtStart appears %d times, want its definition and serve's call", n)
	}
}

// slowReaders takes its whole bound on the first notice and records, for
// each, whether its context was already done when it came.
type slowReaders struct {
	told []string
	done []bool
}

func (r *slowReaders) TellRevoked(ctx context.Context, reader, id string) {
	r.done = append(r.done, ctx.Err() != nil)
	if len(r.told) == 0 {
		<-ctx.Done()
	}
	r.told = append(r.told, reader+"/"+id)
}

// TestReportReadCheck: what the start does with a pass's result, with no
// database. Each reader is told on a bound of its own, so one that takes
// its whole bound leaves the next its own. A narrowed connection's line
// names its numbers and their remedy, a new consent. A busy workspace is
// one Warn line with its id, and a failure one Error line.
func TestReportReadCheck(t *testing.T) {
	was := tellTimeout
	tellTimeout = 50 * time.Millisecond
	t.Cleanup(func() { tellTimeout = was })
	var logs bytes.Buffer
	a := &app{log: slog.New(slog.NewTextHandler(&logs, nil))}
	tenant, busy, number := uuid.New(), uuid.New(), uuid.New()
	res := store.ReadCheck{Ended: []store.SweptConnection{
		{EndedConnection: store.EndedConnection{ID: "slow", Reader: "enclave"}, Tenant: tenant},
		{EndedConnection: store.EndedConnection{ID: "narrowed", Reader: "enclave"}, Tenant: tenant, Narrowed: []uuid.UUID{number}},
	}, Busy: []uuid.UUID{busy}}
	told := &slowReaders{}
	a.reportReadCheck(context.Background(), told, res, errors.New("workspace x: boom"))
	if !slices.Equal(told.told, []string{"enclave/slow", "enclave/narrowed"}) || !slices.Equal(told.done, []bool{false, false}) {
		t.Fatalf("told %v, their bounds done on arrival %v", told.told, told.done)
	}
	var narrowed, skipped, failed string
	for line := range strings.Lines(logs.String()) {
		switch {
		case strings.Contains(line, "connection=narrowed"):
			narrowed = line
		case strings.Contains(line, "skipped a busy workspace"):
			skipped = line
		case strings.Contains(line, "the read check failed"):
			failed = line
		}
	}
	for _, part := range []string{"level=WARN", "workspace=" + tenant.String(), "reason=access_lost", "narrowed=[" + number.String() + "]",
		`narrowed_remedy="a new consent"`} {
		if !strings.Contains(narrowed, part) {
			t.Errorf("the narrowed line does not say %s:\n%s", part, logs.String())
		}
	}
	if strings.Contains(narrowed, "keyless") || strings.Contains(narrowed, "orphan") {
		t.Errorf("the narrowed line names another kind: %s", narrowed)
	}
	if !strings.Contains(skipped, "level=WARN") || !strings.Contains(skipped, "workspace="+busy.String()) {
		t.Errorf("the busy line: %q\n%s", skipped, logs.String())
	}
	if !strings.Contains(failed, "level=ERROR") {
		t.Errorf("the failure line: %q\n%s", failed, logs.String())
	}
}

// TestCheckReadAtStartSurvivesAPanic: the check runs in its own goroutine
// and never fails the start, so a panic in it is logged and goes no
// further. A pool that is not there panics in the first query.
func TestCheckReadAtStartSurvivesAPanic(t *testing.T) {
	var logs bytes.Buffer
	a := &app{log: slog.New(slog.NewTextHandler(&logs, nil)), pools: &pg.Pools{}}
	told := &toldReaders{}
	a.checkReadAtStart(context.Background(), told)
	if len(told.told) != 0 || !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "panic=") {
		t.Fatalf("after a panic: told %v, logged:\n%s", told.told, logs.String())
	}
}
