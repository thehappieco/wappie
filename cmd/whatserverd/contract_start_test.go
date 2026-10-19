package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// TestTakeHangup: a process that took SIGHUP survives one. capabilities
// prints "sighup" for every binary, so this is what makes it true: in a
// child, which Go's default would kill ("signal: hangup").
func TestTakeHangup(t *testing.T) {
	if os.Getenv("WS_TEST_HANGUP_CHILD") == "1" {
		hup, giveBack := takeHangup()
		defer giveBack()
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			os.Exit(3)
		}
		select {
		case <-hup:
			os.Exit(0)
		case <-time.After(10 * time.Second):
			os.Exit(4)
		}
	}
	//nolint:gosec // G204: the test binary itself
	cmd := exec.Command(os.Args[0], "-test.run=^TestTakeHangup$", "-test.count=1")
	cmd.Env = append(os.Environ(), "WS_TEST_HANGUP_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the child: %v\n%s", err, out)
	}
}

// lockedBuffer is a log's buffer that its goroutines and the test share.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestStartContract: serve's wiring of the contract, with no database. With
// a transport, the secret loads lazily and every SIGHUP reloads it and
// publishes the load; without one, a SIGHUP is said and ignored. In both,
// the sign-in routes get the contract's part, which calls the platform
// through the transport, or gets no answer without one.
func TestStartContract(t *testing.T) {
	// A pool never dialled: startContract only builds the store over it.
	pool, err := pgxpool.New(context.Background(), "postgres://wappie@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	old := socketOwner
	socketOwner = os.Getuid()
	t.Cleanup(func() { socketOwner = old })
	secret := membershiptest.Secret(t)
	served := membershiptest.Serve(t, membershiptest.Platform(t, secret, ""), membershiptest.SocketDir(t))
	tmp := t.TempDir()
	secretFile := filepath.Join(tmp, "contract-secret.txt")
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadedFile := filepath.Join(tmp, "contract-secrets.loaded")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logs lockedBuffer
	a := &app{
		cfg: config.Config{Contract: config.Contract{Socket: served.Path, SecretFile: secretFile, LoadedFile: loadedFile}},
		log: slog.New(slog.NewTextHandler(&logs, nil)), pools: &pg.Pools{API: pool}, ws: &wsapi.Server{},
	}
	hup := make(chan os.Signal, 1)
	a.startContract(ctx, hup)
	if a.contract == nil || a.secrets == nil {
		t.Fatal("no client or loader with a transport")
	}
	if a.members == nil || a.members.Client != a.contract || a.members.Contract == nil {
		t.Fatalf("the sign-ins' contract does not call through the transport: %+v", a.members)
	}
	if h := a.authHandler(); h.Membership == nil || h.Membership != a.members || h.Freshness != membership.Freshness(a.members) {
		t.Fatal("the sign-in routes have no contract")
	}
	if a.leader == nil || a.leader.Members != a.members || a.leader.Pool != pool {
		t.Fatalf("no leader with a transport: %+v", a.leader)
	}
	// The start line, after the ledger's: the mode the database holds (it
	// cannot be read here), the transport and the secret.
	if !strings.Contains(logs.String(), `msg="contract: mode=unknown transport=socket secret=`) {
		t.Fatalf("no start line: %s", logs.String())
	}
	eventually(t, "the lazy load", a.contract.Loaded)
	if _, err := a.contract.Feed(ctx, 0, 0); err != nil {
		t.Fatalf("a call on the loaded client: %v", err)
	}
	hup <- syscall.SIGHUP
	eventually(t, "the reload", func() bool { return a.secrets.Last().Reloads == 1 })
	eventually(t, "the published reload", func() bool {
		b, err := os.ReadFile(loadedFile)
		return err == nil && strings.Contains(string(b), "\nreloads=1\n") && strings.Contains(string(b), "\nerror=none\n")
	})
	if strings.Contains(logs.String(), secret) || !strings.Contains(logs.String(), "contract: secrets loaded") {
		t.Fatalf("logs: %s", logs.String())
	}

	// No transport: nothing loads, and a SIGHUP is said and ignored.
	var bare lockedBuffer
	b := &app{log: slog.New(slog.NewTextHandler(&bare, nil)), pools: &pg.Pools{API: pool}, ws: &wsapi.Server{}}
	hup2 := make(chan os.Signal, 1)
	b.startContract(ctx, hup2)
	hup2 <- syscall.SIGHUP
	eventually(t, "the ignored SIGHUP", func() bool { return strings.Contains(bare.String(), "nothing to reload") })
	if b.contract != nil || b.secrets != nil || b.leader != nil {
		t.Fatal("a client or a leader without a transport")
	}
	if !strings.Contains(bare.String(), `msg="contract: mode=unknown transport=none secret=missing"`) {
		t.Fatalf("no start line without a transport: %s", bare.String())
	}
	// Still the contract's part, with no client: a new account is refused
	// once the contract was observed, never given a home of Wappie's own.
	if b.members == nil || b.members.Client != nil {
		t.Fatalf("no transport: %+v", b.members)
	}
	if h := b.authHandler(); h.Membership != b.members {
		t.Fatal("the sign-in routes have no contract without a transport")
	}
	// Members built before (setup's, which the socket's acts already ask)
	// are kept, and given the transport.
	pre := &membership.Members{Contract: store.NewContract(pool), Log: a.log}
	p := &app{
		cfg: config.Config{Contract: config.Contract{Socket: served.Path, SecretFile: secretFile, LoadedFile: filepath.Join(tmp, "pre.loaded")}},
		log: a.log, pools: &pg.Pools{API: pool}, ws: &wsapi.Server{}, members: pre,
	}
	p.startContract(ctx, make(chan os.Signal, 1))
	if p.members != pre || pre.Client == nil || pre.Client != p.contract {
		t.Fatalf("setup's members were not kept with the transport: %p %p, client %p %p", p.members, pre, pre.Client, p.contract)
	}
	// Its loader publishes once, before the directory goes.
	eventually(t, "the kept members' load", func() bool {
		b, err := os.ReadFile(filepath.Join(tmp, "pre.loaded"))
		return p.contract.Loaded() && err == nil && strings.Contains(string(b), "\nerror=none\n")
	})
	// An app startContract never built members for: no contract, and no
	// typed nil the routes would take for one.
	if h := (&app{log: b.log, ws: &wsapi.Server{}}).authHandler(); h.Membership != nil {
		t.Fatal("a typed nil Membership")
	}
}

// serve's freshness hook (the plan's 4.12): setup builds the contract's
// Members once, before the socket's server, and the socket's acts, the
// sign-in routes and the connector all ask that one, which startContract
// keeps.
func TestServeWiresFreshness(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	commandEnv(t, pool, filepath.Join(t.TempDir(), "deletions.ledger"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// With WhatsApp, as serve's: the socket's server is built only then.
	a, closeAll, err := setup(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	members := a.members
	if members == nil || a.ws.Membership() != membership.Freshness(members) {
		t.Fatalf("the socket's acts ask %v, not setup's members %p", a.ws.Membership(), members)
	}
	if h := a.authHandler(); h.Freshness != membership.Freshness(members) || h.Membership != membership.SignIns(members) {
		t.Fatal("the routes ask another hook")
	}
	a.cfg.MCP = enclaveConfig()
	a.routes()
	if a.mcp == nil || a.mcp.Membership != membership.Freshness(members) {
		t.Fatal("the connector asks another hook")
	}
	a.startContract(ctx, make(chan os.Signal, 1))
	if a.members != members {
		t.Fatal("startContract built members of its own")
	}
}

// The start line carries the mode the database holds, which B1's and
// B2a's post-start gates read (contract: mode=off transport=… secret=…):
// off on a database never switched, observe once switched.
func TestContractStartLine(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := func() string {
		t.Helper()
		var logs lockedBuffer
		a := &app{log: slog.New(slog.NewTextHandler(&logs, nil)), pools: &pg.Pools{API: pool}, ws: &wsapi.Server{}}
		a.startContract(ctx, make(chan os.Signal, 1))
		return logs.String()
	}
	if out := start(); !strings.Contains(out, `msg="contract: mode=off transport=none secret=missing"`) {
		t.Fatalf("the start line of a database never switched: %s", out)
	}
	if _, err := store.NewContract(pool).SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if out := start(); !strings.Contains(out, `msg="contract: mode=observe transport=none secret=missing"`) {
		t.Fatalf("the start line once observing: %s", out)
	}
}
