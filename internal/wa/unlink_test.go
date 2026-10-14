package wa_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"

	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

// lockStub is a Locker whose lock another process may hold.
type lockStub struct {
	mu       sync.Mutex
	held     bool
	releases int
}

func (l *lockStub) TryLock(context.Context, string) (func(), bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return nil, false, nil
	}
	l.held = true
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.held = false
		l.releases++
	}, true, nil
}

func unlinkRegistry(t *testing.T, locker *lockStub, checkStart func(context.Context, string) error) (*wa.Registry, *fakewa.Client) {
	t.Helper()
	fake := fakewa.New()
	fake.SetLoggedIn(true)
	r := wa.NewRegistryForTest(wa.RegistryConfig{
		Locker: locker, CheckStart: checkStart, Log: slog.Default(),
		NewClient: func(*store.Device, waLog.Logger) wa.Client { return fake },
	}, func(context.Context, types.JID) (*store.Device, error) { return &store.Device{}, nil })
	return r, fake
}

var deletedJID = types.NewJID("5511912345678", types.DefaultUserServer)

func TestUnlinkIgnoresCheckStart(t *testing.T) {
	ctx := context.Background()
	locker := &lockStub{}
	// The storage policy refuses every start: a logout captures nothing and
	// must not ask it.
	r, fake := unlinkRegistry(t, locker, func(context.Context, string) error { return errors.New("storage paused") })
	rechecked, recorded := 0, 0
	if err := r.Unlink(ctx, "tenant", "device", deletedJID, func(context.Context) error {
		rechecked++
		if !locker.isHeld() {
			t.Error("the re-check ran without the device lock")
		}
		return nil
	}, func(_ context.Context, err error) {
		recorded++
		if err != nil || !locker.isHeld() || fake.Logouts() != 1 {
			t.Errorf("the record ran with %v, lock held %v, after %d logouts", err, locker.isHeld(), fake.Logouts())
		}
	}); err != nil {
		t.Fatal(err)
	}
	if fake.Logouts() != 1 || fake.Connects() != 1 || rechecked != 1 || recorded != 1 {
		t.Fatalf("logouts %d, connects %d, re-checks %d, records %d", fake.Logouts(), fake.Connects(), rechecked, recorded)
	}
	if locker.isHeld() || locker.releases != 1 || len(r.Running()) != 0 {
		t.Fatalf("the logout left its lock (%d releases) or its reservation (%v)", locker.releases, r.Running())
	}

	// Another process holds the number: no WhatsApp call, and nothing to
	// record.
	locker.set(true)
	if err := r.Unlink(ctx, "tenant", "device", deletedJID, nil, func(context.Context, error) { recorded++ }); !errors.Is(err, wa.ErrAlreadyRunning) {
		t.Fatalf("held elsewhere: %v", err)
	}
	locker.set(false)

	// The row was recovered meanwhile: the re-check aborts before WhatsApp.
	recovered := errors.New("recovered")
	if err := r.Unlink(ctx, "tenant", "device", deletedJID, func(context.Context) error { return recovered },
		func(context.Context, error) { recorded++ }); !errors.Is(err, recovered) {
		t.Fatalf("a failed re-check: %v", err)
	}
	if fake.Logouts() != 1 || fake.Connects() != 1 || recorded != 1 {
		t.Fatalf("a refused re-check reached WhatsApp: %d logouts, %d connects, %d records", fake.Logouts(), fake.Connects(), recorded)
	}
}

// A number held by this process is logged out on its own client, after the
// same re-check, once that client is logged in again.
func TestUnlinkUsesTheRunningClient(t *testing.T) {
	ctx := context.Background()
	r, fake := unlinkRegistry(t, &lockStub{}, nil)
	running := fakewa.New()
	if _, err := r.AdoptForTest(ctx, "tenant", "device", running); err != nil {
		t.Fatal(err)
	}
	end := r.BeginUnlink("device")
	if held := r.Held(); len(held) != 1 || !held[0].Unlinking || held[0].TenantID != "tenant" || held[0].Reserved {
		t.Fatalf("held = %+v", held)
	}

	// The row was recovered meanwhile: no logout, and nothing recorded.
	rechecked, recorded := 0, 0
	recovered := errors.New("recovered")
	running.SetLoggedIn(true)
	if err := r.Unlink(ctx, "tenant", "device", deletedJID, func(context.Context) error {
		rechecked++
		return recovered
	}, func(context.Context, error) { recorded++ }); !errors.Is(err, recovered) {
		t.Fatalf("a failed re-check on the running client: %v", err)
	}
	if running.Logouts() != 0 || rechecked != 1 || recorded != 0 {
		t.Fatalf("a refused re-check: %d logouts, %d re-checks, %d records", running.Logouts(), rechecked, recorded)
	}

	// The client is between reconnects: the logout waits for it.
	running.SetLoggedIn(false)
	go func() {
		time.Sleep(150 * time.Millisecond)
		running.SetLoggedIn(true)
	}()
	rechecked = 0
	if err := r.Unlink(ctx, "tenant", "device", deletedJID, func(context.Context) error {
		rechecked++
		if !running.IsLoggedIn() {
			t.Error("the logout did not wait for the running client to log in")
		}
		return nil
	}, func(_ context.Context, err error) {
		recorded++
		if err != nil || running.Logouts() != 1 {
			t.Errorf("recorded %v after %d logouts", err, running.Logouts())
		}
		if _, held := r.Get("device"); !held {
			t.Error("the record ran after the running client let go of its lock")
		}
	}); err != nil {
		t.Fatal(err)
	}
	end()
	end()
	if running.Logouts() != 1 || fake.Connects() != 0 || r.Unlinking("device") || rechecked != 1 || recorded != 1 {
		t.Fatalf("running logouts %d, new client connects %d, still marked %v, re-checks %d, records %d",
			running.Logouts(), fake.Connects(), r.Unlinking("device"), rechecked, recorded)
	}
	// A reservation (a start or a pairing in progress) is never logged out.
	r.ReserveForTest("other")
	if err := r.Unlink(ctx, "tenant", "other", deletedJID, nil, nil); !errors.Is(err, wa.ErrAlreadyRunning) {
		t.Fatalf("a reservation: %v", err)
	}
	if held := r.Held(); len(held) != 2 {
		t.Fatalf("held = %+v", held)
	}
}

// The janitor never logs out a number this process holds, or one a
// deletion is logging out here: the deletion owns that client.
func TestUnlinkLeftoverLeavesHeldNumbers(t *testing.T) {
	ctx := context.Background()
	locker := &lockStub{}
	r, fake := unlinkRegistry(t, locker, nil)
	running := fakewa.New()
	running.SetLoggedIn(true)
	if _, err := r.AdoptForTest(ctx, "tenant", "held", running); err != nil {
		t.Fatal(err)
	}
	recheck := func(context.Context) error { return nil }
	if err := r.UnlinkLeftover(ctx, "tenant", "held", deletedJID, recheck, nil); !errors.Is(err, wa.ErrAlreadyRunning) {
		t.Fatalf("a held number: %v", err)
	}
	end := r.BeginUnlink("marked")
	if err := r.UnlinkLeftover(ctx, "tenant", "marked", deletedJID, recheck, nil); !errors.Is(err, wa.ErrAlreadyRunning) {
		t.Fatalf("a number a deletion is logging out: %v", err)
	}
	ran := false
	if err := r.LockIdle(ctx, "marked", func(context.Context) error { ran = true; return nil }); !errors.Is(err, wa.ErrAlreadyRunning) || ran {
		t.Fatalf("LockIdle on a marked number: %v, ran %v", err, ran)
	}
	if err := r.LockIdle(ctx, "held", func(context.Context) error { ran = true; return nil }); !errors.Is(err, wa.ErrAlreadyRunning) || ran {
		t.Fatalf("LockIdle on a held number: %v, ran %v", err, ran)
	}
	end()
	if running.Logouts() != 0 || fake.Logouts() != 0 {
		t.Fatalf("the janitor logged out a number it does not own: %d, %d", running.Logouts(), fake.Logouts())
	}
	// The stub has one lock for every key, and the running client holds it.
	r.Stop(ctx, "held")
	// An idle number: under the lock.
	if err := r.UnlinkLeftover(ctx, "tenant", "marked", deletedJID, recheck, nil); err != nil || fake.Logouts() != 1 {
		t.Fatalf("an idle number: %v, %d logouts", err, fake.Logouts())
	}
	if err := r.LockIdle(ctx, "idle", func(context.Context) error {
		ran = true
		if !locker.isHeld() {
			t.Error("LockIdle ran without the device lock")
		}
		return nil
	}); err != nil || !ran || locker.isHeld() {
		t.Fatalf("LockIdle: %v, ran %v, still locked %v", err, ran, locker.isHeld())
	}
	locker.set(true)
	if err := r.LockIdle(ctx, "idle", func(context.Context) error { return nil }); !errors.Is(err, wa.ErrAlreadyRunning) {
		t.Fatalf("LockIdle while another process holds the lock: %v", err)
	}
}

// Unlink's errors are logged by the deletion and the janitor: they name the
// device, never the session's JID, which is the phone number.
func TestUnlinkErrorsNameNoPhone(t *testing.T) {
	ctx := context.Background()
	for name, load := range map[string]func(context.Context, types.JID) (*store.Device, error){
		"no session": func(context.Context, types.JID) (*store.Device, error) { return nil, nil },
		"load error": func(context.Context, types.JID) (*store.Device, error) {
			return nil, errors.New("database unavailable")
		},
	} {
		r := wa.NewRegistryForTest(wa.RegistryConfig{Locker: &lockStub{}, Log: slog.Default()}, load)
		var recorded error
		err := r.Unlink(ctx, "tenant", "6f1c2a3b-device", deletedJID, nil, func(_ context.Context, err error) { recorded = err })
		if err == nil || strings.Contains(err.Error(), deletedJID.User) || strings.Contains(err.Error(), "@") {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "no session" && (!errors.Is(err, wa.ErrNoSession) || !errors.Is(recorded, wa.ErrNoSession)) {
			t.Fatalf("a session gone: %v, recorded %v", err, recorded)
		}
	}
}

func (l *lockStub) isHeld() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held
}

func (l *lockStub) set(held bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held = held
}
