package wa_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

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
	rechecked := 0
	if err := r.Unlink(ctx, "tenant", "device", deletedJID, func(context.Context) error {
		rechecked++
		if !locker.isHeld() {
			t.Error("the re-check ran without the device lock")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if fake.Logouts() != 1 || fake.Connects() != 1 || rechecked != 1 {
		t.Fatalf("logouts %d, connects %d, re-checks %d", fake.Logouts(), fake.Connects(), rechecked)
	}
	if locker.isHeld() || locker.releases != 1 || len(r.Running()) != 0 {
		t.Fatalf("the logout left its lock (%d releases) or its reservation (%v)", locker.releases, r.Running())
	}

	// Another process holds the number: no WhatsApp call.
	locker.set(true)
	if err := r.Unlink(ctx, "tenant", "device", deletedJID, nil); !errors.Is(err, wa.ErrAlreadyRunning) {
		t.Fatalf("held elsewhere: %v", err)
	}
	locker.set(false)

	// The row was recovered meanwhile: the re-check aborts before WhatsApp.
	recovered := errors.New("recovered")
	if err := r.Unlink(ctx, "tenant", "device", deletedJID, func(context.Context) error { return recovered }); !errors.Is(err, recovered) {
		t.Fatalf("a failed re-check: %v", err)
	}
	if fake.Logouts() != 1 || fake.Connects() != 1 {
		t.Fatalf("a refused re-check reached WhatsApp: %d logouts, %d connects", fake.Logouts(), fake.Connects())
	}
}

// A number held by this process is logged out on its own client, after the
// same re-check.
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
	if err := r.Unlink(ctx, "tenant", "device", deletedJID, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	end()
	end()
	if running.Logouts() != 1 || fake.Connects() != 0 || r.Unlinking("device") {
		t.Fatalf("running logouts %d, new client connects %d, still marked %v", running.Logouts(), fake.Connects(), r.Unlinking("device"))
	}
	// A reservation (a start or a pairing in progress) is never logged out.
	r.ReserveForTest("other")
	if err := r.Unlink(ctx, "tenant", "other", deletedJID, nil); !errors.Is(err, wa.ErrAlreadyRunning) {
		t.Fatalf("a reservation: %v", err)
	}
	if held := r.Held(); len(held) != 2 {
		t.Fatalf("held = %+v", held)
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
