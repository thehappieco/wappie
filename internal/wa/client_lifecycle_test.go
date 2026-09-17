package wa

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestProtocolAdapterInstalledBeforeConnectAndCleanedOnce(t *testing.T) {
	client := whatsmeow.NewClient(&store.Device{}, waLog.Noop)
	var attached, cleaned atomic.Int32
	r := &Registry{log: slog.Default(), devices: map[string]*entry{}}
	r.cfg.OnClient = func(tenant, device string, got *whatsmeow.Client) func() {
		if tenant != "tenant" || device != "device" || got != client || got.IsConnected() {
			t.Error("protocol adapter was installed on the wrong or connected client")
		}
		attached.Add(1)
		return func() { cleaned.Add(1) }
	}
	if _, err := r.adopt(context.Background(), "tenant", "device", ReceiptPolicy{}, client); err != nil {
		t.Fatal(err)
	}
	if attached.Load() != 1 || cleaned.Load() != 0 {
		t.Fatal("adapter did not follow device adoption")
	}
	if _, err := r.adopt(context.Background(), "tenant", "device", ReceiptPolicy{}, client); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("duplicate adoption: %v", err)
	}
	r.Stop(context.Background(), "device")
	r.Stop(context.Background(), "device")
	if attached.Load() != 1 || cleaned.Load() != 1 {
		t.Fatal("adapter must be installed and cleaned exactly once")
	}
}

func TestCancelledAdoptionCannotPublishOrLeakProtocolAdapter(t *testing.T) {
	client := whatsmeow.NewClient(&store.Device{}, waLog.Noop)
	attached := make(chan struct{})
	continueAttach := make(chan struct{})
	var cleaned atomic.Int32
	r := &Registry{log: slog.Default(), devices: map[string]*entry{}}
	r.cfg.OnClient = func(_, _ string, _ *whatsmeow.Client) func() {
		close(attached)
		<-continueAttach
		return func() { cleaned.Add(1) }
	}
	done := make(chan error, 1)
	go func() {
		_, err := r.adopt(context.Background(), "tenant", "device", ReceiptPolicy{}, client)
		done <- err
	}()
	<-attached
	r.Stop(context.Background(), "device")
	close(continueAttach)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled adoption: %v", err)
	}
	if _, exists := r.Get("device"); exists || cleaned.Load() != 1 {
		t.Fatal("cancelled adoption left a supervised client or protocol adapter")
	}
}

func TestStorageGatePreventsAdoptionBeforeAnyClientSideEffect(t *testing.T) {
	denied := errors.New("storage paused")
	r := &Registry{log: slog.Default(), devices: map[string]*entry{}}
	r.cfg.CheckStart = func(_ context.Context, tenant string) error {
		if tenant != "tenant" {
			t.Fatal(tenant)
		}
		return denied
	}
	r.cfg.OnClient = func(_, _ string, _ *whatsmeow.Client) func() { t.Fatal("attached despite suspension"); return nil }
	if _, err := r.adopt(context.Background(), "tenant", "device", ReceiptPolicy{}, nil); !errors.Is(err, denied) {
		t.Fatalf("got %v", err)
	}
	if len(r.Running()) != 0 {
		t.Fatal("suspended device registered")
	}
}
