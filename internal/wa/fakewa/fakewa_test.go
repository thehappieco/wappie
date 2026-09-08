package fakewa_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/wa/fakewa"
)

// This is the mechanism incognito is verified with. A device that was never
// asked to mark anything read must produce zero receipts and zero presence
// updates, and there is no way to observe that against a live client short of
// looking at the other person's phone.
func TestSilenceIsObservable(t *testing.T) {
	fake := fakewa.New()
	ctx := context.Background()

	// A busy inbound session: messages arrive, nothing is acknowledged.
	for range 50 {
		fake.Emit(&events.Message{Info: types.MessageInfo{ID: "x"}})
	}

	if got := fake.MarkReadCalls(); got != 0 {
		t.Errorf("MarkRead called %d times while incognito", got)
	}
	if got := fake.SendPresenceCalls(); got != 0 {
		t.Errorf("SendPresence called %d times while incognito", got)
	}
	if fake.ForceActiveReceipts() {
		t.Error("SetForceActiveDeliveryReceipts(true) was called while incognito")
	}

	// And the counters do move when something genuinely happens, so a passing
	// assertion above means silence rather than a broken counter.
	if err := fake.MarkRead(ctx, []types.MessageID{"x"}, time.Now(),
		types.JID{User: "1", Server: types.DefaultUserServer}, types.EmptyJID); err != nil {
		t.Fatal(err)
	}
	if got := fake.MarkReadCalls(); got != 1 {
		t.Fatalf("MarkReadCalls = %d after an explicit MarkRead, want 1", got)
	}
}

// SetForceActiveDeliveryReceipts(false) must not clear the flag once it has
// been set. Upstream stores 2 for "forced" and only SendPresence(unavailable)
// resets 1 to 0, so a false call does not undo a previous true — recording it
// as a latch keeps the fake honest about that asymmetry.
func TestForceActiveIsALatch(t *testing.T) {
	fake := fakewa.New()
	fake.SetForceActiveDeliveryReceipts(false)
	if fake.ForceActiveReceipts() {
		t.Fatal("false should not set the flag")
	}
	fake.SetForceActiveDeliveryReceipts(true)
	fake.SetForceActiveDeliveryReceipts(false)
	if !fake.ForceActiveReceipts() {
		t.Fatal("a later false must not erase the fact that true was called")
	}
}

func TestEventHandlersReceiveEvents(t *testing.T) {
	fake := fakewa.New()
	var got []string
	id := fake.AddEventHandler(func(evt any) {
		switch evt.(type) {
		case *events.Connected:
			got = append(got, "connected")
		case *events.Message:
			got = append(got, "message")
		}
	})

	fake.Emit(&events.Connected{})
	fake.Emit(&events.Message{})
	if len(got) != 2 || got[0] != "connected" || got[1] != "message" {
		t.Fatalf("handler saw %v", got)
	}

	if !fake.RemoveEventHandler(id) {
		t.Fatal("RemoveEventHandler reported the handler was not registered")
	}
	fake.Emit(&events.Connected{})
	if len(got) != 2 {
		t.Fatal("a removed handler still received events")
	}
}

func TestQRChannel(t *testing.T) {
	fake := fakewa.New()
	ch, err := fake.GetQRChannel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		fake.PushQR(whatsmeow.QRChannelItem{Event: "code", Code: "abc", Timeout: 20 * time.Second})
		fake.PushQR(whatsmeow.QRChannelSuccess)
		fake.CloseQR()
	}()

	var events []string
	for item := range ch {
		events = append(events, item.Event)
	}
	if len(events) != 2 || events[0] != "code" || events[1] != "success" {
		t.Fatalf("QR channel produced %v", events)
	}
}

// An already-paired device has no QR to show; upstream returns
// ErrQRStoreContainsID rather than a channel.
func TestQRChannelRefusedWhenAlreadyPaired(t *testing.T) {
	fake := fakewa.New()
	fake.SetLoggedIn(true)
	if _, err := fake.GetQRChannel(context.Background()); err == nil {
		t.Fatal("expected an error for an already-paired device")
	}
}

// Event handlers run on their own goroutines against a live client, so the
// fake must be safe under -race or every test built on it is unreliable.
func TestConcurrentUseIsSafe(t *testing.T) {
	fake := fakewa.New()
	fake.AddEventHandler(func(any) {})
	ctx := context.Background()
	chat := types.JID{User: "1", Server: types.DefaultUserServer}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fake.Emit(&events.Message{})
			_ = fake.MarkRead(ctx, []types.MessageID{"x"}, time.Now(), chat, types.EmptyJID)
			_ = fake.SendPresence(ctx, types.PresenceAvailable)
			_ = fake.MarkReadCalls()
			_ = fake.Sent()
		}()
	}
	wg.Wait()
	if got := fake.MarkReadCalls(); got != 20 {
		t.Errorf("MarkReadCalls = %d, want 20", got)
	}
}
