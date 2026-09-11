package wa_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/appstate"
	"go.mau.fi/whatsmeow/proto/waSyncAction"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

// Presence can fail before initial app state supplies the push name. Keep
// attempted calls distinct from successful stanzas and inspect the deadline.
type offlineClient struct {
	*fakewa.Client
	mu           sync.Mutex
	failures     []error
	attempts     []types.Presence
	unbounded    bool
	activeOnSend bool
}

func (c *offlineClient) SendPresence(ctx context.Context, state types.Presence) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 4*time.Second {
		c.unbounded = true
	}
	if c.ActiveDeliveryReceipts() {
		c.activeOnSend = true
	}
	i := len(c.attempts)
	c.attempts = append(c.attempts, state)
	if i < len(c.failures) && c.failures[i] != nil {
		return c.failures[i]
	}
	return c.Client.SendPresence(ctx, state)
}

func (c *offlineClient) assertAttempts(t *testing.T, want int) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.attempts) != want {
		t.Fatalf("presence attempts = %v, want %d unavailable attempts", c.attempts, want)
	}
	for _, state := range c.attempts {
		if state != types.PresenceUnavailable {
			t.Fatalf("public presence %q was sent", state)
		}
	}
	if c.unbounded {
		t.Error("presence request had no short deadline")
	}
	if c.activeOnSend {
		t.Error("active delivery receipts were not reset before announcing unavailable")
	}
}

func newOfflineDevice(t *testing.T, mode wa.ReceiptMode, failures ...error) (*wa.Device, *offlineClient) {
	t.Helper()
	client := &offlineClient{Client: fakewa.New(), failures: failures}
	dev, err := wa.NewDevice(wa.DeviceConfig{
		ID: "device", TenantID: "workspace", Client: client,
		Policy: wa.ReceiptPolicy{Mode: mode}, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Stop(context.Background()) })
	return dev, client
}

func TestEveryConnectionWithdrawsPublicPresence(t *testing.T) {
	for _, mode := range []wa.ReceiptMode{wa.ModePassive, wa.ModeActive} {
		t.Run(string(mode), func(t *testing.T) {
			dev, client := newOfflineDevice(t, mode)
			// A legacy forced counter must be cleared, including after reconnect.
			for range 2 {
				client.SetForceActiveDeliveryReceipts(true)
				client.Emit(&events.Connected{})
				if !client.IsConnected() || dev.Status() != wa.StatusOnline {
					t.Fatal("withdrawing presence interrupted the transport")
				}
				if client.ActiveDeliveryReceipts() {
					t.Fatal("delivery receipts remained forced active")
				}
				client.Emit(&events.Disconnected{})
			}
			client.assertAttempts(t, 2)
			if dev.Policy().Mode != mode {
				t.Fatal("withdrawing presence changed the reading policy")
			}
		})
	}
}

func TestReadingModeChangesStayOfflineAndPreserveExplicitReads(t *testing.T) {
	dev, client := newOfflineDevice(t, wa.ModeActive)
	ctx := context.Background()
	client.Emit(&events.Connected{})
	chat := types.NewJID("5511999999999", types.DefaultUserServer)
	for _, mode := range []wa.ReceiptMode{wa.ModePassive, wa.ModeActive} {
		client.SetForceActiveDeliveryReceipts(true)
		if err := dev.SetReceiptMode(ctx, mode); err != nil {
			t.Fatal(err)
		}
		for _, played := range []bool{false, true} {
			if err := dev.Policy().MarkRead(ctx, client, chat, types.EmptyJID, []types.MessageID{"message"}, played); err != nil {
				t.Fatal(err)
			}
		}
		if mode == wa.ModePassive && client.MarkReadCalls() != 0 {
			t.Fatal("passive policy emitted read or played receipts")
		}
	}
	client.assertAttempts(t, 3)
	receipts := client.ReadReceipts()
	if len(receipts) != 2 || len(receipts[0].Types) != 0 || len(receipts[1].Types) != 1 || receipts[1].Types[0] != types.ReceiptTypePlayed {
		t.Fatalf("active explicit read/played receipts = %+v", receipts)
	}
	if client.ActiveDeliveryReceipts() || !client.IsConnected() {
		t.Fatal("explicit reading changed public presence or disconnected the client")
	}
}

func ownPushName() *events.PushNameSetting {
	return &events.PushNameSetting{Action: &waSyncAction.PushNameSetting{Name: proto.String("Test")}}
}

func TestMissingPushNameRetriesOnlyWhenSettingsAreReady(t *testing.T) {
	for _, readiness := range []string{"push name event", "initial sync without push name event"} {
		t.Run(readiness, func(t *testing.T) {
			_, client := newOfflineDevice(t, wa.ModeActive, whatsmeow.ErrNoPushName)
			client.SetForceActiveDeliveryReceipts(true)
			client.Emit(&events.Connected{})
			client.assertAttempts(t, 1)
			if client.ActiveDeliveryReceipts() {
				t.Fatal("failed presence left delivery receipts active")
			}
			// Other people's names, messages and unrelated collections do not
			// make our push name ready and must not cause presence traffic.
			client.Emit(&events.PushName{NewPushName: "Contact"})
			client.Emit(&events.Message{})
			client.Emit(&events.AppStateSyncComplete{Name: appstate.WAPatchRegular})
			client.assertAttempts(t, 1)
			if readiness == "push name event" {
				client.Emit(ownPushName())
			} else {
				client.Emit(&events.AppStateSyncComplete{Name: appstate.WAPatchCriticalBlock})
			}
			client.assertAttempts(t, 2)
			if got := client.Presences(); len(got) != 1 || got[0] != types.PresenceUnavailable {
				t.Fatalf("presence after settings became ready = %v", got)
			}
			for range 10 {
				client.Emit(ownPushName())
				client.Emit(&events.AppStateSyncComplete{Name: appstate.WAPatchCriticalBlock})
			}
			client.assertAttempts(t, 2)
		})
	}
}

func TestPresenceFailuresHaveBoundedRetriesUntilReconnect(t *testing.T) {
	failed := errors.New("presence stanza failed")
	_, client := newOfflineDevice(t, wa.ModePassive, failed, failed, failed)
	client.Emit(&events.Connected{})
	for range 20 {
		client.Emit(ownPushName())
		client.Emit(&events.AppStateSyncComplete{Name: appstate.WAPatchCriticalBlock})
	}
	client.assertAttempts(t, 3)
	client.Emit(&events.Disconnected{})
	client.Emit(&events.Connected{})
	client.assertAttempts(t, 4)
	if len(client.Presences()) != 1 {
		t.Fatal("reconnection did not retry the failed unavailable announcement")
	}
}

func TestConcurrentModeChangesAndReconnectionsNeverAnnounceOnline(t *testing.T) {
	dev, client := newOfflineDevice(t, wa.ModeActive, whatsmeow.ErrNoPushName)
	client.Emit(&events.Connected{})
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for _, mode := range []wa.ReceiptMode{wa.ModePassive, wa.ModeActive} {
				if err := dev.SetReceiptMode(context.Background(), mode); err != nil {
					t.Error(err)
				}
				_ = dev.Policy()
			}
		}()
		go func() {
			defer wg.Done()
			client.Emit(&events.Connected{})
		}()
		go func() {
			defer wg.Done()
			client.Emit(ownPushName())
			client.Emit(&events.AppStateSyncComplete{Name: appstate.WAPatchCriticalBlock})
		}()
	}
	wg.Wait()
	for _, state := range client.Presences() {
		if state != types.PresenceUnavailable {
			t.Fatalf("concurrent lifecycle changes announced %q", state)
		}
	}
	if client.ActiveDeliveryReceipts() || !client.IsConnected() {
		t.Fatal("concurrent changes enabled active receipts or disconnected transport")
	}
}
