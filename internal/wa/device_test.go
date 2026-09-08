package wa_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waSyncAction"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

// memStore records what the supervisor persists.
type memStore struct {
	mu         sync.Mutex
	statuses   []wa.Status
	identities []wa.Identity
	err        error
}

func (m *memStore) SetStatus(_ context.Context, _, _ string, s wa.Status, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses = append(m.statuses, s)
	return m.err
}

func (m *memStore) SetIdentity(_ context.Context, _, _ string, id wa.Identity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identities = append(m.identities, id)
	return m.err
}

func (m *memStore) seen() []wa.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]wa.Status(nil), m.statuses...)
}

func newDevice(t *testing.T, mode wa.ReceiptMode) (*wa.Device, *fakewa.Client, *memStore) {
	t.Helper()
	fake, store := fakewa.New(), &memStore{}
	dev, err := wa.NewDevice(wa.DeviceConfig{
		ID:       "11111111-1111-1111-1111-111111111111",
		TenantID: "22222222-2222-2222-2222-222222222222",
		Client:   fake,
		Store:    store,
		Policy:   wa.ReceiptPolicy{Mode: mode},
		Log:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Stop(context.Background()) })
	return dev, fake, store
}

// TestIncognitoStaysSilent is the reason the fake exists.
//
// A passive device that connects and receives traffic must emit no presence, no
// read receipts and never force active delivery receipts. Not calling
// SendPresence is the entire mechanism: it keeps whatsmeow's internal counter at
// zero, so delivery receipts leave typed "inactive" and official clients do not
// render them.
//
// The v1 server called SendPresence(available) unconditionally in its Connected
// handler, with a comment explaining that it made the ticks show up. This test
// is what stops that line coming back.
func TestIncognitoStaysSilent(t *testing.T) {
	dev, fake, _ := newDevice(t, wa.ModePassive)
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	fake.Emit(&events.Connected{})
	for range 25 {
		fake.Emit(&events.Message{Info: types.MessageInfo{ID: "m"}})
	}
	fake.Emit(&events.Receipt{})

	if got := fake.SendPresenceCalls(); got != 0 {
		t.Errorf("presence announced %d times in passive mode; delivery receipts will render", got)
	}
	if got := fake.MarkReadCalls(); got != 0 {
		t.Errorf("MarkRead called %d times without being asked", got)
	}
	if fake.ForceActiveReceipts() {
		t.Error("SetForceActiveDeliveryReceipts(true) was called in passive mode")
	}
	if dev.Status() != wa.StatusOnline {
		t.Errorf("status = %q, want online", dev.Status())
	}
}

// The complement, so the silence above means "suppressed" rather than "the
// policy never does anything".
func TestActiveModeAnnouncesPresence(t *testing.T) {
	dev, fake, _ := newDevice(t, wa.ModeActive)
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.Emit(&events.Connected{})

	got := fake.Presences()
	if len(got) != 1 || got[0] != types.PresenceAvailable {
		t.Fatalf("presences = %v, want exactly [available]", got)
	}
}

// Marking read is silent in the quiet posture, and this reverses an earlier
// decision on purpose.
//
// It used to send in either mode, on the grounds that it was always an explicit
// request: nothing on the ingest path called it, so asking for one was somebody
// deliberately asking. That stopped being true when the browser began marking
// messages read as they appear on screen. The request is now produced by
// looking at a conversation, and a posture that promises silence cannot have
// reading count as asking for an exception to it.
func TestMarkReadIsSilentInPassiveMode(t *testing.T) {
	_, fake, _ := newDevice(t, wa.ModePassive)
	policy := wa.ReceiptPolicy{Mode: wa.ModePassive}
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	if err := policy.MarkRead(context.Background(), fake, chat, types.EmptyJID,
		[]types.MessageID{"a", "b"}, false); err != nil {
		t.Fatal(err)
	}
	if got := fake.ReadReceipts(); len(got) != 0 {
		t.Fatalf("a read receipt left a device in the quiet posture: %+v", got)
	}
}

func TestMarkReadWorksInActiveMode(t *testing.T) {
	_, fake, _ := newDevice(t, wa.ModeActive)
	policy := wa.ReceiptPolicy{Mode: wa.ModeActive}
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	if err := policy.MarkRead(context.Background(), fake, chat, types.EmptyJID,
		[]types.MessageID{"a", "b"}, false); err != nil {
		t.Fatal(err)
	}
	receipts := fake.ReadReceipts()
	if len(receipts) != 1 || len(receipts[0].IDs) != 2 {
		t.Fatalf("receipts = %+v", receipts)
	}
	if len(receipts[0].Types) != 0 {
		t.Errorf("a plain read receipt should carry no extra type, got %v", receipts[0].Types)
	}
}

// Played is a distinct signal from read: it is what tells the sender their
// voice note was actually listened to, or their view-once was opened.
func TestMarkPlayedCarriesTheReceiptType(t *testing.T) {
	_, fake, _ := newDevice(t, wa.ModeActive)
	policy := wa.ReceiptPolicy{Mode: wa.ModeActive}
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	if err := policy.MarkRead(context.Background(), fake, chat, types.EmptyJID,
		[]types.MessageID{"a"}, true); err != nil {
		t.Fatal(err)
	}
	got := fake.ReadReceipts()[0].Types
	if len(got) != 1 || got[0] != types.ReceiptTypePlayed {
		t.Fatalf("receipt types = %v, want [played]", got)
	}
}

// Typing is the most continuous thing this account can emit — several times a
// minute, naming a conversation somebody has open right now — and it must not
// leave a device in the quiet posture.
func TestTypingIsSilentInPassiveMode(t *testing.T) {
	_, fake, _ := newDevice(t, wa.ModePassive)
	policy := wa.ReceiptPolicy{Mode: wa.ModePassive}
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	if err := policy.ChatPresence(context.Background(), fake, chat,
		types.ChatPresenceComposing, types.ChatPresenceMediaText); err != nil {
		t.Fatal(err)
	}
	if got := fake.ChatPresences(); len(got) != 0 {
		t.Fatalf("a typing notification left a device in the quiet posture: %v", got)
	}
}

func TestTypingLeavesInActiveMode(t *testing.T) {
	_, fake, _ := newDevice(t, wa.ModeActive)
	policy := wa.ReceiptPolicy{Mode: wa.ModeActive}
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	if err := policy.ChatPresence(context.Background(), fake, chat,
		types.ChatPresenceComposing, types.ChatPresenceMediaAudio); err != nil {
		t.Fatal(err)
	}
	if got := fake.ChatPresences(); len(got) != 1 {
		t.Fatalf("chat presences = %v, want one", got)
	}
}

func TestPolicyRecordsEveryDecision(t *testing.T) {
	var decisions []string
	policy := wa.ReceiptPolicy{
		Mode:     wa.ModePassive,
		Recorder: func(kind, decision string) { decisions = append(decisions, kind+":"+decision) },
	}
	fake := fakewa.New()
	ctx := context.Background()
	chat := types.JID{User: "1", Server: types.DefaultUserServer}

	_ = policy.OnConnect(ctx, fake)
	_ = policy.MarkRead(ctx, fake, chat, types.EmptyJID, []types.MessageID{"a"}, false)
	_ = policy.ChatPresence(ctx, fake, chat, types.ChatPresenceComposing, "")

	// Every outbound signal is recorded, sent or not. In the quiet posture only
	// the suppressed series moves, and that is the property a dashboard is
	// meant to make obvious: anything landing in "sent" while a device is meant
	// to be silent is the bug, and it is visible without reading any code.
	want := []string{"presence:suppressed", "read:suppressed", "typing:suppressed"}
	if len(decisions) != len(want) {
		t.Fatalf("decisions = %v, want %v", decisions, want)
	}
	for i := range want {
		if decisions[i] != want[i] {
			t.Fatalf("decisions = %v, want %v", decisions, want)
		}
	}
}

func TestStatusTransitions(t *testing.T) {
	dev, fake, store := newDevice(t, wa.ModePassive)
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	fake.Emit(&events.PairSuccess{
		ID:  types.JID{User: "5511999999999", Server: types.DefaultUserServer},
		LID: types.JID{User: "123456789", Server: types.HiddenUserServer},
	})
	fake.Emit(&events.Connected{})
	fake.Emit(&events.Disconnected{})
	fake.Emit(&events.Connected{})

	want := []wa.Status{wa.StatusPairing, wa.StatusOnline, wa.StatusOffline, wa.StatusOnline}
	got := store.seen()
	if len(got) != len(want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("status %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// Repeated identical events must not produce repeated writes. whatsmeow emits
// Connected on every successful reconnect, and a flapping network would
// otherwise write a row per flap.
func TestRepeatedStatusIsNotRewritten(t *testing.T) {
	dev, fake, store := newDevice(t, wa.ModePassive)
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		fake.Emit(&events.Connected{})
	}
	if got := store.seen(); len(got) != 1 {
		t.Fatalf("wrote %d status rows for 5 identical events: %v", len(got), got)
	}
}

// Logged out and banned are terminal. Retrying them burns connection attempts
// against a server that has already refused.
func TestTerminalStatesStopSupervision(t *testing.T) {
	for name, evt := range map[string]any{
		"logged out": &events.LoggedOut{Reason: events.ConnectFailureLoggedOut},
		"banned":     &events.TemporaryBan{Code: events.TempBanSentToTooManyPeople, Expire: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			dev, fake, _ := newDevice(t, wa.ModePassive)
			if err := dev.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			fake.Emit(evt)
			select {
			case <-dev.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("supervision did not stop after a terminal event")
			}
			if !dev.Status().Terminal() {
				t.Errorf("status = %q, want a terminal state", dev.Status())
			}
		})
	}
}

// Identity is a (lid, pn) pair and either half may be absent. A later event
// carrying only one half must not erase the other.
func TestIdentityMergeKeepsBothHalves(t *testing.T) {
	dev, fake, _ := newDevice(t, wa.ModePassive)
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	lid := types.JID{User: "123456789", Server: types.HiddenUserServer}
	pn := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	fake.Emit(&events.PairSuccess{ID: pn, LID: lid, BusinessName: "Acme Ltda"})
	fake.Emit(&events.PushNameSetting{Action: &waSyncAction.PushNameSetting{Name: proto.String("Acme")}})

	id := dev.Identity()
	if id.LID != lid || id.PN != pn {
		t.Errorf("identity = %+v, want both LID and PN preserved", id)
	}
	if id.PushName != "Acme" {
		t.Errorf("PushName = %q, want Acme", id.PushName)
	}
	if id.BusinessName != "Acme Ltda" {
		t.Errorf("BusinessName = %q; it must not be conflated with PushName", id.BusinessName)
	}
	if !id.Known() {
		t.Error("identity should be known after pairing")
	}
	if id.Primary() != lid {
		t.Errorf("Primary() = %v, want the LID", id.Primary())
	}
}

// events.PushName reports that a *contact* changed their name. Treating it as
// our own would rewrite this device's identity with a stranger's name.
func TestContactPushNameDoesNotTouchOurIdentity(t *testing.T) {
	dev, fake, _ := newDevice(t, wa.ModePassive)
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.Emit(&events.PairSuccess{
		ID:  types.JID{User: "5511999999999", Server: types.DefaultUserServer},
		LID: types.JID{User: "123456789", Server: types.HiddenUserServer},
	})
	fake.Emit(&events.PushNameSetting{Action: &waSyncAction.PushNameSetting{Name: proto.String("Mine")}})

	fake.Emit(&events.PushName{
		JID:         types.JID{User: "5511888888888", Server: types.DefaultUserServer},
		NewPushName: "Somebody Else",
	})

	if got := dev.Identity().PushName; got != "Mine" {
		t.Fatalf("PushName = %q; a contact's name leaked into our own identity", got)
	}
}

// A device that fails to connect must surface the failure rather than sit in a
// retry loop forever.
func TestStartFailsAfterExhaustingRetries(t *testing.T) {
	fake := fakewa.New()
	fake.ConnectErr = errors.New("network unreachable")
	dev, err := wa.NewDevice(wa.DeviceConfig{
		ID: "d", TenantID: "t", Client: fake, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := dev.Start(ctx); err == nil {
		t.Fatal("Start succeeded despite every connect failing")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	dev, _, _ := newDevice(t, wa.ModePassive)
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	dev.Stop(context.Background())
	dev.Stop(context.Background())
}

// Event handlers run on whatsmeow's goroutines while API handlers read state,
// which is exactly the race the v1 server had on its deviceJID field.
func TestConcurrentIdentityAccess(t *testing.T) {
	dev, fake, _ := newDevice(t, wa.ModePassive)
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			fake.Emit(&events.PairSuccess{
				ID:  types.JID{User: "5511999999999", Server: types.DefaultUserServer},
				LID: types.JID{User: "123456789", Server: types.HiddenUserServer},
			})
		}()
		go func() {
			defer wg.Done()
			_ = dev.Identity().String()
			_ = dev.Status()
			_ = i
		}()
	}
	wg.Wait()
}

func TestParseReceiptMode(t *testing.T) {
	for in, want := range map[string]wa.ReceiptMode{"passive": wa.ModePassive, "active": wa.ModeActive} {
		got, err := wa.ParseReceiptMode(in)
		if err != nil || got != want {
			t.Errorf("ParseReceiptMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := wa.ParseReceiptMode("stealth"); err == nil {
		t.Error("ParseReceiptMode accepted an unknown mode")
	}
}
