package wa

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"go.mau.fi/whatsmeow"
	upstreamStore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConnectionPolicyRunsBeforeEveryTransportAttempt(t *testing.T) {
	denied := errors.New("storage paused")
	var paused atomic.Bool
	calls := 0
	guarded := connectionPolicyTransport{tenant: "tenant", check: func(_ context.Context, tenant string) error {
		if tenant != "tenant" {
			t.Fatal(tenant)
		}
		if paused.Load() {
			return denied
		}
		return nil
	}, next: transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://web.whatsapp.com/ws/chat", nil)
	response, err := guarded.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	paused.Store(true)
	response, err = guarded.RoundTrip(req)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, denied) {
		t.Fatalf("got %v", err)
	}
	if calls != 1 {
		t.Fatalf("network called %d times", calls)
	}
}

func TestUpstreamInternalConnectCannotBypassPolicy(t *testing.T) {
	client := whatsmeow.NewClient(&upstreamStore.Device{}, waLog.Noop)
	denied := errors.New("storage paused")
	installConnectionPolicy(client, "tenant", func(context.Context, string) error { return denied })
	// Exercise the actual upstream connection path with its default URL. The
	// transport gate must reject it without any network request.
	if err := client.Connect(); !errors.Is(err, denied) {
		t.Fatalf("connect bypassed gate: %v", err)
	}
	jid := types.NewJID("123", types.DefaultUserServer)
	client.Store.ID = &jid
	if err := client.Connect(); !errors.Is(err, denied) {
		t.Fatalf("logged-in connect bypassed gate: %v", err)
	}
	if client.AutoReconnectHook(&connectionPolicyError{cause: denied}) {
		t.Fatal("policy denial must end automatic retries")
	}
}

func TestConnectionPolicyPreservesExistingReconnectHook(t *testing.T) {
	client := whatsmeow.NewClient(&upstreamStore.Device{}, waLog.Noop)
	calls := 0
	client.AutoReconnectHook = func(error) bool { calls++; return false }
	installConnectionPolicy(client, "tenant", func(context.Context, string) error { return nil })
	if client.AutoReconnectHook(errors.New("network")) || calls != 1 {
		t.Fatal("existing reconnect decision lost")
	}
}
