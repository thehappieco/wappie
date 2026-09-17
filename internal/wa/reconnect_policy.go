package wa

import (
	"context"
	"errors"
	"net/http"
	"time"

	"go.mau.fi/whatsmeow"
)

// AutoReconnectHook is an after-failure hook, not a before-connect hook. The
// HTTP transport gate also covers upstream's private connect method, used by
// automatic reconnect and post-pairing reconnect, before it dials the socket.
type connectionPolicyTransport struct {
	tenant string
	check  func(context.Context, string) error
	next   http.RoundTripper
}
type connectionPolicyError struct{ cause error }

func (e *connectionPolicyError) Error() string {
	return "wa: connection policy denied: " + e.cause.Error()
}
func (e *connectionPolicyError) Unwrap() error { return e.cause }
func (t connectionPolicyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	err := t.check(ctx, t.tenant)
	cancel()
	if err != nil {
		return nil, &connectionPolicyError{cause: err}
	}
	return t.next.RoundTrip(r)
}

// Install before the client connects. Registry creates these clients with the
// default HTTP transport; preserve its proxy, TLS and pool settings via Clone.
// Both logged-in and pre-login sockets are gated. Media clients are unchanged.
func installConnectionPolicy(client *whatsmeow.Client, tenant string, check func(context.Context, string) error) {
	if check == nil {
		return
	}
	base := http.DefaultTransport
	if transport, ok := base.(*http.Transport); ok {
		base = transport.Clone()
	}
	guarded := &http.Client{Transport: connectionPolicyTransport{tenant: tenant, check: check, next: base}}
	client.SetWebsocketHTTPClient(guarded)
	client.SetPreLoginHTTPClient(guarded)
	previous := client.AutoReconnectHook
	client.AutoReconnectHook = func(err error) bool {
		var denied *connectionPolicyError
		if errors.As(err, &denied) {
			return false
		}
		return previous == nil || previous(err)
	}
}
