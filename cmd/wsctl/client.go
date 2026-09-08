package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"whatserver2/internal/wsapi"
)

// client multiplexes one websocket between request/response calls and a push
// stream.
//
// A single read loop owns the connection. Anything else reading directly would
// steal frames from it — which is exactly the bug this replaced: fetching a
// content key mid-stream consumed and discarded every message that arrived
// while it waited, and the watch command silently stopped after one line.
//
// Frames are routed by request id and type. The subscribe stream reuses one
// request id for every message it pushes, so the type is what separates a
// keys reply from a message that happens to share the id.
type client struct {
	conn   *websocket.Conn
	tenant string

	mu      sync.Mutex
	waiters map[waiterKey]chan wsapi.Frame

	stream chan wsapi.Frame
	done   chan struct{}
	err    error
	once   sync.Once
}

type waiterKey struct{ reqID, frameType string }

func newClient(conn *websocket.Conn) *client {
	return &client{
		conn:    conn,
		waiters: map[waiterKey]chan wsapi.Frame{},
		stream:  make(chan wsapi.Frame, 256),
		done:    make(chan struct{}),
	}
}

// run reads frames until the connection ends. It is the only reader.
func (c *client) run(ctx context.Context) {
	defer c.finish(nil)
	for {
		_, data, err := c.conn.Read(ctx)
		if err != nil {
			c.finish(err)
			return
		}
		var f wsapi.Frame
		if err := json.Unmarshal(data, &f); err != nil {
			c.finish(err)
			return
		}

		c.mu.Lock()
		ch, waiting := c.waiters[waiterKey{f.ReqID, f.Type}]
		if waiting {
			delete(c.waiters, waiterKey{f.ReqID, f.Type})
		}
		c.mu.Unlock()

		if waiting {
			ch <- f
			continue
		}
		select {
		case c.stream <- f:
		case <-ctx.Done():
			c.finish(ctx.Err())
			return
		}
	}
}

func (c *client) finish(err error) {
	c.once.Do(func() {
		c.err = err
		close(c.done)
		close(c.stream)
	})
}

// Stream yields frames nobody is specifically waiting for.
func (c *client) Stream() <-chan wsapi.Frame { return c.stream }

// Err reports why the read loop ended.
func (c *client) Err() error {
	<-c.done
	return c.err
}

// request sends a frame and waits for the reply of the expected type.
//
// The waiter is registered before the send, so a reply that arrives
// immediately cannot be routed to the stream and lost.
func (c *client) request(ctx context.Context, reqID, sendType string, payload any,
	wantType string) (wsapi.Frame, error) {
	ch := make(chan wsapi.Frame, 1)
	key := waiterKey{reqID, wantType}

	c.mu.Lock()
	if _, exists := c.waiters[key]; exists {
		c.mu.Unlock()
		return wsapi.Frame{}, fmt.Errorf("a request for %s/%s is already in flight", reqID, wantType)
	}
	c.waiters[key] = ch
	// An error reply carries the same request id, so wait for that too.
	errCh := make(chan wsapi.Frame, 1)
	errKey := waiterKey{reqID, wsapi.TypeError}
	if _, exists := c.waiters[errKey]; !exists {
		c.waiters[errKey] = errCh
	}
	c.mu.Unlock()

	cleanup := func() {
		c.mu.Lock()
		delete(c.waiters, key)
		delete(c.waiters, errKey)
		c.mu.Unlock()
	}

	if err := c.send(ctx, sendType, reqID, payload); err != nil {
		cleanup()
		return wsapi.Frame{}, err
	}

	select {
	case f := <-ch:
		cleanup()
		return f, nil
	case f := <-errCh:
		cleanup()
		return wsapi.Frame{}, protocolError(f)
	case <-c.done:
		cleanup()
		return wsapi.Frame{}, fmt.Errorf("connection closed: %w", c.err)
	case <-ctx.Done():
		cleanup()
		return wsapi.Frame{}, ctx.Err()
	}
}

func (c *client) send(ctx context.Context, frameType, reqID string, payload any) error {
	f := wsapi.Frame{Type: frameType, ReqID: reqID}
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		f.Payload = b
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return c.conn.Write(writeCtx, websocket.MessageText, b)
}

//nolint:errcheck // the peer is usually already gone by the time we close
func (c *client) close() { _ = c.conn.CloseNow() }

func dial(ctx context.Context) (*client, error) {
	url := serverURL()
	key := os.Getenv("WS_API_KEY")
	if key == "" {
		// Deliberately does not suggest bootstrap: that creates a *new*
		// tenant, and a key for a tenant with no devices in it looks like it
		// works right up until every command answers "no such device".
		return nil, errors.New("WS_API_KEY is not set. Put it in .env, or:\n\n" +
			"    ./bin/whatserverd tenants              # find your tenant\n" +
			"    ./bin/whatserverd key -tenant <ID>     # issue a key for it\n\n" +
			"Use bootstrap only to create a brand new tenant")
	}

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	//nolint:bodyclose // the handshake response has no body to close; the library owns it
	conn, _, err := websocket.Dial(dialCtx, url, nil)
	if err != nil {
		if isRefused(err) {
			return nil, fmt.Errorf("cannot reach the server at %s.\n"+
				"Is whatserverd running? Start it with:\n\n    ./bin/whatserverd\n\n"+
				"(underlying error: %w)", url, err)
		}
		return nil, fmt.Errorf("connecting to %s: %w", url, err)
	}
	conn.SetReadLimit(1 << 22)

	c := newClient(conn)
	go c.run(ctx)

	f, err := c.request(ctx, "", wsapi.TypeHello, wsapi.Hello{
		APIKey: key, Version: wsapi.Version, ClientID: "wsctl",
	}, wsapi.TypeWelcome)
	if err != nil {
		c.close()
		return nil, err
	}
	var w wsapi.Welcome
	if err := json.Unmarshal(f.Payload, &w); err != nil {
		c.close()
		return nil, err
	}
	c.tenant = w.TenantID
	return c, nil
}

// serverURL resolves where to connect.
//
// WS_URL wins when set. Otherwise it is derived from WS_HTTP_ADDR, the same
// variable the server binds to, so changing the port in .env moves both sides
// at once instead of leaving the client pointed at a stale default.
func serverURL() string {
	if u := os.Getenv("WS_URL"); u != "" {
		return u
	}
	addr := os.Getenv("WS_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = "", strings.TrimPrefix(addr, ":")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "ws://" + net.JoinHostPort(host, port) + "/v1/ws"
}
