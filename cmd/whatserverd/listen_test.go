package main

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"
)

// `kill $pid && ./bin/whatserverd` is what anybody types to restart, and it
// races the old process letting go of the port. Failing there does not just
// delay the restart -- it kills the replacement, and once the old process
// finishes exiting there is nothing running at all. That happened here: an
// operator issued a restart and ended up with no server.

func TestListenWaitsForThePortToBeReleased(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := held.Addr().String()

	// The outgoing process, still holding the port for a moment.
	go func() {
		time.Sleep(300 * time.Millisecond)
		held.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	ln, err := listenPatiently(ctx, addr, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("gave up on a port that was about to be free: %v", err)
	}
	defer ln.Close()

	if waited := time.Since(start); waited < 250*time.Millisecond {
		t.Errorf("bound after %v, which is too soon to have waited for the "+
			"previous holder — the test is not exercising the retry", waited)
	}
}

func TestListenStillFailsOnAPortThatNeverFrees(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	// Waiting forever would be worse than failing: a port genuinely held by
	// something else is an operator error, and the message has to say so.
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	if _, err := listenPatiently(ctx, held.Addr().String(), slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("bound a port that another listener holds")
	}
}

func TestListenReportsAnAddressItCannotUse(t *testing.T) {
	// Not "in use" — unusable. That must fail immediately rather than spending
	// the patience budget on something no amount of waiting fixes.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err := listenPatiently(ctx, "203.0.113.1:9", slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("bound an address that is not on this machine")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("took %v to report an address it can never bind", waited)
	}
}
