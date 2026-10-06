package stepup_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/stepup"
)

type sessions struct {
	fresh  bool
	err    error
	asked  []uuid.UUID
	window time.Duration
}

func (s *sessions) AuthenticatedWithin(_ context.Context, session uuid.UUID, window time.Duration) (bool, error) {
	s.asked = append(s.asked, session)
	s.window = window
	return s.fresh, s.err
}

// Recent asks the session store about the session, over Window; no session
// is never fresh and is not asked about.
func TestRecent(t *testing.T) {
	ctx := context.Background()
	s := &sessions{fresh: true}
	id := uuid.New()
	if fresh, err := stepup.Recent(s).Fresh(ctx, id); err != nil || !fresh || len(s.asked) != 1 || s.asked[0] != id || s.window != stepup.Window {
		t.Fatalf("a fresh session: %v %v %+v", fresh, err, s)
	}
	if fresh, err := stepup.Recent(s).Fresh(ctx, uuid.Nil); err != nil || fresh || len(s.asked) != 1 {
		t.Fatalf("no session: %v %v %+v", fresh, err, s)
	}
	broken := &sessions{err: errors.New("down")}
	if _, err := stepup.Recent(broken).Fresh(ctx, id); err == nil {
		t.Fatal("a store error was swallowed")
	}
}

// The window and the tolerance of Decision 3 (step 4), and the approved
// messages (E-STEP-01 and E-STEP-15, 2026-10-06): ASCII, as every API
// message is, and the provider's names the route that starts its step-up.
func TestConstants(t *testing.T) {
	if stepup.Window != 10*time.Minute || stepup.ProviderClockTolerance != time.Minute {
		t.Fatalf("window %v, tolerance %v", stepup.Window, stepup.ProviderClockTolerance)
	}
	if stepup.Message != "confirm it is you first: with your passkey or your password, or at the identity provider your account signs in with, "+
		"or sign in again; giving an assistant message text, or anyone a number's key, needs it within the last ten minutes" {
		t.Fatalf("E-STEP-01: %q", stepup.Message)
	}
	if stepup.ProviderMessage != "this account confirms it is you at the identity provider it signs in with, not with a passkey or password here: "+
		"use POST /v1/auth/platform/step-up/start" {
		t.Fatalf("E-STEP-15: %q", stepup.ProviderMessage)
	}
	for _, m := range []string{stepup.Message, stepup.ProviderMessage} {
		for _, r := range m {
			if r > 0x7e {
				t.Fatalf("a non-ASCII character in %q", m)
			}
		}
		if strings.Contains(m, "’") {
			t.Fatalf("a typographic apostrophe in %q", m)
		}
	}
}
