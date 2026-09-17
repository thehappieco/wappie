package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"whatserver2/internal/calling"
	"whatserver2/internal/store"
)

func TestCallCommandsRequireSendPermission(t *testing.T) {
	for _, frame := range []string{TypeCallsList, TypeCallStart, TypeCallAnswer, TypeCallReject, TypeCallHangup, TypeCallMedia, TypeCallInvite} {
		if got := frameAction(frame); got != store.ActionSend {
			t.Errorf("%s uses %s, want send", frame, got)
		}
	}
}

func TestCallPeerRejectsGroupsAndNormalizesIndividualAddresses(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"5511999999999@s.whatsapp.net", "5511999999999@s.whatsapp.net"},
		{"5511999999999:2@s.whatsapp.net", "5511999999999@s.whatsapp.net"},
		{" 1234567@lid ", "1234567@lid"},
	} {
		got, err := callPeer(tc.input)
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	for _, input := range []string{"", "5511999999999", "@s.whatsapp.net", "120363123@g.us", "status@broadcast", "1234@newsletter", "someone@lid", "123456789012345678901@lid"} {
		if _, err := callPeer(input); !errors.Is(err, calling.ErrInvalid) {
			t.Errorf("accepted non-individual address %q: %v", input, err)
		}
	}
}

func TestCallOwnerIsUniqueStableAndCannotReturnAfterRelease(t *testing.T) {
	calls := calling.New()
	server := NewServer(Config{Calls: calls})
	first := &session{srv: server, clientID: "shared-client"}
	second := &session{srv: server, clientID: "shared-client"}
	one, two := first.initCallOwner(), second.initCallOwner()
	if one == "" || two == "" || one == two || one == first.clientID {
		t.Fatalf("owners are not unique per connection: %q %q", one, two)
	}
	if err := calls.Hangup(context.Background(), "tenant", "device", one, "missing"); !errors.Is(err, calling.ErrNotFound) {
		t.Fatalf("connection owner was not registered: %v", err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if got := first.initCallOwner(); got != one {
				t.Errorf("concurrent dispatch changed owner to %q", got)
			}
		})
	}
	wg.Wait()
	first.releaseCallOwner()
	first.releaseCallOwner()
	if got := first.initCallOwner(); got != "" {
		t.Fatalf("released connection registered again: %q", got)
	}
	if err := calls.Hangup(context.Background(), "tenant", "device", one, "missing"); !errors.Is(err, calling.ErrUnavailable) {
		t.Fatalf("released owner still authorized: %v", err)
	}
	if got := second.initCallOwner(); got != two {
		t.Fatalf("releasing another connection changed owner: %q", got)
	}
}

func callTestSession() *session {
	server := NewServer(Config{Log: slog.New(slog.DiscardHandler)})
	return &session{srv: server, out: make(chan Frame, 8), log: server.log, who: actor{scope: store.ScopeRead}}
}

func TestReadOnlyCallCommandsFailBeforeReachingProvider(t *testing.T) {
	for _, kind := range []string{TypeCallsList, TypeCallStart, TypeCallAnswer, TypeCallReject, TypeCallHangup, TypeCallMedia, TypeCallInvite} {
		t.Run(kind, func(t *testing.T) {
			s := callTestSession()
			f := Frame{Type: kind, Payload: json.RawMessage(`{"device_id":"device","chat":"5511999999999@s.whatsapp.net","call_id":"call","participants":["5511888888888@s.whatsapp.net"]}`)}
			switch kind {
			case TypeCallsList:
				s.handleCallsList(context.Background(), f)
			case TypeCallStart:
				s.handleCallStart(context.Background(), f)
			case TypeCallInvite:
				s.handleCallInvite(context.Background(), f)
			default:
				s.handleCallAction(context.Background(), f)
			}
			var failure Error
			if err := json.Unmarshal((<-s.out).Payload, &failure); err != nil {
				t.Fatal(err)
			}
			if failure.Code != ErrCodeNotAuthorized {
				t.Fatalf("got %+v, want denied send permission", failure)
			}
		})
	}
}

func TestCallErrorsHaveStableCodesWithoutExposingInternalDetails(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{calling.ErrInvalid, ErrCodeBadRequest},
		{calling.ErrNotFound, ErrCodeNotFound},
		{calling.ErrConflict, ErrCodeConflict},
		{calling.ErrUnavailable, ErrCodeConflict},
		{context.Canceled, ErrCodeConflict},
		{context.DeadlineExceeded, ErrCodeConflict},
		{errors.New("provider detail"), ErrCodeInternal},
	} {
		s := callTestSession()
		s.replyCallError("request", fmt.Errorf("private provider detail: %w", tc.err))
		f := <-s.out
		var failure Error
		if err := json.Unmarshal(f.Payload, &failure); err != nil {
			t.Fatal(err)
		}
		if f.Type != TypeError || f.ReqID != "request" || failure.Code != tc.code {
			t.Errorf("%v: got %s %+v", tc.err, f.Type, failure)
		}
		if strings.Contains(failure.Message, "provider detail") {
			t.Errorf("internal provider information exposed: %+v", failure)
		}
	}
}

func TestCallInviteRejectsMalformedBatchBeforeProvider(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"call_id":" "}`, `{"call_id":"call","participants":[]}`,
		`{"call_id":"call","participants":null}`, `{"call_id":"call","participants":"123@lid"}`,
		`{"call_id":"call","participants":["123@lid", "120363@g.us"]}`,
		`{"call_id":"call","participants":["1@lid","2@lid","3@lid","4@lid","5@lid","6@lid","7@lid","8@lid"]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			s := callTestSession()
			s.handleCallInvite(context.Background(), Frame{Type: TypeCallInvite, ReqID: "invite", Payload: json.RawMessage(raw)})
			f := <-s.out
			var failure Error
			if err := json.Unmarshal(f.Payload, &failure); err != nil {
				t.Fatal(err)
			}
			if f.ReqID != "invite" || failure.Code != ErrCodeBadRequest {
				t.Fatalf("got %s %+v", f.ReqID, failure)
			}
		})
	}
}
