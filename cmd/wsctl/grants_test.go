package main

import (
	"strings"
	"testing"

	"whatserver2/internal/wsapi"
)

// Who a device key is sealed to decides who can read somebody's WhatsApp
// messages, for as long as the archive exists. A convenient default that seals
// to everyone would undo the separation a per-device key exists to provide, so
// the ambiguous case asks rather than guesses.

func accounts(emails ...string) []wsapi.UserSummary {
	out := make([]wsapi.UserSummary, 0, len(emails))
	for i, e := range emails {
		out = append(out, wsapi.UserSummary{
			ID: e, Email: e, Role: "member", PublicKey: []byte{byte(i)},
		})
	}
	return out
}

func TestOneAccountNeedsNoChoice(t *testing.T) {
	got, err := chooseAccounts(accounts("ana@example.com"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Email != "ana@example.com" {
		t.Fatalf("got %v", got)
	}
}

func TestSeveralAccountsMustBeNamed(t *testing.T) {
	_, err := chooseAccounts(accounts("ana@example.com", "bruno@example.com"), nil)
	if err == nil {
		t.Fatal("a key was sealed to two accounts without anybody choosing")
	}
	// The message has to carry the list, or the next thing somebody types is a
	// guess at an address.
	for _, want := range []string{"ana@example.com", "bruno@example.com", "-grant"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %s", want, err)
		}
	}
}

func TestNamingPicksExactlyThose(t *testing.T) {
	all := accounts("ana@example.com", "bruno@example.com", "carla@example.com")
	got, err := chooseAccounts(all, emails{"bruno@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Email != "bruno@example.com" {
		t.Fatalf("got %v, want only bruno", got)
	}
}

func TestNamingIsCaseInsensitive(t *testing.T) {
	// The flag lowercases what it is given; the accounts may not be stored
	// that way, and refusing over capitalisation would be a bad hour.
	got, err := chooseAccounts(accounts("Ana@Example.com"), emails{"ana@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestAnUnknownAddressIsRefused(t *testing.T) {
	all := accounts("ana@example.com")
	_, err := chooseAccounts(all, emails{"ghost@example.com"})
	if err == nil {
		t.Fatal("a device was granted to an account that does not exist")
	}
	if !strings.Contains(err.Error(), "ana@example.com") {
		t.Errorf("the error does not say what does exist: %s", err)
	}
}

func TestNoAccountsAtAllIsNotAnError(t *testing.T) {
	// Handled by the caller, which refuses to pair unless -orphan was passed.
	// Failing here instead would make the message about it worse.
	got, err := chooseAccounts(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}
