package wsapi_test

import (
	"context"
	"testing"
	"time"

	"whatserver2/internal/wsapi"
)

// A key may be issued with a deadline. The deadline comes back in the
// created reply and in every listing, so a console can show it; omitted, the
// key lives until revoked, as every key did before deadlines existed.
func TestAPIKeyCreateWithExpiry(t *testing.T) {
	c := newConsole(t)
	owner := wsapi.Hello{Session: c.account(t, "owner@acme.test", "owner")}
	device := c.deviceWithKey(t, "Phone")
	in := time.Now().Add(20 * time.Minute).UTC().Truncate(time.Second)

	frame := ask(t, c, owner, wsapi.TypeKeyCreate, map[string]any{
		"name": "provisional", "scope": "read", "device_ids": []string{device}, "expires_at": in.Format(time.RFC3339),
	})
	if frame.Type != wsapi.TypeAPIKeyNew {
		t.Fatalf("create: %s %s", frame.Type, frame.Payload)
	}
	created := payload[wsapi.APIKeyCreated](t, frame)
	if created.Info.ExpiresAt == nil || !created.Info.ExpiresAt.Equal(in) {
		t.Fatalf("created expires_at = %v, want %v", created.Info.ExpiresAt, in)
	}
	listed := payload[wsapi.APIKeys](t, ask(t, c, owner, wsapi.TypeKeysList, nil))
	found := false
	for _, info := range listed.Keys {
		if info.Prefix != created.Info.Prefix {
			continue
		}
		found = true
		if info.ExpiresAt == nil || !info.ExpiresAt.Equal(in) {
			t.Fatalf("listed expires_at = %v, want %v", info.ExpiresAt, in)
		}
	}
	if !found {
		t.Fatal("issued key absent from listing")
	}

	// No deadline asked for, none reported.
	frame = ask(t, c, owner, wsapi.TypeKeyCreate, map[string]any{"name": "forever", "scope": "read"})
	if frame.Type != wsapi.TypeAPIKeyNew {
		t.Fatalf("create: %s %s", frame.Type, frame.Payload)
	}
	if info := payload[wsapi.APIKeyCreated](t, frame).Info; info.ExpiresAt != nil {
		t.Fatalf("a key issued without a deadline reports one: %v", info.ExpiresAt)
	}
}

// A deadline is a moment in the future within a year, or it is refused with
// no key issued.
func TestAPIKeyCreateRejectsBadExpiry(t *testing.T) {
	c := newConsole(t)
	owner := wsapi.Hello{Session: c.account(t, "owner@acme.test", "owner")}
	for name, value := range map[string]any{
		"not a timestamp": "next tuesday",
		"a number":        1700000000,
		"in the past":     time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		"now":             time.Now().UTC().Format(time.RFC3339),
		"over a year":     time.Now().Add(366 * 24 * time.Hour).UTC().Format(time.RFC3339),
	} {
		t.Run(name, func(t *testing.T) {
			wantError(t, ask(t, c, owner, wsapi.TypeKeyCreate, map[string]any{
				"name": name, "scope": "read", "expires_at": value,
			}), wsapi.ErrCodeBadRequest)
			keys, err := c.keys.List(context.Background(), c.tenant.String())
			if err != nil || len(keys) != 1 {
				t.Fatalf("a refused deadline left a key behind: %d %v", len(keys), err)
			}
		})
	}
}
