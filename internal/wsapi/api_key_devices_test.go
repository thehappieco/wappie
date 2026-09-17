package wsapi_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

func TestAPIKeyDeviceSelectionRestrictsReads(t *testing.T) {
	c := newConsole(t)
	owner := wsapi.Hello{Session: c.account(t, "owner@acme.test", "owner")}
	allowed, excluded := c.deviceWithKey(t, "Allowed"), c.deviceWithKey(t, "Excluded")
	frame := ask(t, c, owner, wsapi.TypeKeyCreate, map[string]any{
		"name": "MCP reader", "scope": "read", "device_ids": []string{allowed},
	})
	if frame.Type != wsapi.TypeAPIKeyNew {
		t.Fatalf("create: %s %s", frame.Type, frame.Payload)
	}
	created := payload[wsapi.APIKeyCreated](t, frame)
	reader := wsapi.Hello{APIKey: created.Key}
	wantError(t, ask(t, c, reader, wsapi.TypeChatsList, map[string]string{"device_id": excluded}), wsapi.ErrCodeNotAuthorized)
	if response := ask(t, c, reader, wsapi.TypeChatsList, map[string]string{"device_id": allowed}); response.Type != wsapi.TypeChats {
		t.Fatalf("allowed number refused: %s %s", response.Type, response.Payload)
	}
	if !created.Info.DevicesRestricted || len(created.Info.DeviceIDs) != 1 || created.Info.DeviceIDs[0] != allowed {
		t.Fatalf("create did not disclose actual restrictions: %s", frame.Payload)
	}
	listedFrame := ask(t, c, owner, wsapi.TypeKeysList, nil)
	if strings.Contains(string(listedFrame.Payload), created.Key) {
		t.Fatal("listing revealed the credential")
	}
	listed := payload[wsapi.APIKeys](t, listedFrame)
	for _, info := range listed.Keys {
		if info.Prefix == created.Info.Prefix {
			if !info.DevicesRestricted || len(info.DeviceIDs) != 1 || info.DeviceIDs[0] != allowed {
				t.Fatalf("list changed restrictions: %+v", info)
			}
			return
		}
	}
	t.Fatal("issued key absent from listing")
}

func TestAPIKeyInvalidDeviceSelectionCreatesNoKey(t *testing.T) {
	c := newConsole(t)
	owner := wsapi.Hello{Session: c.account(t, "owner@acme.test", "owner")}
	device := c.deviceWithKey(t, "Local")
	var foreign uuid.UUID
	if err := c.pool.QueryRow(context.Background(), `INSERT INTO tenants(name) VALUES('foreign') RETURNING id`).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	other, err := c.devices.Create(context.Background(), foreign.String(), "Foreign", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	for name, ids := range map[string]any{
		"empty": []string{}, "null": nil, "not an array": device,
		"duplicate": []string{device, strings.ToUpper(device)},
		"zero":      []string{uuid.Nil.String()}, "invalid": []string{"not-a-uuid"},
		"short":   []string{strings.ReplaceAll(device, "-", "")},
		"foreign": []string{device, other.ID}, "missing": []string{device, uuid.NewString()},
	} {
		t.Run(name, func(t *testing.T) {
			wantError(t, ask(t, c, owner, wsapi.TypeKeyCreate, map[string]any{
				"name": name, "scope": "read", "device_ids": ids,
			}), wsapi.ErrCodeBadRequest)
			keys, err := c.keys.List(context.Background(), c.tenant.String())
			if err != nil || len(keys) != 1 {
				t.Fatalf("failed issue left a key behind: %d %v", len(keys), err)
			}
		})
	}
}

func TestAPIKeyDeviceSelectionDoesNotWidenWithNewServiceGrants(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	owner := wsapi.Hello{Session: c.account(t, "owner@acme.test", "owner")}
	allowed, excluded := c.deviceWithKey(t, "Allowed"), c.deviceWithKey(t, "Excluded")
	service, err := c.users.CreateService(ctx, c.tenant, "mcp-reader", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	grant := func(device string) {
		t.Helper()
		if err := store.NewKeys(c.pool).PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: uuid.MustParse(device), UserID: service.ID, Epoch: 1, SealedDSK: []byte("opaque test grant")}, nil); err != nil {
			t.Fatal(err)
		}
	}
	grant(allowed)
	created := payload[wsapi.APIKeyCreated](t, ask(t, c, owner, wsapi.TypeKeyCreate, map[string]any{
		"name": "Service MCP reader", "scope": "read", "acts_as": service.ID.String(), "device_ids": []string{allowed},
	}))
	if created.Info.ActsAsID != service.ID.String() {
		t.Fatalf("service identity missing: %+v", created.Info)
	}
	grant(excluded)
	reader := wsapi.Hello{APIKey: created.Key}
	wantError(t, ask(t, c, reader, wsapi.TypeChatsList, map[string]string{"device_id": excluded}), wsapi.ErrCodeNotAuthorized)
	devices := payload[wsapi.Devices](t, ask(t, c, reader, wsapi.TypeDevicesList, nil))
	if len(devices.Devices) != 1 || devices.Devices[0].ID != allowed {
		t.Fatalf("new service grant widened token directory: %+v", devices)
	}
	grants := payload[wsapi.Grants](t, ask(t, c, reader, wsapi.TypeGrantsList, nil))
	if len(grants.Grants) != 1 || grants.Grants[0].DeviceID != allowed {
		t.Fatalf("new service grant escaped token whitelist: %+v", grants)
	}
}

func TestAPIKeyOmittedDeviceSelectionRemainsUnrestricted(t *testing.T) {
	c := newConsole(t)
	owner := wsapi.Hello{Session: c.account(t, "owner@acme.test", "owner")}
	created := payload[wsapi.APIKeyCreated](t, ask(t, c, owner, wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "Legacy", Scope: "read"}))
	if created.Info.DevicesRestricted || created.Info.DeviceIDs == nil || len(created.Info.DeviceIDs) != 0 || created.Info.ActsAsID != "" {
		t.Fatalf("legacy metadata is ambiguous: %+v", created.Info)
	}
	device := c.deviceWithKey(t, "Added later")
	frame := ask(t, c, wsapi.Hello{APIKey: created.Key}, wsapi.TypeChatsList, map[string]string{"device_id": device})
	if frame.Type != wsapi.TypeChats {
		t.Fatalf("omission no longer preserves legacy access: %s %s", frame.Type, frame.Payload)
	}
}

func TestAPIKeyTypedEmptyDeviceSelectionIsNotOmitted(t *testing.T) {
	c := newConsole(t)
	owner := wsapi.Hello{Session: c.account(t, "owner@acme.test", "owner")}
	// A Go client that explicitly selects no devices must not serialize that
	// as omission and accidentally mint a legacy unrestricted credential.
	wantError(t, ask(t, c, owner, wsapi.TypeKeyCreate, wsapi.APIKeyRequest{
		Name: "Empty selection", Scope: "read", DeviceIDs: []string{},
	}), wsapi.ErrCodeBadRequest)
}

func TestAPIKeyDeviceSelectionRequiresWorkspaceAdministrator(t *testing.T) {
	c := newConsole(t)
	device := c.deviceWithKey(t, "Number")
	for _, who := range []wsapi.Hello{
		{APIKey: c.apiKey}, {Session: c.account(t, "member@acme.test", "member")},
	} {
		wantError(t, ask(t, c, who, wsapi.TypeKeyCreate, map[string]any{
			"name": "Forbidden", "scope": "read", "device_ids": []string{device},
		}), wsapi.ErrCodeNotAuthorized)
	}
	admin := wsapi.Hello{Session: c.account(t, "admin@acme.test", "admin")}
	frame := ask(t, c, admin, wsapi.TypeKeyCreate, map[string]any{
		"name": "Admin reader", "scope": "read", "device_ids": []string{device},
	})
	if frame.Type != wsapi.TypeAPIKeyNew {
		t.Fatalf("administrator could not issue restricted key: %s %s", frame.Type, frame.Payload)
	}
}
