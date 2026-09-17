package wsapi_test

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/http/httptest"
	"testing"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

func TestStoragePauseBlocksCaptureButKeepsSessionAndAdministration(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name,storage_paused_at) VALUES('paused',now()) RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(pool)
	key, err := keys.Issue(ctx, tenant.String(), "test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{Keys: keys, Storage: store.NewStorage(pool), Devices: store.NewDevices(pool)}))
	defer srv.Close()
	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: key, Version: wsapi.Version, ClientID: "storage-test"})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("hello: %+v", f)
	}
	for _, typ := range []string{wsapi.TypeSend, wsapi.TypePair, wsapi.TypeDeviceStart, wsapi.TypeBackfill, wsapi.TypeMediaRetry, wsapi.TypeReprojectPut} {
		send(t, conn, typ, map[string]string{})
		f := read(t, conn)
		var payload struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(f.Payload, &payload)
		if payload.Code != "storage_paused" {
			t.Fatalf("%s: %s", typ, f.Payload)
		}
	}
	send(t, conn, wsapi.TypePing, nil)
	if f := read(t, conn); f.Type != wsapi.TypePong {
		t.Fatalf("ping: %+v", f)
	}
	send(t, conn, wsapi.TypeDevicesList, nil)
	if f := read(t, conn); f.Type == wsapi.TypeError {
		t.Fatalf("admin list blocked: %s", f.Payload)
	}
}
