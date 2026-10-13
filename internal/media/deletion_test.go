package media_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/media"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// A deleted number's attachments answer exactly as one that does not exist,
// to a key that reached them a moment before (decision 0038).
func TestMediaOfAnExcludedNumberIsNotFound(t *testing.T) {
	f := newFixture(t, []byte(strings.Repeat("y", 3000)))
	ctx := context.Background()
	if ref := f.run(t, f.worker(t)); ref.Status != "done" {
		t.Fatalf("status = %q, want done", ref.Status)
	}
	devices := store.NewDevices(f.pool)
	if err := devices.SetIdentity(ctx, f.tenant.String(), f.device.String(), wa.Identity{PN: types.NewJID("5511912345678", types.DefaultUserServer)}); err != nil {
		t.Fatal(err)
	}
	owner, err := store.NewUsers(f.pool).Create(ctx, store.NewUser{TenantID: f.tenant, Email: "owner@acme.test", Role: "owner", AuthKey: "test",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /v1/media/{uid}", &media.Handler{Keys: f.apiKeys, Media: f.media, Blob: f.blob, Log: slog.New(slog.DiscardHandler)})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	status := func() int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/v1/media/"+f.msgUID.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := status(); got != http.StatusOK {
		t.Fatalf("control: %d", got)
	}
	if _, err := devices.Quarantine(ctx, f.tenant, owner.ID, f.device, nil); err != nil {
		t.Fatal(err)
	}
	if got := status(); got != http.StatusNotFound {
		t.Fatalf("an excluded number's attachment: %d", got)
	}
}
